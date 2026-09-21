import { mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

// Do not parse request bodies: upstream handlers enforce their own byte limits.
export const config = { api: { bodyParser: false } };
let initialization;

async function initialize() {
  const cacheRoot = path.join(tmpdir(), 'gev-vercel');
  await mkdir(cacheRoot, { recursive: true });
  process.chdir(cacheRoot);
  process.env.OPENSKY_AUTH_MODE = 'anon';
  const { localProviderPlugins } = await import('../server/providers/local.js');
  const routes = [];
  const server = {
    middlewares: {
      use(prefix, handler) {
        if (typeof prefix !== 'string' || typeof handler !== 'function')
          throw new Error('Unsupported upstream middleware registration');
        routes.push({ prefix, handler });
      },
    },
  };
  const excluded = new Set([
    'gev-key-setup', 'ais-live-proxy', 'openai-realtime-proxy',
  ]);
  for (const plugin of localProviderPlugins()) {
    if (!excluded.has(plugin.name)) await plugin.configureServer?.(server);
  }
  return routes;
}

function json(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(JSON.stringify(body));
}

export default async function handler(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const rewrittenPath = url.searchParams.get('__path');
  url.searchParams.delete('__path');
  const pathname = rewrittenPath === null ? url.pathname : `/api/${rewrittenPath}`;
  req.url = pathname + url.search;
  if (pathname === '/api/health') {
    return json(res, 200, {
      ok: true, runtime: 'vercel', mode: 'keyless',
      disabled: ['remote-key-setup', 'openai', 'ais-live'],
    });
  }
  if (/^\/api\/setup(?:\/|$)/.test(pathname))
    return json(res, 404, { error: 'Remote provider-key editing is disabled.' });
  if (/^\/api\/(?:openai|realtime|ais-live)(?:\/|$)/.test(pathname))
    return json(res, 503, { error: 'This feature is disabled in the keyless Vercel deployment.' });
  if (!['GET', 'HEAD', 'POST'].includes(req.method))
    return json(res, 405, { error: 'Method not allowed' });
  try {
    const routes = await (initialization ??= initialize());
    for (const route of routes) {
      if (pathname !== route.prefix && !pathname.startsWith(`${route.prefix}/`)) continue;
      const original = req.url;
      req.url = (pathname.slice(route.prefix.length) || '/') + url.search;
      let passed = false;
      await route.handler(req, res, (error) => {
        if (error) throw error;
        passed = true;
      });
      req.url = original;
      if (!passed) return;
    }
    return json(res, 404, { error: 'Unknown API route' });
  } catch (error) {
    console.error('[vercel-adapter]', error?.message);
    if (!res.headersSent) json(res, 502, { error: 'Provider temporarily unavailable' });
    else if (!res.writableEnded) res.end();
  }
}
