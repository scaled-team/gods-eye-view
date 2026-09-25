// Vercel Routing Middleware: the hosted console requires a SysOp session.
// The API function checks the session again; this gate covers the page.
import { readSession } from './server/auth/core.js';

// The two headers `@vercel/functions/middleware` sets for next() and rewrite().
const next = () => new Response(null, { headers: { 'x-middleware-next': '1' } });
const rewrite = (destination) =>
  new Response(null, { headers: { 'x-middleware-rewrite': String(destination), 'Cache-Control': 'no-store' } });

export const config = { matcher: ['/', '/index.html', '/api/:path*'] };

export default async function middleware(request) {
  const url = new URL(request.url);
  if (url.pathname.startsWith('/api/auth/') || url.pathname === '/api/health') return next();
  if (await readSession(request.headers.get('cookie'), process.env.GODSEYE_SESSION_SECRET)) return next();
  if (url.pathname.startsWith('/api/'))
    return Response.json({ error: 'Sign in with Delegate to use this deployment.' },
      { status: 401, headers: { 'Cache-Control': 'no-store' } });
  return rewrite(new URL('/auth/signin.html', url));
}
