// /api/auth/* for the hosted deployment: SysOp OIDC (public client, PKCE) and
// the popup handoff that signs in a copy framed by Delegate V2.
import {
  DEFAULT_CLIENT_ID,
  DEFAULT_ISSUER,
  EMBED_NONCE_PATTERN,
  HANDOFF_TTL_SECONDS,
  OAUTH_COOKIE,
  OAUTH_TTL_SECONDS,
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  cookie,
  isAllowedEmail,
  readCookie,
  readSession,
  randomToken,
  safeReturnPath,
  sessionClaims,
  sha256,
  signToken,
  verifyIdToken,
  verifyToken,
} from './core.js';

export const EMBED_HEADER = 'x-godseye-embed';
const POPUP_COMPLETE_PATH = '/auth/popup-complete.html';
const MAX_BODY_BYTES = 4096;

const list = (value) =>
  String(value ?? '')
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);

export function authConfig(env = process.env) {
  return {
    issuer: env.SYSOP_OIDC_ISSUER || DEFAULT_ISSUER,
    clientId: env.SYSOP_OIDC_CLIENT_ID || DEFAULT_CLIENT_ID,
    secret: env.GODSEYE_SESSION_SECRET || '',
    // Pinned in production so redirect_uri and the Origin check never follow a Host header.
    publicOrigin: env.GODSEYE_PUBLIC_ORIGIN || '',
    allowed: {
      emails: list(env.GODSEYE_ALLOWED_EMAILS),
      domains: list(env.GODSEYE_ALLOWED_DOMAINS ?? 'scaledbydesign.com'),
    },
  };
}

let discoveryCache;
async function discover(issuer, fetchImpl) {
  if (discoveryCache?.issuer === issuer) return discoveryCache.value;
  const response = await fetchImpl(
    `${issuer}/.well-known/openid-configuration`,
    { redirect: 'error' },
  );
  if (!response.ok) throw new Error(`discovery ${response.status}`);
  const document = await response.json();
  if (document.issuer !== issuer) throw new Error('discovery issuer mismatch');
  const jwksResponse = await fetchImpl(document.jwks_uri, {
    redirect: 'error',
  });
  if (!jwksResponse.ok) throw new Error(`jwks ${jwksResponse.status}`);
  const value = { ...document, jwks: await jwksResponse.json() };
  discoveryCache = { issuer, value };
  return value;
}

export function resetDiscoveryCache() {
  discoveryCache = undefined;
}

/** The deployment's own origin: pinned by config, else the host Vercel routed to. */
function ownOrigin(req, config) {
  return (
    config.publicOrigin ||
    `https://${String(req.headers.host ?? '').toLowerCase()}`
  );
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  });
  res.end(body === undefined ? undefined : JSON.stringify(body));
}

function redirect(res, location, cookies = []) {
  res.writeHead(302, {
    Location: location,
    'Cache-Control': 'no-store',
    'Set-Cookie': cookies,
  });
  res.end();
}

async function readJson(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error('body too large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

async function login(req, res, url, config, fetchImpl) {
  const embedNonce = url.searchParams.get('embed');
  if (embedNonce !== null && !EMBED_NONCE_PATTERN.test(embedNonce))
    return send(
      res,
      400,
      { error: 'Invalid embed nonce' },
      { 'Content-Type': 'application/json' },
    );
  const oidc = await discover(config.issuer, fetchImpl);
  const state = randomToken();
  const nonce = randomToken();
  const verifier = randomToken(48);
  const oauth = await signToken(
    {
      typ: 'oauth',
      state,
      nonce,
      verifier,
      ret: safeReturnPath(url.searchParams.get('return')),
      embed: embedNonce === null ? null : await sha256(embedNonce),
    },
    config.secret,
    OAUTH_TTL_SECONDS,
  );
  const authorize = new URL(oidc.authorization_endpoint);
  authorize.search = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: `${ownOrigin(req, config)}/api/auth/callback`,
    scope: 'openid profile email',
    state,
    nonce,
    code_challenge: await sha256(verifier),
    code_challenge_method: 'S256',
  }).toString();
  return redirect(res, authorize.toString(), [
    cookie(OAUTH_COOKIE, oauth, OAUTH_TTL_SECONDS),
  ]);
}

async function callback(req, res, url, config, fetchImpl) {
  const clearOauth = cookie(OAUTH_COOKIE, '', 0);
  const oauth = await verifyToken(
    readCookie(req.headers.cookie, OAUTH_COOKIE),
    config.secret,
    'oauth',
  );
  const code = url.searchParams.get('code');
  if (!oauth || !code || url.searchParams.get('state') !== oauth.state)
    return send(
      res,
      400,
      { error: 'Sign-in expired or was not started here. Try again.' },
      { 'Content-Type': 'application/json', 'Set-Cookie': [clearOauth] },
    );
  const oidc = await discover(config.issuer, fetchImpl);
  const tokenResponse = await fetchImpl(oidc.token_endpoint, {
    method: 'POST',
    redirect: 'error',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: `${ownOrigin(req, config)}/api/auth/callback`,
      client_id: config.clientId,
      code_verifier: oauth.verifier,
    }),
  });
  if (!tokenResponse.ok)
    throw new Error(`token exchange ${tokenResponse.status}`);
  const { id_token: idToken } = await tokenResponse.json();
  const verify = (jwks) =>
    verifyIdToken(idToken, {
      jwks,
      issuer: config.issuer,
      clientId: config.clientId,
      nonce: oauth.nonce,
    });
  let identity;
  try {
    identity = await verify(oidc.jwks);
  } catch (error) {
    // SysOp rotated its signing key since this instance cached the JWKS.
    if (error?.message !== 'id_token signing key not found') throw error;
    resetDiscoveryCache();
    identity = await verify((await discover(config.issuer, fetchImpl)).jwks);
  }
  if (!isAllowedEmail(identity.email, config.allowed))
    return send(
      res,
      403,
      { error: 'This account is not allowed to use GodsEye.' },
      { 'Content-Type': 'application/json', 'Set-Cookie': [clearOauth] },
    );
  const session = await signToken(
    sessionClaims(identity),
    config.secret,
    SESSION_TTL_SECONDS,
  );
  const cookies = [
    clearOauth,
    cookie(SESSION_COOKIE, session, SESSION_TTL_SECONDS),
  ];
  if (!oauth.embed) return redirect(res, safeReturnPath(oauth.ret), cookies);
  // Framed sign-in: hand the opener a short-lived code bound to the nonce only it holds.
  const handoff = await signToken(
    { ...sessionClaims(identity), typ: 'handoff', nh: oauth.embed },
    config.secret,
    HANDOFF_TTL_SECONDS,
  );
  return redirect(res, `${POPUP_COMPLETE_PATH}#code=${handoff}`, cookies);
}

async function embedSession(req, res, config) {
  const json = { 'Content-Type': 'application/json' };
  if (req.method !== 'POST')
    return send(res, 405, { error: 'Method not allowed' }, json);
  // A custom header forces a CORS preflight; Origin must be this deployment.
  if (
    req.headers[EMBED_HEADER] !== '1' ||
    req.headers.origin !== ownOrigin(req, config)
  )
    return send(res, 403, { error: 'Forbidden' }, json);
  let body;
  try {
    body = await readJson(req);
  } catch {
    return send(res, 400, { error: 'Invalid request' }, json);
  }
  const nonce = typeof body?.nonce === 'string' ? body.nonce : '';
  const handoff = EMBED_NONCE_PATTERN.test(nonce)
    ? await verifyToken(body.code, config.secret, 'handoff')
    : null;
  if (
    !handoff ||
    handoff.nh !== (await sha256(nonce)) ||
    !isAllowedEmail(handoff.email, config.allowed)
  )
    return send(
      res,
      401,
      { error: 'Sign-in handoff expired. Try again.' },
      json,
    );
  const session = await signToken(
    sessionClaims(handoff),
    config.secret,
    SESSION_TTL_SECONDS,
  );
  return send(res, 204, undefined, {
    'Set-Cookie': [
      cookie(SESSION_COOKIE, session, SESSION_TTL_SECONDS, { embedded: true }),
    ],
  });
}

/** Handle /api/auth/*; returns false for any other path. */
export async function handleAuth(
  req,
  res,
  pathname,
  url,
  { config = authConfig(), fetchImpl = fetch } = {},
) {
  if (!pathname.startsWith('/api/auth/')) return false;
  const json = { 'Content-Type': 'application/json' };
  if (!config.secret) {
    send(res, 503, { error: 'Sign-in is not configured.' }, json);
    return true;
  }
  try {
    if (pathname === '/api/auth/login' && req.method === 'GET')
      await login(req, res, url, config, fetchImpl);
    else if (pathname === '/api/auth/callback' && req.method === 'GET')
      await callback(req, res, url, config, fetchImpl);
    else if (pathname === '/api/auth/embed-session')
      await embedSession(req, res, config);
    else if (pathname === '/api/auth/me' && req.method === 'GET') {
      const session = await readSession(req.headers.cookie, config.secret);
      if (session)
        send(res, 200, { email: session.email, name: session.name }, json);
      else send(res, 401, { error: 'Not signed in' }, json);
    } else if (pathname === '/api/auth/logout' && req.method === 'POST') {
      send(res, 204, undefined, {
        'Set-Cookie': [
          cookie(SESSION_COOKIE, '', 0),
          cookie(SESSION_COOKIE, '', 0, { embedded: true }),
        ],
      });
    } else send(res, 404, { error: 'Unknown auth route' }, json);
  } catch (error) {
    console.error('[auth]', error?.message);
    if (!res.headersSent)
      send(res, 502, { error: 'Sign-in failed. Try again.' }, json);
  }
  return true;
}
