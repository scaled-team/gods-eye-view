import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import test from 'node:test';
import {
  SESSION_COOKIE, base64UrlEncode, readCookie, readSession, safeReturnPath, sha256, signToken,
  verifyIdToken, verifyToken, isAllowedEmail,
} from './core.js';
import { authConfig, handleAuth, resetDiscoveryCache } from './routes.js';

const SECRET = 'test-session-secret-0123456789abcdef-0123456789';
const ISSUER = 'https://sysop.test/oauth';
const CLIENT_ID = 'godseye-web';
const HOST = 'godseye.delegate.ws';
const config = {
  issuer: ISSUER,
  clientId: CLIENT_ID,
  secret: SECRET,
  publicOrigin: '',
  allowed: { emails: [], domains: ['example.com'] },
};
const enc = (value) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));

const keys = await crypto.subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true, ['sign', 'verify'],
);
const publicJwk = { ...(await crypto.subtle.exportKey('jwk', keys.publicKey)), kid: 'k1' };
const jwks = { keys: [publicJwk] };

async function idToken(overrides = {}, header = { alg: 'RS256', kid: 'k1' }) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: ISSUER, aud: CLIENT_ID, sub: 'user-1', email: 'Pat@Example.com', email_verified: true,
    name: 'Pat', nonce: 'n1', iat: now, exp: now + 300, ...overrides,
  };
  const signed = `${enc(header)}.${enc(claims)}`;
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', keys.privateKey, new TextEncoder().encode(signed));
  return `${signed}.${base64UrlEncode(new Uint8Array(signature))}`;
}

function request({ method = 'GET', headers = {}, body } = {}) {
  const req = Readable.from(body === undefined ? [] : [Buffer.from(JSON.stringify(body))]);
  Object.assign(req, { method, headers: { host: HOST, ...headers } });
  return req;
}

function response() {
  return {
    status: 0, headers: {}, body: '', headersSent: false,
    writeHead(status, headers) { this.status = status; this.headers = headers; this.headersSent = true; },
    end(body) { this.body = body ?? ''; },
  };
}

async function call(path, init = {}, fetchImpl = fakeSysop()) {
  const url = new URL(path, `https://${HOST}`);
  const res = response();
  await handleAuth(request(init), res, url.pathname, url, { config, fetchImpl });
  return res;
}

function fakeSysop(tokenFor = () => ({})) {
  return async (input, init) => {
    const url = String(input);
    if (url === `${ISSUER}/.well-known/openid-configuration`)
      return Response.json({
        issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/jwks`,
      });
    if (url === `${ISSUER}/jwks`) return Response.json(jwks);
    if (url === `${ISSUER}/token`) return Response.json(await tokenFor(new URLSearchParams(init.body)));
    return new Response('not found', { status: 404 });
  };
}

const cookieValue = (res, name) =>
  readCookie([].concat(res.headers['Set-Cookie'] ?? []).map((c) => c.split(';')[0]).join('; '), name);

test.beforeEach(() => resetDiscoveryCache());

test('session tokens verify, and tampered, expired or wrong-type tokens do not', async () => {
  const token = await signToken({ typ: 'session', sub: 'u', email: 'a@b.c' }, SECRET, 60);
  assert.equal((await verifyToken(token, SECRET, 'session')).sub, 'u');
  assert.equal(await verifyToken(token, SECRET, 'handoff'), null);
  assert.equal(await verifyToken(token, `${SECRET}x`, 'session'), null);
  const [h, , s] = token.split('.');
  assert.equal(await verifyToken(`${h}.${enc({ typ: 'session', sub: 'evil', exp: 9e9 })}.${s}`, SECRET, 'session'), null);
  assert.equal(await verifyToken(await signToken({ typ: 'session' }, SECRET, -1), SECRET, 'session'), null);
  assert.equal(await verifyToken(`${enc({ alg: 'none' })}.${enc({ typ: 'session', exp: 9e9 })}.`, SECRET, 'session'), null);
  assert.equal(await readSession(`${SESSION_COOKIE}=${token}`, ''), null);
});

test('return paths stay on this origin and off the API', () => {
  assert.equal(safeReturnPath('/?city=paris'), '/?city=paris');
  for (const value of ['//evil.com', 'https://evil.com', '/\\evil.com', '/api/auth/logout', null, '/\u0000x'])
    assert.equal(safeReturnPath(value), '/');
});

test('ID tokens are checked for signature, issuer, audience, azp, expiry, nonce and verified email', async () => {
  const context = { jwks, issuer: ISSUER, clientId: CLIENT_ID, nonce: 'n1' };
  assert.deepEqual(await verifyIdToken(await idToken(), context), { sub: 'user-1', email: 'pat@example.com', name: 'Pat' });
  const bad = [
    { iss: 'https://other/oauth' }, { aud: 'someone-else' }, { azp: 'someone-else' },
    { exp: Math.floor(Date.now() / 1000) - 1 }, { nonce: 'n2' }, { email_verified: false }, { email: undefined },
  ];
  for (const overrides of bad) await assert.rejects(verifyIdToken(await idToken(overrides), context));
  await assert.rejects(verifyIdToken(await idToken({}, { alg: 'HS256', kid: 'k1' }), context));
  await assert.rejects(verifyIdToken(await idToken({}, { alg: 'RS256', kid: 'unknown' }), context));
  const token = await idToken();
  await assert.rejects(verifyIdToken(`${token.split('.').slice(0, 2).join('.')}.${base64UrlEncode(new Uint8Array(256))}`, context));
});

async function signIn({ embedNonce, header, keepCache } = {}) {
  if (!keepCache) resetDiscoveryCache();
  const login = await call(`/api/auth/login?${embedNonce ? `embed=${embedNonce}` : 'return=/?x=1'}`);
  assert.equal(login.status, 302);
  const authorize = new URL(login.headers.Location);
  assert.equal(authorize.origin + authorize.pathname, `${ISSUER}/authorize`);
  assert.equal(authorize.searchParams.get('redirect_uri'), `https://${HOST}/api/auth/callback`);
  assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
  const oauth = cookieValue(login, '__Host-gev_oauth');
  const state = authorize.searchParams.get('state');
  const fetchImpl = fakeSysop(async (form) => {
    assert.equal(await sha256(form.get('code_verifier')), authorize.searchParams.get('code_challenge'));
    assert.equal(form.get('client_id'), CLIENT_ID);
    return { id_token: await idToken({ nonce: authorize.searchParams.get('nonce') }, header) };
  });
  const callback = await call(`/api/auth/callback?code=c1&state=${state}`,
    { headers: { cookie: `__Host-gev_oauth=${oauth}` } }, fetchImpl);
  return { login, callback, oauth, state };
}

test('top-level sign-in sets a Lax session and returns to the requested path', async () => {
  const { login, callback } = await signIn();
  assert.match([].concat(login.headers['Set-Cookie'])[0], /HttpOnly; Secure; SameSite=Lax/);
  assert.equal(callback.status, 302);
  assert.equal(callback.headers.Location, '/?x=1');
  const session = await readSession(`${SESSION_COOKIE}=${cookieValue(callback, SESSION_COOKIE)}`, SECRET);
  assert.equal(session.email, 'pat@example.com');
});

test('the callback refuses a missing or mismatched state', async () => {
  const { oauth } = await signIn();
  assert.equal((await call('/api/auth/callback?code=c1&state=forged', { headers: { cookie: `__Host-gev_oauth=${oauth}` } })).status, 400);
  assert.equal((await call('/api/auth/callback?code=c1&state=forged')).status, 400);
});

test('framed sign-in hands off a code that only the nonce holder can redeem', async () => {
  const nonce = 'N'.repeat(43);
  const { callback } = await signIn({ embedNonce: nonce });
  const location = callback.headers.Location;
  assert.match(location, /^\/auth\/popup-complete\.html#code=/);
  const code = location.split('#code=')[1];
  const redeem = (body, headers = {}) => call('/api/auth/embed-session', {
    method: 'POST', body,
    headers: { origin: `https://${HOST}`, 'x-godseye-embed': '1', ...headers },
  });
  assert.equal((await redeem({ code, nonce: 'M'.repeat(43) })).status, 401);
  assert.equal((await redeem({ code, nonce }, { origin: 'https://evil.example' })).status, 403);
  assert.equal((await redeem({ code, nonce }, { 'x-godseye-embed': undefined })).status, 403);
  const ok = await redeem({ code, nonce });
  assert.equal(ok.status, 204);
  assert.match([].concat(ok.headers['Set-Cookie'])[0], /HttpOnly; Secure; SameSite=None; Partitioned/);
  const session = await readSession(`${SESSION_COOKIE}=${cookieValue(ok, SESSION_COOKIE)}`, SECRET);
  assert.equal(session.typ, 'session');
  assert.equal(session.email, 'pat@example.com');
  // A session token is not a handoff code.
  assert.equal((await redeem({ code: cookieValue(ok, SESSION_COOKIE), nonce })).status, 401);
});

test('a bad embed nonce is refused before any redirect, and an unconfigured deployment fails closed', async () => {
  assert.equal((await call('/api/auth/login?embed=short')).status, 400);
  const url = new URL(`https://${HOST}/api/auth/login`);
  const res = response();
  await handleAuth(request(), res, url.pathname, url, { config: { ...config, secret: '' }, fetchImpl: fakeSysop() });
  assert.equal(res.status, 503);
});

test('the middleware lets signed-in requests through and gates everything else', async () => {
  const { default: middleware } = await import('../../middleware.js');
  process.env.GODSEYE_SESSION_SECRET = SECRET;
  const session = await signToken({ typ: 'session', sub: 'u', email: 'a@b.c' }, SECRET, 60);
  const run = (path, cookie) => middleware(new Request(`https://${HOST}${path}`, { headers: cookie ? { cookie } : {} }));
  assert.equal((await run('/', `${SESSION_COOKIE}=${session}`)).headers.get('x-middleware-next'), '1');
  assert.equal((await run('/api/auth/login')).headers.get('x-middleware-next'), '1');
  assert.equal((await run('/api/flights')).status, 401);
  assert.equal((await run('/api/flights', `${SESSION_COOKIE}=${session}x`)).status, 401);
  assert.equal((await run('/')).headers.get('x-middleware-rewrite'), `https://${HOST}/auth/signin.html`);
});

test('the API function refuses provider routes without a session', async () => {
  const { default: handler } = await import('../../api/index.js');
  process.env.GODSEYE_SESSION_SECRET = SECRET;
  const res = response();
  await handler(Object.assign(request(), { url: '/api/index?__path=flights' }), res);
  assert.equal(res.status, 401);
});

test('only listed emails or domains are allowed, and an empty list admits no one', () => {
  const allowed = { emails: ['guest@gmail.com'], domains: ['scaledbydesign.com'] };
  assert.equal(isAllowedEmail('Pat@ScaledByDesign.com', allowed), true);
  assert.equal(isAllowedEmail('guest@gmail.com', allowed), true);
  for (const email of ['other@gmail.com', 'pat@evil-scaledbydesign.com', 'pat@scaledbydesign.com.evil.com', '', null])
    assert.equal(isAllowedEmail(email, allowed), false);
  assert.equal(isAllowedEmail('pat@scaledbydesign.com', { emails: [], domains: [] }), false);
  assert.deepEqual(authConfig({}).allowed, { emails: [], domains: ['scaledbydesign.com'] });
  assert.deepEqual(authConfig({ GODSEYE_ALLOWED_DOMAINS: '' }).allowed.domains, []);
});

test('a signed-in account outside the allowlist gets no session and no handoff', async () => {
  const saved = config.allowed;
  config.allowed = { emails: [], domains: ['scaledbydesign.com'] };
  try {
    for (const embedNonce of [undefined, 'N'.repeat(43)]) {
      const { callback } = await signIn({ embedNonce, expectStatus: 403 });
      assert.equal(callback.status, 403);
      assert.equal(cookieValue(callback, SESSION_COOKIE), null);
    }
  } finally {
    config.allowed = saved;
  }
});

test('an unknown signing key refetches the JWKS once (SysOp key rotation)', async () => {
  const rotated = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify'],
  );
  await call('/api/auth/login'); // caches the JWKS with only k1
  jwks.keys.push({ ...(await crypto.subtle.exportKey('jwk', rotated.publicKey)), kid: 'k2' });
  const originalKey = keys.privateKey;
  keys.privateKey = rotated.privateKey;
  try {
    const { callback } = await signIn({ header: { alg: 'RS256', kid: 'k2' }, keepCache: true });
    assert.equal(callback.status, 302);
  } finally {
    keys.privateKey = originalKey;
    jwks.keys.pop();
  }
});

test('a pinned public origin wins over the Host header', async () => {
  config.publicOrigin = 'https://godseye.delegate.ws';
  try {
    const url = new URL('https://attacker.example/api/auth/login');
    const res = response();
    const req = Object.assign(request(), { headers: { host: 'attacker.example' } });
    await handleAuth(req, res, url.pathname, url, { config, fetchImpl: fakeSysop() });
    assert.equal(new URL(res.headers.Location).searchParams.get('redirect_uri'), 'https://godseye.delegate.ws/api/auth/callback');
  } finally {
    config.publicOrigin = '';
  }
});
