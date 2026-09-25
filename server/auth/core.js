// SysOp OIDC sign-in for the hosted deployment. WebCrypto only, so the same
// code runs in the Vercel edge middleware and in the Node API function.

export const SESSION_COOKIE = '__Host-gev_session';
export const OAUTH_COOKIE = '__Host-gev_oauth';
export const SESSION_TTL_SECONDS = 12 * 60 * 60;
export const OAUTH_TTL_SECONDS = 10 * 60;
export const HANDOFF_TTL_SECONDS = 60;
export const EMBED_NONCE_PATTERN = /^[A-Za-z0-9_-]{32,128}$/;
export const DEFAULT_ISSUER = 'https://api.portal.omnicart.cc/oauth';
export const DEFAULT_CLIENT_ID = 'godseye-web';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function base64UrlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function base64UrlDecode(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value))
    throw new Error('bad base64url');
  const padded =
    value.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - (value.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

export function randomToken(bytes = 32) {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256(value) {
  return base64UrlEncode(
    new Uint8Array(
      await crypto.subtle.digest('SHA-256', encoder.encode(value)),
    ),
  );
}

function now() {
  return Math.floor(Date.now() / 1000);
}

function parseJwt(token) {
  if (typeof token !== 'string' || token.length > 8192) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    return {
      header: JSON.parse(decoder.decode(base64UrlDecode(parts[0]))),
      payload: JSON.parse(decoder.decode(base64UrlDecode(parts[1]))),
      signed: encoder.encode(`${parts[0]}.${parts[1]}`),
      signature: base64UrlDecode(parts[2]),
    };
  } catch {
    return null;
  }
}

async function hmacKey(secret) {
  if (typeof secret !== 'string' || secret.length < 32)
    throw new Error('session secret missing or too short');
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

/** Sign an HS256 token of our own (session, OAuth state, embed handoff). */
export async function signToken(claims, secret, ttlSeconds) {
  const header = base64UrlEncode(
    encoder.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })),
  );
  const iat = now();
  const body = base64UrlEncode(
    encoder.encode(JSON.stringify({ ...claims, iat, exp: iat + ttlSeconds })),
  );
  const signature = await crypto.subtle.sign(
    'HMAC',
    await hmacKey(secret),
    encoder.encode(`${header}.${body}`),
  );
  return `${header}.${body}.${base64UrlEncode(new Uint8Array(signature))}`;
}

/** Verify one of our HS256 tokens and its `typ`; returns the claims or null. */
export async function verifyToken(token, secret, typ) {
  const jwt = parseJwt(token);
  if (!jwt || jwt.header.alg !== 'HS256') return null;
  const valid = await crypto.subtle.verify(
    'HMAC',
    await hmacKey(secret),
    jwt.signature,
    jwt.signed,
  );
  if (!valid) return null;
  const { payload } = jwt;
  if (
    payload.typ !== typ ||
    typeof payload.exp !== 'number' ||
    payload.exp <= now()
  )
    return null;
  return payload;
}

export function readCookie(header, name) {
  for (const part of (header ?? '').split(';')) {
    const index = part.indexOf('=');
    if (index > 0 && part.slice(0, index).trim() === name)
      return part.slice(index + 1).trim();
  }
  return null;
}

/** `Set-Cookie` for a host-only cookie. Framed sessions must be SameSite=None and partitioned (CHIPS). */
export function cookie(name, value, maxAge, { embedded = false } = {}) {
  const site = embedded ? 'SameSite=None; Partitioned' : 'SameSite=Lax';
  return `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; ${site}`;
}

export async function readSession(cookieHeader, secret) {
  if (!secret) return null;
  const token = readCookie(cookieHeader, SESSION_COOKIE);
  if (!token) return null;
  try {
    return await verifyToken(token, secret, 'session');
  } catch {
    return null;
  }
}

export function sessionClaims(identity) {
  return {
    typ: 'session',
    sub: identity.sub,
    email: identity.email,
    name: identity.name ?? null,
  };
}

/** A same-origin path to return to after sign-in; anything else becomes `/`. */
export function safeReturnPath(value) {
  if (
    typeof value !== 'string' ||
    !value.startsWith('/') ||
    value.startsWith('//') ||
    value.includes('\\')
  )
    return '/';
  if (/[\u0000-\u001f]/.test(value) || value.startsWith('/api/')) return '/';
  return value.slice(0, 512);
}

/**
 * Verify a SysOp ID token (RS256) against the issuer's JWKS: signature, issuer,
 * audience, authorized party, expiry, nonce, and a verified email.
 */
export async function verifyIdToken(
  idToken,
  { jwks, issuer, clientId, nonce },
) {
  const jwt = parseJwt(idToken);
  if (!jwt || jwt.header.alg !== 'RS256')
    throw new Error('id_token must be RS256');
  const jwk = (jwks?.keys ?? []).find(
    (key) => key.kid === jwt.header.kid && key.kty === 'RSA',
  );
  if (!jwk) throw new Error('id_token signing key not found');
  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  if (
    !(await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      jwt.signature,
      jwt.signed,
    ))
  )
    throw new Error('id_token signature invalid');
  const claims = jwt.payload;
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== issuer) throw new Error('id_token issuer mismatch');
  if (!audiences.includes(clientId))
    throw new Error('id_token audience mismatch');
  if (claims.azp !== undefined && claims.azp !== clientId)
    throw new Error('id_token azp mismatch');
  if (typeof claims.exp !== 'number' || claims.exp <= now())
    throw new Error('id_token expired');
  if (!nonce || claims.nonce !== nonce)
    throw new Error('id_token nonce mismatch');
  if (typeof claims.sub !== 'string' || !claims.sub)
    throw new Error('id_token has no subject');
  if (
    typeof claims.email !== 'string' ||
    !claims.email ||
    claims.email_verified === false
  )
    throw new Error('id_token has no verified email');
  return {
    sub: claims.sub,
    email: claims.email.toLowerCase(),
    name: typeof claims.name === 'string' ? claims.name : null,
  };
}

/**
 * SysOp creates an account for any Google user on first sign-in, so SysOp
 * identity alone is not authorization. Only listed emails or domains get in;
 * an empty list admits no one.
 */
export function isAllowedEmail(email, { emails = [], domains = [] } = {}) {
  if (typeof email !== 'string' || !email.includes('@')) return false;
  const address = email.toLowerCase();
  return (
    emails.includes(address) ||
    domains.includes(address.slice(address.lastIndexOf('@') + 1))
  );
}
