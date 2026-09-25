# God's Eye View on Vercel

This fork preserves the upstream interface and adapts its Node middleware to a
single Vercel function. Use Node 24.x and the settings in `vercel.json`.

## Deployment boundary

- Every page and API route requires a **SysOp (Delegate Login) session**.
  `middleware.js` gates `/` and `/api/*`; `api/index.js` checks the session
  again. Only `/api/auth/*`, `/api/health` and the static sign-in pages under
  `/auth/` are public. Preview deployments keep Vercel Authentication.
- Production is `https://godseye.delegate.ws`, framed by Delegate V2 as the
  native `godseye` app (sandbox profile `godseye-v1`). `frame-ancestors` allows
  `'self'`, `*.delegate.ws` and `*.omnicart.cc`.
- No API credentials are committed or configured for the initial deployment.
- Remote provider-key setup is disabled. Never enable the local `.env` editor on
  hosted infrastructure.
- OpenAI voice/HUD and persistent AIS ship ingestion are explicitly disabled.
- Anonymous OpenSky and keyless providers retain upstream validation and fetch
  limits. Data-source availability, throttling, and terms still apply.
- Caches are per-function-instance and ephemeral under `/tmp`, not durable or
  globally shared. A shared cache is recommended before expanding usage.
- Long-running radio/video streams and large provider responses may hit Vercel
  duration or payload limits. This is not a claim of full upstream feature parity.

## Sign-in

- SysOp OIDC public client `godseye-web` (PKCE, no client secret), redirect
  `https://godseye.delegate.ws/api/auth/callback`, Google login. The ID token is
  verified against the issuer's JWKS (issuer, audience, azp, expiry, nonce,
  verified email).
- Session: an HS256 cookie `__Host-gev_session`, 12 hours, signed with
  `GODSEYE_SESSION_SECRET` (Vercel sensitive env, production only, at least 32
  characters). Without it every sign-in route returns 503 and nothing opens.
  Optional: `SYSOP_OIDC_ISSUER`, `SYSOP_OIDC_CLIENT_ID`.
- Authorization: SysOp creates an account for any Google user, so a SysOp
  identity alone does not get in. The email must be in `GODSEYE_ALLOWED_EMAILS`
  or its domain in `GODSEYE_ALLOWED_DOMAINS` (comma-separated; unset means
  `scaledbydesign.com`, empty means no one). Others get 403 and no session.
- `GODSEYE_PUBLIC_ORIGIN=https://godseye.delegate.ws` in production pins the
  OAuth `redirect_uri` and the embed Origin check instead of trusting Host.
- Framed in Delegate V2, SysOp and Google cannot render in the frame, so the
  sign-in page opens a popup. The popup posts back a 60-second code bound to a
  nonce that only the frame holds; the frame redeems it at
  `/api/auth/embed-session` for a `SameSite=None; Partitioned` session cookie.

## Verification

`npm run build` verifies the static frontend. `/api/health` reports the keyless
runtime. `/api/setup/keys` must return 404 and paid/persistent features must return
503. Check the globe, live aircraft, camera catalog, and geocoding separately.
An upstream refusal must not be reported as a successful live feed.

Upstream: https://github.com/bilawalsidhu/gods-eye-view

## CI and deploys

- CI runs on Gitea (`git.delegate.ws/ScaledByDesign/gods-eye-view`,
  `.gitea/workflows/ci.yml`): formatting, package boundaries, unit tests
  (including `server/auth`) and the production build. The Gitea copy is
  push-fed: after a merge on GitHub, `git push gitea origin/main:refs/heads/main`.
  The upstream GitHub Actions workflow is removed; GitHub Actions is not a gate.
- Production deploys: the Vercel Git integration did not deploy on merge
  (2026-09-25), so production is deployed with `vercel deploy --prod` from a
  clean checkout of `main`. A Gitea deploy job needs a Vercel CI token, which
  must reach Gitea through Connect rather than by hand; Connect has no action
  that issues one yet.
