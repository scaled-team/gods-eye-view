# God's Eye View on Vercel

This fork preserves the upstream interface and adapts its Node middleware to a
single Vercel function. Use Node 24.x and the settings in `vercel.json`.

## Deployment boundary

- Deploy as a **preview**, retaining Vercel Authentication. Do not promote to an
  unprotected production domain without explicitly reviewing access controls.
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

## Verification

`npm run build` verifies the static frontend. `/api/health` reports the keyless
runtime. `/api/setup/keys` must return 404 and paid/persistent features must return
503. Check the globe, live aircraft, camera catalog, and geocoding separately.
An upstream refusal must not be reported as a successful live feed.

Upstream: https://github.com/bilawalsidhu/gods-eye-view
