# Deploying to Vercel

> **Heads-up (read this first).** Vercel runs **stateless serverless functions**
> with no long-lived process and tight execution limits. This app was built as a
> persistent server (background scheduler, in-memory cache, 30–60s scans). It has
> been adapted to run on Vercel, but with trade-offs:
>
> | Feature | On Vercel | Why |
> |---------|-----------|-----|
> | **Dashboard data** | ✅ Works (served from a pre-built snapshot) | Live refresh (~90s) exceeds function limits, so data is fetched at build time |
> | **Theme / pagination / research reader / PDF brief** | ✅ Works | Pure request/response |
> | **Data freshness** | ⚠️ As of last build | No background scheduler on serverless — redeploy (or rebuild the snapshot) to refresh |
> | **Attack-surface scanner — IP / ASN** | ⚠️ Usually works | A few seconds; may exceed the Hobby 10s default on cold start |
> | **Attack-surface scanner — domain** | ❌ Times out on Hobby | A domain scan takes 30–60s; Hobby caps at ~10s (needs Pro + raised `maxDuration`) |
>
> For full functionality (live refresh + domain scans) a persistent host like
> **Render/Railway** is still the better fit — see `DEPLOY.md`.

## How it’s wired

- `app.py` detects Vercel via the `VERCEL` env var. On serverless it **skips the
  scheduler** and **primes data from `data_snapshot.json`** (bundled) instead of
  fetching live.
- All writable paths already fall back to `/tmp` (`fetcher._writable_base`), so
  the read-only serverless filesystem won’t crash it.
- `vercel.json` builds `app.py` with `@vercel/python` and routes all requests to it.
- `build_snapshot.py` produces `data_snapshot.json` (the dashboard’s data).

## Deploy steps

1. **Generate the data snapshot** (do this whenever you want fresh data):
   ```bash
   python build_snapshot.py
   ```
   This writes `data_snapshot.json` (~0.5 MB). Commit it.

2. **Push to a Git repo** (GitHub/GitLab/Bitbucket).

3. **Import the repo in Vercel** (vercel.com → Add New → Project). Vercel reads
   `vercel.json` automatically. No framework preset needed.
   - Or via CLI:
     ```bash
     npm i -g vercel
     vercel        # preview deploy
     vercel --prod # production
     ```

4. (Optional) Add API keys under **Project → Settings → Environment Variables**:
   `OTX_API_KEY`, `VT_API_KEY`, `ABUSEIPDB_KEY`. They enrich live scans.

Your app will be at `https://<project>.vercel.app`.

## Refreshing the data

Because there’s no scheduler on serverless, data only updates when you rebuild
the snapshot and redeploy:

```bash
python build_snapshot.py && vercel --prod
```

To automate, add a **Vercel Cron Job** that triggers a redeploy via a Deploy Hook,
or move to Render/Railway where the 4-hour scheduler runs natively.

## Enabling the domain scanner on Vercel (optional, needs Pro)

The scanner runs live and a domain scan needs ~30–60s. To allow it:
- Use a **Pro** plan and raise the function timeout (`maxDuration`, up to 300s).
- This requires the modern `functions` config instead of the legacy `builds`
  block in `vercel.json`. On Hobby, leave it as-is — IP/ASN scans work, domain
  scans will hit the 10s limit.
