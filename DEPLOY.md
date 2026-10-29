# Deploying JATAYU

This app is a **persistent Flask server** (background scheduler, in-memory cache,
30–60s attack-surface scans). It needs a host that runs a long-lived process —
**not** a serverless platform like Vercel (whose 10s function limit and read-only
filesystem are incompatible with this design).

Recommended: **Render** or **Railway** (both have free tiers).

---

## Option A — Render (one-click via Blueprint)

1. Push this folder to a GitHub/GitLab repo.
2. Go to <https://dashboard.render.com> → **New → Blueprint** → pick the repo.
   Render reads `render.yaml` and configures everything.
3. (Optional) Set API keys under the service's **Environment** tab:
   `OTX_API_KEY`, `VT_API_KEY`, `ABUSEIPDB_KEY`. The app works without them.
4. Deploy. Your app is at `https://<service>.onrender.com`.

Manual setup (without the Blueprint):
- **Build command:** `pip install -r requirements.txt`
- **Start command:** `gunicorn app:app --workers 1 --threads 8 --timeout 120 --bind 0.0.0.0:$PORT`
- **Health check path:** `/api/status`

---

## Option B — Railway

1. Push to a Git repo.
2. <https://railway.app> → **New Project → Deploy from GitHub repo**.
3. Railway auto-detects Python and uses the `Procfile`:
   `web: gunicorn app:app --workers 1 --threads 8 --timeout 120 --bind 0.0.0.0:$PORT`
4. (Optional) Add `OTX_API_KEY` / `VT_API_KEY` / `ABUSEIPDB_KEY` in **Variables**.
5. Generate a public domain under **Settings → Networking**.

---

## Why these settings

- **`--workers 1`** — the background scheduler and in-memory caches
  (`fetcher.current_data`, the scan cache) are per-process. One worker keeps a
  single shared copy instead of duplicating fetches across workers.
- **`--threads 8`** — still serves multiple requests concurrently.
- **`--timeout 120`** — a domain attack-surface scan can take 30–60s; the default
  gunicorn 30s timeout would kill it.
- **Writable data dir** — `cache/` and `history/` resolve via `DATA_DIR` → app dir
  → OS temp dir (see `fetcher._writable_base`), so the app never crashes on a
  read-only filesystem. Set `DATA_DIR` to a mounted disk if you want persistence
  across restarts (otherwise data is re-fetched on startup, which is fine).

## Notes on free tiers

- Free instances **sleep when idle**. The first request after sleeping cold-starts
  the app; the scheduler then refreshes data immediately in the background, so
  `/api/data` may return 503 ("loading") for ~60–90s while the first fetch runs —
  the dashboard handles this and retries automatically.
- For always-on behavior and persistent storage, upgrade to a paid instance and
  attach a disk mounted at `DATA_DIR`.

---

## Local development (unchanged)

```bash
pip install -r requirements.txt
python app.py            # http://localhost:5000
```

`gunicorn` is Linux-only and is used only in production; local dev still uses
`python app.py`.
