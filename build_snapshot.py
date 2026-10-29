"""
build_snapshot.py — generate data_snapshot.json for serverless (Vercel) deploys.

Vercel runs stateless functions with no background scheduler and tight time
limits, so the dashboard data is fetched ONCE here (at build / pre-deploy time)
and bundled as a static snapshot the function serves instantly.

Run before deploying (or wire into the Vercel build step):
    python build_snapshot.py
"""

import json
from pathlib import Path

from fetcher import DataFetcher

OUT = Path(__file__).resolve().parent / "data_snapshot.json"


def main():
    print("Fetching all threat-intel sources for snapshot…")
    data = DataFetcher().refresh_all()
    OUT.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    src = data.get("metadata", {}).get("sources", {})
    size_kb = OUT.stat().st_size / 1024
    print(f"Wrote {OUT.name} ({size_kb:.1f} KB)")
    print("Sources:", src)


if __name__ == "__main__":
    main()
