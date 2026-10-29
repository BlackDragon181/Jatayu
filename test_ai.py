"""
test_ai.py — live end-to-end test of the "Ask AI" vendor remediation route.

Run with your key set IN YOUR OWN SHELL so the secret never lands in chat/logs:

  PowerShell:
    $env:ANTHROPIC_API_KEY = "sk-ant-..."; python test_ai.py CVE-2021-44228

  bash:
    ANTHROPIC_API_KEY=sk-ant-... python test_ai.py CVE-2021-44228

Exercises the real /api/remediation/ai route (snapshot mode), which fetches the
live vendor advisory, grounds a prompt on it, and calls claude-opus-4-8.
"""
import os
import sys

os.environ.setdefault("VERCEL", "1")  # snapshot mode: no scheduler, instant data

cve = (sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228").upper()

if not os.environ.get("ANTHROPIC_API_KEY"):
    print("ANTHROPIC_API_KEY is not set in this process. Set it first, e.g.:")
    print('  $env:ANTHROPIC_API_KEY = "sk-ant-..."; python test_ai.py ' + cve)
    sys.exit(1)

import app  # noqa: E402

client = app.app.test_client()

print(f"== Vendor advisory (live) for {cve} ==")
adv = client.get(f"/api/remediation/advisory?cve={cve}").get_json()
print("vendor:", adv.get("vendor"), "| url:", adv.get("url") or adv.get("portal"))
print("extracted:", (adv.get("text") or "(none)")[:300])

print(f"\n== Ask AI ({cve}) ==")
r = client.get(f"/api/remediation/ai?cve={cve}")
j = r.get_json()
print("HTTP", r.status_code, "| model:", j.get("model"))
if r.status_code == 200:
    print("\n--- AI-tailored remediation ---")
    print(j.get("guidance", ""))
    print("\nOK — Ask AI works end-to-end.")
else:
    print("ERROR:", j.get("error"))
    sys.exit(2)
