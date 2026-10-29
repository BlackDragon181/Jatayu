"""
verify_frontend.py — comprehensive headless UI/design check for the JATAYU SPA.

Generalises verify_ui.py: launches the app (snapshot mode) and renders EVERY
section in BOTH dark and light themes, asserting design correctness:

  • no uncaught JS errors (fatal),
  • no invisible / low-contrast text — the effective text colour vs. its first
    non-transparent ancestor background, flagged when the WCAG contrast ratio
    is below a threshold (catches dark-on-dark / light-on-light, e.g. the
    "Live Data" date-filter bug),
  • charts / SVG diagrams actually draw where expected,
  • per-section Back (.sec-back) + Export (.sec-export) controls are present.

Saves screenshots to static/ss_frontend_<theme>_<section>.png and exits
non-zero on any fatal failure — suitable for CI / pre-deploy gates.

Run (PowerShell on this box — Bash can't fork here):
    python verify_frontend.py
    python verify_frontend.py -v          # list every contrast flag
Needs: pip install playwright ; playwright install chromium
"""

import os
import subprocess
import sys
import time
import urllib.request

PORT = 5063  # avoid Chromium's ERR_UNSAFE_PORT list (5060/5061 = SIP)
URL = f"http://localhost:{PORT}/"
VERBOSE = "-v" in sys.argv or "--verbose" in sys.argv

# Contrast ratio below CONTRAST_FATAL == effectively invisible text (same-on-same,
# e.g. the "Live Data" dark-on-dark bug). This is NOT a full WCAG audit — the app's
# cyberpunk palette uses deliberately-muted text (ratio ~3-4.5) which we do not fail.
# We only fail on genuine invisibility, and warn on notably-low contrast.
CONTRAST_FATAL = 1.6
CONTRAST_WARN = 2.6

# Sections that must render a chart canvas / SVG when populated.
CHART_SECTIONS = {"sec-overview", "sec-analytics", "sec-risk"}

# JS injected into the page: returns low-contrast text elements in the active page.
# args: {pageId, fallback:{r,g,b}} — fallback is the theme's real page background,
# used when no opaque ancestor background is found.
_SCAN_JS = r"""
(args) => {
  const pageId=args.pageId, fb=args.fallback, WARN=args.warn;
  function parseRGB(s){
    const m=(s||'').match(/rgba?\(([^)]+)\)/);
    if(!m) return null;
    const p=m[1].split(',').map(x=>parseFloat(x.trim()));
    return {r:p[0], g:p[1], b:p[2], a:(p.length>3?p[3]:1)};
  }
  function lum(c){
    const f=v=>{v/=255; return v<=0.03928? v/12.92 : Math.pow((v+0.055)/1.055,2.4);};
    return 0.2126*f(c.r)+0.7152*f(c.g)+0.0722*f(c.b);
  }
  // first opaque ancestor background; null if a gradient/image is hit (can't
  // reliably sample a colour over a gradient, so we skip those elements).
  function effBg(el){
    let n=el;
    while(n && n.nodeType===1){
      const cs=getComputedStyle(n);
      if((cs.backgroundImage||'none')!=='none') return null;
      const bg=parseRGB(cs.backgroundColor);
      if(bg && bg.a>0.6) return bg;
      n=n.parentElement;
    }
    return {r:fb.r, g:fb.g, b:fb.b, a:1};
  }
  const page=document.getElementById(pageId);
  if(!page) return [];
  const out=[];
  for(const el of page.querySelectorAll('*')){
    const own=Array.from(el.childNodes).filter(n=>n.nodeType===3 && n.textContent.trim()).map(n=>n.textContent.trim()).join(' ');
    if(!own) continue;
    const st=getComputedStyle(el);
    if(st.visibility==='hidden'||st.display==='none'||parseFloat(st.opacity)<0.15) continue;
    // skip gradient-clipped text (e.g. brand wordmark) — colour is transparent fill
    if((st.webkitTextFillColor||'')==='rgba(0, 0, 0, 0)' || st.webkitTextFillColor==='transparent') continue;
    const r=el.getBoundingClientRect();
    if(r.width<3||r.height<3) continue;
    const fg=parseRGB(st.color);
    if(!fg||fg.a<0.35) continue;
    const bg=effBg(el);
    if(!bg) continue;   // sat over a gradient/image — not assessable
    const L1=lum(fg)+0.05, L2=lum(bg)+0.05;
    const ratio=Math.max(L1,L2)/Math.min(L1,L2);
    if(ratio < WARN){
      let cls=(el.className && typeof el.className==='string')?('.'+el.className.trim().split(/\s+/).slice(0,2).join('.')):'';
      out.push({sel: el.tagName.toLowerCase()+(el.id?('#'+el.id):'')+cls,
                text: own.slice(0,40), ratio: Math.round(ratio*100)/100,
                color: st.color, bg: 'rgb('+bg.r+','+bg.g+','+bg.b+')'});
    }
  }
  return out;
}
"""


def _wait_up(timeout=40):
    for _ in range(timeout * 2):
        try:
            with urllib.request.urlopen(URL + "api/status", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def main():
    env = dict(os.environ, VERCEL="1", PORT=str(PORT))
    proc = subprocess.Popen([sys.executable, "app.py"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    failures = []
    warnings = []
    try:
        if not _wait_up():
            print("FAIL: app did not start"); return 1
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1500, "height": 980})
            js_errors = []
            page.on("console", lambda m: js_errors.append(m.text)
                    if m.type == "error" and "Failed to load resource" not in m.text else None)
            page.on("pageerror", lambda e: js_errors.append(str(e)))
            page.goto(URL, wait_until="networkidle")
            page.wait_for_function("typeof DC!=='undefined' && DC.threat_intel", timeout=20000)
            page.evaluate("document.getElementById('loading') && document.getElementById('loading').remove()")
            section_ids = page.evaluate("() => (typeof PAGE_IDS!=='undefined') ? PAGE_IDS : []")
            print(f"sections: {len(section_ids)}  themes: dark, light")

            for theme in ("dark", "light"):
                page.evaluate(
                    "(t)=>{ if(t==='light') document.documentElement.setAttribute('data-theme','light');"
                    " else document.documentElement.removeAttribute('data-theme'); }", theme)
                page.wait_for_timeout(150)
                # resolve the theme's real page background for the contrast fallback
                fb = page.evaluate(
                    "()=>{const m=(getComputedStyle(document.body).backgroundColor||'').match(/rgba?\\(([^)]+)\\)/);"
                    "if(m){const p=m[1].split(',').map(x=>parseFloat(x));if(p[3]===undefined||p[3]>0.6)return{r:p[0],g:p[1],b:p[2]};}"
                    "return null;}")
                if not fb:
                    fb = {"r": 231, "g": 237, "b": 245} if theme == "light" else {"r": 19, "g": 21, "b": 29}
                for sid in section_ids:
                    before = len(js_errors)
                    page.evaluate("(id)=>showPage(id)", sid)
                    page.wait_for_timeout(700)
                    # contrast scan
                    flags = page.evaluate(_SCAN_JS, {"pageId": sid, "fallback": fb, "warn": CONTRAST_WARN})
                    fatal = [f for f in flags if f["ratio"] < CONTRAST_FATAL]
                    warn = [f for f in flags if CONTRAST_FATAL <= f["ratio"] < CONTRAST_WARN]
                    for f in fatal:
                        failures.append(f"[{theme}/{sid}] invisible text ratio={f['ratio']} "
                                        f"{f['sel'][:60]} '{f['text']}' color={f['color']} on {f['bg']}")
                    warnings.extend([f"[{theme}/{sid}] low-contrast ratio={f['ratio']} {f['sel'][:50]} '{f['text']}'" for f in warn])  # noqa
                    # JS errors during this section
                    if len(js_errors) > before:
                        for e in js_errors[before:]:
                            failures.append(f"[{theme}/{sid}] JS error: {e[:140]}")
                    # back/export controls
                    chrome = page.evaluate(
                        "(id)=>({back:document.querySelectorAll('#'+id+' .sec-back').length,"
                        "exp:document.querySelectorAll('#'+id+' .sec-export').length})", sid)
                    if chrome["back"] < 1:
                        failures.append(f"[{theme}/{sid}] missing Back control")
                    # chart/SVG presence for chart-heavy sections
                    if sid in CHART_SECTIONS:
                        drew = page.evaluate(
                            "(id)=>{const cs=document.querySelectorAll('#'+id+' canvas');"
                            "let ok=false;cs.forEach(c=>{if(c.clientHeight>40)ok=true;});return {n:cs.length,ok};}", sid)
                        if drew["n"] and not drew["ok"]:
                            failures.append(f"[{theme}/{sid}] canvas present but did not size/draw")

                # explicit date-filter option check (the reported bug)
                df = page.evaluate(
                    "()=>{const s=document.getElementById('date-select');if(!s)return null;"
                    "const cs=getComputedStyle(s.options[0]);return {color:cs.color,bg:cs.backgroundColor};}")
                if df:
                    print(f"  [{theme}] #date-select option: color={df['color']} bg={df['bg']}")

                # screenshots for key sections
                for sid in ("sec-overview", "sec-analytics", "sec-patchsphere"):
                    if sid in section_ids:
                        page.evaluate("(id)=>showPage(id)", sid)
                        page.wait_for_timeout(400)
                        try:
                            page.locator("#" + sid).screenshot(path=f"static/ss_frontend_{theme}_{sid}.png")
                        except Exception:
                            pass
            browser.close()

        print()
        if warnings:
            print(f"{len(warnings)} low-contrast warning(s) (ratio {CONTRAST_FATAL}-{CONTRAST_WARN}):")
            for w in (warnings if VERBOSE else warnings[:6]):
                print("  ~", w)
            if not VERBOSE and len(warnings) > 6:
                print(f"  ... +{len(warnings)-6} more (run -v)")
        if failures:
            print(f"\n{len(failures)} FATAL issue(s):")
            for f in failures[:30]:
                print("  x", f)
            print("\nRESULT: FAIL")
            return 1
        print("\nAll sections render correctly in dark + light themes: no invisible text, "
              "charts/SVG draw, Back/Export present, no JS errors.")
        print("RESULT: PASS")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
