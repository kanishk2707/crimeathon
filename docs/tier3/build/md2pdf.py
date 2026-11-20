"""Render a Markdown file to a black-and-white A4 PDF (Vortex style) with Edge headless.

  python docs/tier3/build/md2pdf.py docs/tier3/PROOF_PACK.md docs/tier3/Vortex_CR-26-047_Proof_Pack.pdf
Requires: pip install markdown ; Microsoft Edge (Windows).
"""
import subprocess
import sys
from pathlib import Path

import markdown

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
LOGO = ('<svg viewBox="4.5 4.5 15 15" width="30" height="30" aria-hidden="true"><path d="M12 12a1 1 0 0 1 2 0a2 2 0 0 1-4 0a3 3 0 0 1 6 0'
        'a4 4 0 0 1-8 0a5 5 0 0 1 10 0a6 6 0 0 1-12 0" fill="none" stroke="#000" stroke-width="1.35" stroke-linecap="round"/></svg>')
CSS = """
@page { size: A4; margin: 12mm 11mm 13mm; @bottom-right { content: "Proof pack · " counter(page); font-family: "Segoe UI", sans-serif; font-size: 7pt; color: #555; } }
*{box-sizing:border-box}
body{font-family:"Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;font-size:8.4pt;line-height:1.42;color:#000;margin:0;
  -webkit-print-color-adjust:exact;print-color-adjust:exact}
.hdr{display:flex;align-items:center;gap:10px;border-bottom:2px solid #000;padding-bottom:6px;margin-bottom:10px}
.hdr .t{font-family:"Bahnschrift","Segoe UI",sans-serif;font-weight:700;font-size:15pt;letter-spacing:.2em}
.hdr .k{font-size:7.4pt;color:#333;margin-left:auto;text-align:right}
h1{font-family:"Bahnschrift","Segoe UI",sans-serif;font-weight:600;font-size:17pt;margin:4px 0 4px}
h2{font-family:"Bahnschrift","Segoe UI",sans-serif;font-weight:600;font-size:11pt;letter-spacing:.04em;text-transform:uppercase;
  border-bottom:1px solid #999;padding-bottom:2px;margin:16px 0 6px;break-after:avoid}
h3{font-family:"Bahnschrift","Segoe UI",sans-serif;font-weight:600;font-size:9.2pt;margin:11px 0 4px;break-after:avoid}
p{margin:0 0 6px} ul,ol{margin:0 0 6px;padding-left:18px} li{margin:0 0 3px}
code{font-family:Consolas,"Cascadia Mono",monospace;font-size:.9em}
pre{background:#f2f2f2;border:1px solid #ccc;border-radius:3px;padding:7px 9px;font-size:7.4pt;line-height:1.35;white-space:pre-wrap;break-inside:avoid}
pre code{font-size:1em}
table{border-collapse:collapse;width:100%;margin:2px 0 8px;font-size:7.2pt;line-height:1.32}
thead{display:table-header-group}
tr{break-inside:avoid}
th{background:#000;color:#fff;text-align:left;font-weight:600;padding:3px 5px;font-family:"Bahnschrift","Segoe UI",sans-serif;letter-spacing:.02em}
td{border-bottom:1px solid #d4d4d4;padding:2.5px 5px;vertical-align:top;overflow-wrap:break-word}
td code{font-size:.92em}
hr{border:0;border-top:1px solid #999;margin:12px 0 6px}
strong{font-weight:600}
"""


def main(src, dst):
    src, dst = Path(src).resolve(), Path(dst).resolve()
    body = markdown.markdown(src.read_text(encoding="utf-8"), extensions=["tables", "fenced_code", "sane_lists", "toc"])
    html = (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>{src.stem}</title><style>{CSS}</style></head><body>"
            f"<div class='hdr'>{LOGO}<span class='t'>VORTEX</span><span class='k'>CRIMEATHON’26 · Tier 3 · Case CR-26-047<br>"
            f"github.com/kanishk2707/crimeathon</span></div>{body}</body></html>")
    tmp = dst.with_suffix(".html")
    tmp.write_text(html, encoding="utf-8")
    subprocess.run([EDGE, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={dst}", tmp.as_uri()],
                   check=True, capture_output=True)
    tmp.unlink()
    print(f"wrote {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
