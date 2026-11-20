"""Build the narrated demo video (MP4, 1920x1080) from a real run of the engine.

  python docs/tier3/build/make_demo_video.py            # writes docs/tier3/demo/
Requires (docs only, not the engine): pip install playwright imageio-ffmpeg pillow numpy;
Microsoft Edge; Windows (narration uses the built-in System.Speech voice).

What it does, in order:
  1. runs `python -m doubleentry analyze evidence --out out/real --truth analysis/analyst_labels.json`
     and keeps the real console output for the terminal scene;
  2. screenshots out/real/report.html and eval/evaluation.html with Edge (Playwright), and finds each
     report section's position so the camera can scroll to it;
  3. synthesises the narration with Windows text-to-speech;
  4. renders every frame (scroll, slow zoom, captions, cross-fades) and encodes H.264 + AAC with ffmpeg;
  5. writes DEMO_SCRIPT.md with the timings, captions and narration, for re-recording in a human voice.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import wave
from pathlib import Path

import imageio_ffmpeg
import numpy as np
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "docs" / "tier3" / "demo"
WORK = OUT / "_work"
T2 = ROOT / "docs" / "tier2" / "Vortex_CR-26-047_Tier2_Concept.pptx"
ONEPAGER = ROOT / "docs" / "tier3" / "Vortex_CR-26-047_Final_OnePager.pptx"
EXPORT_PPT = ROOT / "docs" / "tier3" / "build" / "export_ppt.ps1"
W, H, FPS, DSF = 1920, 1080, 25, 1.5          # video size; browser device scale (1280 css px -> 1920 px)
CAP_H = 118                                   # caption bar height (px)
FADE = 0.4
FONT_DIR = Path("C:/Windows/Fonts")
LOGO_SVG = ('<svg viewBox="4.5 4.5 15 15" width="{s}" height="{s}"><path d="M12 12a1 1 0 0 1 2 0a2 2 0 0 1-4 0a3 3 0 0 1 6 0'
            'a4 4 0 0 1-8 0a5 5 0 0 1 10 0a6 6 0 0 1-12 0" fill="none" stroke="{c}" stroke-width="1.35" stroke-linecap="round"/></svg>')

# ----------------------------------------------------------------------------- scenes
# sel: ("top", None) | ("h2", text prefix) | ("h3", text fragment) -> where the camera starts in a long page.
SCENES = [
    dict(src="title", label="", caption="Live run on the supplied evidence (E01–E20)",
         say="Double-Entry Defense, by Team Vortex. Case C R 26, zero 47, Defense track. This is a live run of our engine on the supplied evidence."),
    dict(src="t2_2", label="The problem", caption="A trusted vendor key changed where we pay V-0412, with no approval, 5 days before a payment run",
         say="A trusted vendor integration, TallyBridge Connect, had its keys used by a second actor. It searched support tickets for secrets, "
             "stole a storage key, exported our vendor and payment lists, and on the third of September changed vendor V 0 4 1 2's bank account "
             "with no approval, five days before a payment run."),
    dict(src="t2_5", label="Architecture", caption="Every action by the integration must match an independent record",
         say="Our engine checks the integration the way an accountant checks books: every action must match an independent record. "
             "It loads the evidence, aligns the clocks, joins each actor's names across systems, runs four checks, and ranks findings by how soon money could leave."),
    dict(src="terminal", label="Run it", caption="pip install -r requirements.txt   ·   python -m doubleentry analyze evidence",
         say="Setup is one pip install. One command analyses the evidence and scores it against our labels: "
             "181 of 181 attacker records, zero false alarms, all nine stages. The obvious per-log rules raise almost 30 thousand false alarms."),
    dict(src="report", sel=("top", None), label="The report", caption="The decision comes first: hold one vendor before the 8 Sep payment run",
         say="The report opens with the decision: hold one vendor before the eighth of September payment run. Fifty alerts, joined into one incident."),
    dict(src="report", sel=("h2", "0 "), label="Four briefs", caption="One analysis, four readers: General Manager, Finance, Legal, IT security",
         say="The same findings are written four ways: for the General Manager, Finance, Legal, and IT security. Every line is generated from the analysis; nothing is typed by hand."),
    dict(src="report", sel=("h2", "1 "), label="Payment-run firewall", caption="HOLD V-0412: changed by a software key, no approval, unknown host  ·  call-back guard: 66 vendors",
         say="The payment-run firewall holds V 0 4 1 2. Its bank account was changed by a software key, with no approval, from a host that never carried the sync, "
             "and the report gives the last known good account to restore. The call-back guard warns that software rewrote the contact details of 66 vendors, "
             "so Finance must call the number in the contract, not the one on file."),
    dict(src="report", sel=("h2", "2 "), label="Incident threads", caption="All alerts join into one incident, 9 Aug to 6 Sep",
         say="Every alert joins into one incident thread, linked by shared keys and addresses, from the ninth of August to the sixth of September."),
    dict(src="report", sel=("h2", "3 "), label="Double-entry ledger", caption="Reads with no matching write go to the suspense account",
         say="The double-entry ledger pairs every read of our data with the write it serves. Reads with no matching write land in the suspense account."),
    dict(src="report", sel=("h2", "4 "), label="Witness check", caption="API log × network log: off-link use, and the unlisted link host 10.20.4.77",
         say="The witness check compares every API call with the private link's network log. It catches the stolen keys used from home broadband, "
             "and the vendor build host, 10.20.4.77, which never carried the sync."),
    dict(src="report", sel=("h2", "5 "), label="Sync grammar", caption="Learned from witnessed sessions only: searches, exports and a retired client break it",
         say="The sync grammar is learned only from witnessed sessions, with no hand labels. Ticket searches, exports and a retired client version break it."),
    dict(src="report", sel=("h2", "6 "), label="Exports and storage", caption="Deleted exports still appear on the invoice; a stolen storage key read /finance",
         say="Ten export jobs were deleted, but the vendor's invoice still counts them. And a storage key stolen from a support ticket read our finance folders."),
    dict(src="report", sel=("h3", "machine-checked"), label="Vendor-claim checker", caption="The vendor's statement, tested against our logs: 6 of 6 claims contradicted",
         say="We tested the vendor's own incident statement against our logs. All six claims are contradicted, and each verdict cites the records."),
    dict(src="report", sel=("h3", "Least-privilege"), label="Least-privilege replay", caption="Learned before 21 Jul, replayed after: 133 of 133 attacker requests refused",
         say="The least-privilege policy learns what each key really needs. Replayed on the rest of the evidence, it would have refused all 133 attacker requests. "
             "Among genuine requests, it refuses only the unreviewed contact sync."),
    dict(src="report", sel=("h2", "10 "), label="Evidence IDs", caption="Every alert cites the exact evidence records it relies on",
         say="Every alert lists the exact evidence records it relies on, so anyone can open the file and check."),
    dict(src="eval", sel=("top", None), label="Testing", caption="6 attack variants × 3 seeds: precision 1.00 everywhere; the hardest variant is half caught",
         say="To test variations we have not seen, we generate six attack variants with three seeds each. Precision is 1 point 0 everywhere. "
             "The hardest variant, an attacker hiding inside the sync's own session, is only half caught, and we say so."),
    dict(src="op_1", label="", caption="github.com/kanishk2707/crimeathon",
         say="Double-Entry Defense. The code, the proof pack and the technical report are on GitHub. Thank you."),
]


def font(names, size):
    for n in names:
        p = FONT_DIR / n
        if p.exists():
            return ImageFont.truetype(str(p), size)
    return ImageFont.load_default()


F_CAP = font(["seguisb.ttf", "segoeuib.ttf", "bahnschrift.ttf"], 34)
F_LABEL = font(["bahnschrift.ttf", "segoeuib.ttf"], 27)
F_MARK = font(["bahnschrift.ttf", "segoeuib.ttf"], 22)


# ----------------------------------------------------------------------------- 1. real run
def run_engine():
    t0 = time.perf_counter()
    r = subprocess.run([sys.executable, "-m", "doubleentry", "analyze", "evidence", "--out", "out/real", "--truth", "analysis/analyst_labels.json"],
                       cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=True)
    return r.stdout, time.perf_counter() - t0


def terminal_html(stdout: str, secs: float) -> str:
    keep = re.compile(r'^\s*("ours"|"baseline"|"malicious"|"tp"|"fp"|"fn"|"precision"|"recall"|"stages_detected")|^\s*[{}]\s*,?$|^\{|^\}')
    lines, skipped = [], False
    body = stdout.strip().splitlines()
    for ln in body[:-1]:
        if keep.search(ln):
            lines.append(ln); skipped = False
        elif not skipped:
            lines.append("    …"); skipped = True
    files = sorted(p.name for p in (ROOT / "out" / "real").iterdir())
    esc = lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    hl = lambda s: re.sub(r'("(?:tp|fp|fn|stages_detected)": )([^,\n]+)', r'\1<b>\2</b>', esc(s))
    out = [f'<span class="p">PS C:\\crimeathon&gt;</span> pip install -r requirements.txt',
           '<span class="d">Requirement already satisfied: pandas, numpy</span>',
           f'<span class="p">PS C:\\crimeathon&gt;</span> python -m doubleentry analyze evidence --out out/real --truth analysis/analyst_labels.json']
    out += [hl(x) for x in lines]
    out.append(f"<b>{esc(body[-1])}</b>")
    out.append(f'<span class="d">(finished in {secs:.0f} s)</span>')
    out.append('<span class="p">PS C:\\crimeathon&gt;</span> ls out/real')
    out.append("   ".join(files))
    css = ("body{margin:0;background:#0c0c0c;color:#e6e6e6;font:15.5px/1.42 Consolas,'Cascadia Mono',monospace}"
           ".bar{background:#1f1f1f;color:#bbb;font:13px 'Segoe UI',sans-serif;padding:8px 16px;display:flex;gap:8px;align-items:center}"
           ".bar i{width:11px;height:11px;border-radius:50%;background:#555;display:inline-block}"
           "pre{margin:0;padding:16px 24px 120px;white-space:pre-wrap}.p{color:#fff;font-weight:bold}.d{color:#8c8c8c}b{color:#fff}")
    return (f"<!doctype html><meta charset='utf-8'><style>{css}</style><div class='bar'><i></i><i></i><i></i>&nbsp; Windows PowerShell · crimeathon</div>"
            f"<pre>{'<br>'.join(out)}</pre>")


def title_html() -> str:
    css = ("html,body{margin:0;height:100%;background:#fff;color:#111;font-family:'Segoe UI',sans-serif}"
           ".w{height:100%;display:flex;flex-direction:column;justify-content:center;padding:0 110px}"
           ".b{display:flex;align-items:center;gap:18px;font:700 34px Bahnschrift,'Segoe UI';letter-spacing:.32em}"
           "h1{font:700 86px Bahnschrift,'Segoe UI';margin:34px 0 10px;letter-spacing:-.01em}"
           "p{font-size:27px;color:#333;margin:0}.k{margin-top:46px;font-size:19px;color:#6b6b6b;letter-spacing:.08em;text-transform:uppercase}")
    return (f"<!doctype html><meta charset='utf-8'><style>{css}</style><div class='w'><div class='b'>{LOGO_SVG.format(s=58, c='#111')}VORTEX</div>"
            "<h1>Double-Entry Defense</h1><p>Catching a trusted integration that changes where we pay, before the money moves.</p>"
            "<div class='k'>CRIMEATHON’26 · Tier 3 demo · Case CR-26-047 · Defense track</div></div>")


# ----------------------------------------------------------------------------- 2. screenshots
def screenshots(term: str):
    from playwright.sync_api import sync_playwright
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "terminal.html").write_text(term, encoding="utf-8")
    (WORK / "title.html").write_text(title_html(), encoding="utf-8")
    marks = {}
    with sync_playwright() as p:
        b = p.chromium.launch(channel="msedge", headless=True)
        ctx = b.new_context(viewport={"width": 1280, "height": 720}, device_scale_factor=DSF, color_scheme="light")
        pg = ctx.new_page()
        for name, path in [("title", WORK / "title.html"), ("terminal", WORK / "terminal.html"),
                           ("report", ROOT / "out" / "real" / "report.html"), ("eval", ROOT / "eval" / "evaluation.html")]:
            pg.goto(path.as_uri()); pg.wait_for_timeout(400)
            pg.screenshot(path=str(WORK / f"{name}.png"), full_page=name != "title")
            marks[name] = pg.evaluate("() => [...document.querySelectorAll('h2,h3')].map(h => ({tag: h.tagName.toLowerCase(), "
                                      "t: h.textContent.replace(/\\s+/g,' ').trim(), y: h.getBoundingClientRect().top + window.scrollY}))")
        b.close()
    # slides from the Tier 2 deck and the Tier 3 one-pager, exported by PowerPoint
    for deck, prefix in [(T2, "t2_"), (ONEPAGER, "op_")]:
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(EXPORT_PPT), str(deck),
                        str(WORK / f"{prefix}deck.pdf"), str(WORK / prefix)], check=True, capture_output=True)
    return marks


# ----------------------------------------------------------------------------- 3. narration
def narrate(scenes):
    ps = ["Add-Type -AssemblyName System.Speech",
          "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer",
          "try { $s.SelectVoice('Microsoft Zira Desktop') } catch {}", "$s.Rate = 0",
          "$fmt = New-Object System.Speech.AudioFormat.SpeechAudioFormatInfo(44100, [System.Speech.AudioFormat.AudioBitsPerSample]::Sixteen, [System.Speech.AudioFormat.AudioChannel]::Mono)"]
    for i, sc in enumerate(scenes):
        txt = WORK / f"say_{i:02d}.txt"
        txt.write_text(sc["say"], encoding="utf-8")
        ps += [f"$s.SetOutputToWaveFile('{WORK / f'say_{i:02d}.wav'}', $fmt)", f"$s.Speak([IO.File]::ReadAllText('{txt}'))"]
    ps.append("$s.Dispose()")
    (WORK / "say.ps1").write_text("\n".join(ps), encoding="utf-8-sig")
    subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(WORK / "say.ps1")], check=True)
    clips = []
    for i in range(len(scenes)):
        with wave.open(str(WORK / f"say_{i:02d}.wav")) as w:
            clips.append(np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16))
    return clips, 44100


# ----------------------------------------------------------------------------- 4. frames
def overlay(label: str, caption: str) -> Image.Image:
    o = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(o)
    d.rectangle([0, H - CAP_H, W, H], fill=(17, 17, 17, 228))
    words, lines, cur = caption.split(), [], ""
    for w_ in words:
        t = (cur + " " + w_).strip()
        if d.textlength(t, font=F_CAP) > W - 380 and cur:
            lines.append(cur); cur = w_
        else:
            cur = t
    lines.append(cur)
    y = H - CAP_H / 2 - len(lines) * 21
    for ln in lines[:2]:
        d.text((56, y), ln, font=F_CAP, fill=(255, 255, 255, 255)); y += 42
    d.text((W - 56, H - CAP_H / 2), "VORTEX", font=F_MARK, fill=(150, 150, 150, 255), anchor="rm")
    if label:
        tw = d.textlength(label.upper(), font=F_LABEL)
        d.rounded_rectangle([40, 34, 40 + tw + 44, 34 + 50], radius=10, fill=(17, 17, 17, 235))
        d.text((62, 59), label.upper(), font=F_LABEL, fill=(255, 255, 255, 255), anchor="lm")
    return o


def ease(t):
    return 0.5 - 0.5 * np.cos(np.pi * min(max(t, 0.0), 1.0))


def scene_frames(sc, img: Image.Image, marks, dur):
    n = int(round(dur * FPS))
    ov = overlay(sc["label"], sc["caption"])
    if img.height <= H + 4:
        base = img.convert("RGB").resize((W, H)) if img.size != (W, H) else img.convert("RGB")
        for k in range(n):                                  # slow 3 % zoom
            z = 1 + 0.03 * ease(k / max(n - 1, 1))
            cw, ch = W / z, H / z
            x0, y0 = (W - cw) / 2, (H - ch) / 2
            f = base.crop((int(x0), int(y0), int(x0 + cw), int(y0 + ch))).resize((W, H), Image.BILINEAR).convert("RGBA")
            yield Image.alpha_composite(f, ov).convert("RGB")
        return
    tag, key = sc.get("sel") or ("top", None)
    ys = sorted(m["y"] * DSF for m in marks)
    if tag == "top":
        start = 0.0
        nxt = next((m["y"] * DSF for m in marks if m["tag"] == "h2"), img.height) if sc.get("sel") else img.height
    else:
        m = next(m for m in marks if m["tag"] == tag and (m["t"].startswith(key) if tag == "h2" else key in m["t"]))
        start = max(m["y"] * DSF - 34, 0)
        nxt = next((y for y in ys if y > m["y"] * DSF + 40), img.height)
    view = H - CAP_H + 10
    end = min(max(start, nxt - view + 30), img.height - H, start + 140 * DSF * dur)   # no faster than ~140 css px/s
    end = max(end, start)
    for k in range(n):
        t = k / max(n - 1, 1)
        y = start + (end - start) * ease((t - 0.12) / 0.76)
        f = img.crop((0, int(y), W, int(y) + H)).convert("RGBA")
        yield Image.alpha_composite(f, ov).convert("RGB")


def main():
    stdout, secs = run_engine()
    marks = screenshots(terminal_html(stdout, secs))
    clips, sr = narrate(SCENES)
    imgs = {}
    for name in ["title", "terminal", "report", "eval"]:
        im = Image.open(WORK / f"{name}.png")
        imgs[name] = im.convert("RGB") if im.width == W else im.convert("RGB").resize((W, int(im.height * W / im.width)))
    imgs["t2_2"] = Image.open(WORK / "t2_2.png").convert("RGB")
    imgs["t2_5"] = Image.open(WORK / "t2_5.png").convert("RGB")
    imgs["op_1"] = Image.open(WORK / "op_1.png").convert("RGB")

    durs = [max(5.0, len(c) / sr + 1.3) for c in clips]
    total = sum(durs)
    audio = np.zeros(int((total + 1) * sr), dtype=np.int16)
    t = 0.0
    for c, d in zip(clips, durs):
        a = int((t + 0.45) * sr); audio[a:a + len(c)] = c[: len(audio) - a]; t += d
    with wave.open(str(WORK / "narration.wav"), "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(sr); w.writeframes(audio.tobytes())

    OUT.mkdir(parents=True, exist_ok=True)
    mp4 = OUT / "Vortex_CR-26-047_Demo.mp4"
    ff = subprocess.Popen([imageio_ffmpeg.get_ffmpeg_exe(), "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24",
                           "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-", "-i", str(WORK / "narration.wav"),
                           "-c:v", "libx264", "-preset", "medium", "-crf", "21", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
                           "-c:a", "aac", "-b:a", "128k", "-shortest", str(mp4)], stdin=subprocess.PIPE)
    prev, nf = None, int(FADE * FPS)
    for i, (sc, d) in enumerate(zip(SCENES, durs)):
        src = sc["src"]
        for k, fr in enumerate(scene_frames(sc, imgs[src], marks.get(src, []), d)):
            if prev is not None and k < nf:
                fr = Image.blend(prev, fr, (k + 1) / (nf + 1))
            ff.stdin.write(fr.tobytes())
            last = fr
            if i == 0 and k == int(1.5 * FPS):
                fr.save(OUT / "thumbnail.png")
        prev = last
        print(f"scene {i + 1:2d}/{len(SCENES)} {sc['label'] or sc['src']:<24s} {d:5.1f}s", flush=True)
    ff.stdin.close(); ff.wait()

    rows, t = [], 0.0
    for i, (sc, d) in enumerate(zip(SCENES, durs), 1):
        rows.append(f"| {i} | {int(t // 60)}:{int(t % 60):02d} | {sc['label'] or ('Title' if i == 1 else 'Close')} | {sc['caption']} | {sc['say']} |")
        t += d
    (OUT / "DEMO_SCRIPT.md").write_text(
        "# Demo video: script and shot list\n\n"
        f"`Vortex_CR-26-047_Demo.mp4`, 1920×1080, {int(total // 60)} min {int(total % 60)} s. Built by `docs/tier3/build/make_demo_video.py` from a real run of the engine "
        f"on the supplied evidence (the terminal scene shows that run's actual console output; omitted lines are marked `…`). "
        "Every report scene is a screenshot of the generated `out/real/report.html`.\n\n"
        "The narration is Windows' built-in text-to-speech voice. To re-record it in your own voice, read the narration column below; "
        "each row starts at the time shown.\n\n"
        "| # | Starts | Scene | On-screen caption | Narration |\n|---|---|---|---|---|\n" + "\n".join(rows) + "\n\n"
        "## Recording it live instead\n\n"
        "1. `pip install -r requirements.txt`\n2. `.\\run_demo.ps1` (prints the score and the four briefs, opens the report)\n"
        "3. Scroll the report in the order of the scenes above, then open `eval/evaluation.html` (run `.\\run_demo.ps1 -Full` first to regenerate it).\n",
        encoding="utf-8")
    print(f"wrote {mp4} ({mp4.stat().st_size / 1e6:.1f} MB, {total:.0f} s) and DEMO_SCRIPT.md")


if __name__ == "__main__":
    main()
