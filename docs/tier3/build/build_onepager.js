// Team Vortex — Tier 3 one-page final project slide (CR-26-047).
// Build (uses the Tier 2 node_modules):  NODE_PATH=../../tier2/build/node_modules node build_onepager.js
const path = require("path");
const pptxgen = require("pptxgenjs");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa6");
const SKILL = "C:/Users/Admin/.claude/skills/synced/9bbc82a6-b847-4bb7-bd48-4df9f30d5bc9_7f8b130f-2317-42b1-8c76-ad582e0ab201/pptx";
const { applyTheme } = require(SKILL + "/scripts/apply_theme.js");

const OUT = path.resolve(__dirname, "..", "Vortex_CR-26-047_Final_OnePager.pptx");
const THEME = {
  name: "Vortex Mono", headFontFace: "Calibri", bodyFontFace: "Calibri",
  colors: { dk1: "111111", lt1: "FFFFFF", dk2: "333333", lt2: "F2F2F2", accent1: "111111", accent2: "6B6B6B",
            accent3: "A6A6A6", accent4: "D9D9D9", accent5: "404040", accent6: "8C8C8C", hlink: "111111", folHlink: "555555" },
};
const K = { ink: "111111", dark: "333333", mid: "6B6B6B", soft: "8C8C8C", line: "D9D9D9", panel: "F2F2F2", white: "FFFFFF", pale: "BFBFBF" };
const MONO = "Consolas";
const L = 0.55;

async function icon(Comp, color = "#FFFFFF") {
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(Comp, { color, size: 256 }));
  return "image/png;base64," + (await sharp(Buffer.from(svg)).png().toBuffer()).toString("base64");
}
async function spiral(color) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="4.5 4.5 15 15" width="256" height="256"><path d="M12 12a1 1 0 0 1 2 0a2 2 0 0 1-4 0a3 3 0 0 1 6 0a4 4 0 0 1-8 0a5 5 0 0 1 10 0a6 6 0 0 1-12 0" fill="none" stroke="${color}" stroke-width="1.35" stroke-linecap="round"/></svg>`;
  return "image/png;base64," + (await sharp(Buffer.from(svg)).png().toBuffer()).toString("base64");
}

(async () => {
  const pres = new pptxgen();
  pres.layout = "LAYOUT_WIDE";
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
  pres.title = "Double-Entry Defense — Team Vortex, CR-26-047 final project";
  pres.author = "Team Vortex";
  pres.company = "Team Vortex";
  pres.subject = "CRIMEATHON'26 Tier 3 one-page final project";

  const I = {
    eye: await icon(fa.FaEye), scale: await icon(fa.FaScaleBalanced), grammar: await icon(fa.FaDiagramProject),
    shield: await icon(fa.FaShieldHalved), claim: await icon(fa.FaFileCircleCheck), lock: await icon(fa.FaLock),
    phone: await icon(fa.FaPhoneSlash), users: await icon(fa.FaUsers), arrow: await icon(fa.FaChevronRight, "#8C8C8C"),
    github: await icon(fa.FaGithub, "#111111"),
  };
  const LOGO = await spiral("#111111");

  pres.defineSlideMaster({ title: "VX_ONEPAGE", background: { color: K.white }, objects: [
    { placeholder: { options: { name: "title", type: "title", x: L, y: 0.86, w: 8.4, h: 0.62, fontSize: 34, bold: true, color: K.ink, margin: 0, valign: "top", align: "left" }, text: "" } },
    { placeholder: { options: { name: "body", type: "body", x: L, y: 1.46, w: 8.4, h: 0.4, fontSize: 15, color: K.dark, margin: 0, valign: "top", align: "left" }, text: "" } },
  ] });

  const T = (s, text, o) => s.addText(text, Object.assign({ isTextBox: true, margin: 0, fontFace: "Calibri", color: K.ink, valign: "top" }, o));
  const box = (s, x, y, w, h, fill, name, line) => s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x, y, w, h, rectRadius: 0.07, fill: { color: fill }, line: line ? { color: line, width: 1 } : { color: fill, width: 0 }, objectName: name });
  const disc = (s, x, y, d, fill, img, name) => {
    s.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { color: fill, width: 0 }, objectName: name });
    s.addImage({ data: img, x: x + d * 0.24, y: y + d * 0.24, w: d * 0.52, h: d * 0.52, altText: name });
  };
  const label = (s, text, x, y, w, dark) => T(s, text, { x, y, w, h: 0.26, fontSize: 11, bold: true, color: dark ? K.pale : K.mid, charSpacing: 2 });

  const s = pres.addSlide({ masterName: "VX_ONEPAGE" });

  // header -----------------------------------------------------------------
  s.addImage({ data: LOGO, x: L, y: 0.3, w: 0.42, h: 0.42, altText: "Vortex spiral mark" });
  T(s, "VORTEX", { x: L + 0.55, y: 0.3, w: 2.2, h: 0.42, fontSize: 17, bold: true, charSpacing: 7, valign: "middle" });
  T(s, "CRIMEATHON’26 · Tier 3 · Final project · Case CR-26-047 · Defense", { x: 3.2, y: 0.3, w: 5.75, h: 0.42, fontSize: 12, color: K.mid, align: "right", valign: "middle" });
  s.addText("Double-Entry Defense", { placeholder: "title" });
  s.addText("Catching a trusted integration that changes where we pay, before the money moves.", { placeholder: "body" });

  // problem + objectives -----------------------------------------------------
  const top = 2.05;
  label(s, "SELECTED PROBLEM", L, top, 4.6);
  T(s, [
    { text: "A third-party integration can change where money goes, and nothing cross-checks that change. ", options: { bold: true } },
    { text: "TallyBridge’s keys were used from home broadband, then from a vendor build host inside our private link. On 3 Sep, V-0412’s bank account was changed with no approval, 5 days before the run." },
  ], { x: L, y: top + 0.3, w: 4.6, h: 1.25, fontSize: 12, color: K.dark, paraSpaceAfter: 2 });
  T(s, "E18 req-5f61b0de8 → E19 chg-8b9888c39b", { x: L, y: top + 1.42, w: 4.6, h: 0.24, fontSize: 10, color: K.mid, fontFace: MONO });

  const ox = 5.45, ow = 3.5;
  label(s, "OBJECTIVES", ox, top, ow);
  const objs = ["Hold a tampered payee before the run", "Catch a misused key, even inside the link", "No alert flood for a one-person team", "Every finding cites the exact records"];
  objs.forEach((o, i) => {
    const y = top + 0.32 + i * 0.34;
    s.addShape(pres.shapes.OVAL, { x: ox, y: y + 0.02, w: 0.24, h: 0.24, fill: { color: K.ink }, line: { color: K.ink, width: 0 }, objectName: `objective ${i + 1}` });
    T(s, String(i + 1), { x: ox, y: y + 0.02, w: 0.24, h: 0.24, fontSize: 10, bold: true, color: K.white, align: "center", valign: "middle" });
    T(s, o, { x: ox + 0.34, y, w: ow - 0.34, h: 0.3, fontSize: 12, color: K.dark, valign: "middle" });
  });

  // architecture ---------------------------------------------------------------
  const ay = 3.8;
  label(s, "ARCHITECTURE", L, ay, 6);
  const stages = [
    ["Ingest", "E01–E20 logs + context.json facts"],
    ["Normalise", "IST→UTC, clock offsets, one name per actor"],
    ["Check", "4 invariants + exports, storage, governance"],
    ["Triage", "time to money, threads, alert budget"],
    ["Act", "hold list, 4 briefs, report, records"],
  ];
  const bw = 1.53, gap = 0.19;
  stages.forEach(([h, t], i) => {
    const x = L + i * (bw + gap), dark = i === 2;
    box(s, x, ay + 0.3, bw, 0.88, dark ? K.ink : K.panel, `stage ${h}`);
    T(s, h, { x: x + 0.12, y: ay + 0.38, w: bw - 0.24, h: 0.28, fontSize: 13, bold: true, color: dark ? K.white : K.ink });
    T(s, t, { x: x + 0.12, y: ay + 0.66, w: bw - 0.2, h: 0.55, fontSize: 10, color: dark ? K.line : K.dark });
    if (i < stages.length - 1) s.addImage({ data: I.arrow, x: x + bw + 0.02, y: ay + 0.68, w: 0.15, h: 0.18, altText: "then" });
  });

  // key features -----------------------------------------------------------------
  const fy = 5.12;
  label(s, "KEY FEATURES", L, fy, 6);
  const feats = [
    [I.eye, "Witness check", "API call must match the network log"],
    [I.scale, "Double-entry ledger", "every read paired with its write"],
    [I.grammar, "Sync grammar", "learns the sync’s normal requests"],
    [I.shield, "Payment-run firewall", "HOLD / VERIFY each bank change"],
    [I.claim, "Vendor-claim checker", "tests each vendor claim"],
    [I.lock, "Least-privilege replay", "learns what each key needs"],
    [I.phone, "Call-back guard", "flags rewritten numbers"],
    [I.users, "Four briefs", "GM, Finance, Legal, IT"],
  ];
  const cw = 2.12, ch = 0.7;
  feats.forEach(([img, h, t], i) => {
    const x = L + (i % 4) * (cw + 0.0), y = fy + 0.32 + Math.floor(i / 4) * (ch + 0.08);
    disc(s, x, y + 0.04, 0.44, K.ink, img, `feature ${h}`);
    T(s, h, { x: x + 0.53, y: y + 0.01, w: cw - 0.58, h: 0.28, fontSize: 12, bold: true });
    T(s, t, { x: x + 0.53, y: y + 0.29, w: cw - 0.58, h: 0.4, fontSize: 10, color: K.dark });
  });

  // results panel ------------------------------------------------------------------
  const px = 9.25, pw = 3.55, py = 0.3, ph = 6.55;
  box(s, px, py, pw, ph, K.ink, "results panel");
  const ix = px + 0.3, iw = pw - 0.6;
  T(s, "RESULTS · SUPPLIED EVIDENCE", { x: ix, y: py + 0.28, w: iw, h: 0.26, fontSize: 11, bold: true, color: K.pale, charSpacing: 1 });
  const big = (y, n, cap, sub) => {
    T(s, n, { x: ix, y, w: iw, h: 0.62, fontSize: 40, bold: true, color: K.white });
    T(s, cap, { x: ix, y: y + 0.62, w: iw, h: 0.28, fontSize: 12, bold: true, color: K.white });
    if (sub) T(s, sub, { x: ix, y: y + 0.89, w: iw, h: 0.26, fontSize: 10.5, color: K.pale });
  };
  big(py + 0.62, "181 / 181", "attacker records flagged", "all 9 stages, joined into 1 incident");
  big(py + 1.85, "0", "false alarms", "obvious per-log rules: 29,961");
  big(py + 3.08, "HOLD", "V-0412 before the 8 Sep run", "4 more vendors to verify");
  s.addShape(pres.shapes.LINE, { x: ix, y: py + 4.38, w: iw, h: 0, line: { color: K.dark, width: 1 }, objectName: "divider" });
  const minis = [["6 / 6", "vendor claims contradicted"], ["133 / 133", "attacker requests refused by learned policy"],
                 ["18", "synthetic worlds, precision 1.00"], ["8 s", "per run on a laptop"]];
  minis.forEach(([n, t], i) => {
    const x = ix + (i % 2) * (iw / 2), y = py + 4.52 + Math.floor(i / 2) * 0.82;
    T(s, n, { x, y, w: iw / 2 - 0.1, h: 0.36, fontSize: 20, bold: true, color: K.white });
    T(s, t, { x, y: y + 0.36, w: iw / 2 - 0.12, h: 0.44, fontSize: 9.5, color: K.pale });
  });
  T(s, "Scored against our own labels after one calibration pass. Hardest variant (inside_worker): recall 0.44–0.56.",
    { x: ix, y: py + 6.12, w: iw, h: 0.38, fontSize: 8.5, color: K.soft, italic: true });

  // footer --------------------------------------------------------------------------
  s.addImage({ data: I.github, x: L, y: 6.98, w: 0.22, h: 0.22, altText: "GitHub" });
  T(s, [{ text: "github.com/kanishk2707/crimeathon", options: { bold: true, hyperlink: { url: "https://github.com/kanishk2707/crimeathon" } } },
        { text: "   ·   Python 3.10+, pandas, numpy   ·   python -m doubleentry analyze evidence", options: { color: K.mid } }],
    { x: L + 0.3, y: 6.96, w: 8.4, h: 0.26, fontSize: 11, valign: "middle" });
  T(s, "Team Vortex · CRIMEATHON’26", { x: px, y: 6.96, w: pw, h: 0.26, fontSize: 11, color: K.soft, align: "right", valign: "middle" });

  s.addNotes("One slide, top to bottom: the problem (a vendor's trusted key changed where we pay V-0412, with no approval, five days before a run), four objectives, the five-stage pipeline, the eight key features, and on the right the results on the supplied evidence: 181 of 181 attacker records with zero false alarms, V-0412 held. Scores use our own labels after one calibration pass; the code, proof pack and demo are in the GitHub repository.");

  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log("wrote " + OUT);
})();
