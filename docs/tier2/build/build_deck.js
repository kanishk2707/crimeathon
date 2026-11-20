// Team Vortex — Tier 2 concept deck (CR-26-047). Build: node build_deck.js
const path = require("path");
const pptxgen = require("pptxgenjs");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa6");
const SKILL = "C:/Users/Admin/.claude/skills/synced/9bbc82a6-b847-4bb7-bd48-4df9f30d5bc9_7f8b130f-2317-42b1-8c76-ad582e0ab201/pptx";
const { applyTheme } = require(SKILL + "/scripts/apply_theme.js");

const OUT = path.resolve(__dirname, "..", "Vortex_CR-26-047_Tier2_Concept.pptx");
const THEME = {
  name: "Vortex Mono", headFontFace: "Calibri", bodyFontFace: "Calibri",
  colors: { dk1: "111111", lt1: "FFFFFF", dk2: "333333", lt2: "F2F2F2", accent1: "111111", accent2: "6B6B6B",
            accent3: "A6A6A6", accent4: "D9D9D9", accent5: "404040", accent6: "8C8C8C", hlink: "111111", folHlink: "555555" },
};
const K = { ink: "111111", dark: "333333", mid: "6B6B6B", soft: "8C8C8C", line: "D9D9D9", panel: "F2F2F2", white: "FFFFFF", pale: "BFBFBF" };
const MONO = "Consolas";
const W = 13.333, L = 0.6, CW = 12.13;

async function icon(Comp, color = "#FFFFFF") {
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(Comp || fa.FaCircle, { color, size: 256 }));
  const buf = await sharp(Buffer.from(svg)).png().toBuffer();
  return "image/png;base64," + buf.toString("base64");
}
async function spiral(color) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="4.5 4.5 15 15" width="256" height="256"><path d="M12 12a1 1 0 0 1 2 0a2 2 0 0 1-4 0a3 3 0 0 1 6 0a4 4 0 0 1-8 0a5 5 0 0 1 10 0a6 6 0 0 1-12 0" fill="none" stroke="${color}" stroke-width="1.35" stroke-linecap="round"/></svg>`;
  return "image/png;base64," + (await sharp(Buffer.from(svg)).png().toBuffer()).toString("base64");
}

(async () => {
  const pres = new pptxgen();
  pres.layout = "LAYOUT_WIDE";
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
  pres.title = "Double-Entry Defense — Team Vortex, CR-26-047";
  pres.author = "Team Vortex";
  pres.company = "Team Vortex";
  pres.subject = "CRIMEATHON'26 Tier 2 technical concept";

  const I = {
    eye: await icon(fa.FaEye), scale: await icon(fa.FaScaleBalanced), link: await icon(fa.FaLink),
    shield: await icon(fa.FaShieldHalved), check: await icon(fa.FaCheck), claim: await icon(fa.FaFileCircleCheck),
    lock: await icon(fa.FaLock), phone: await icon(fa.FaPhoneSlash), users: await icon(fa.FaUsers),
    checkInk: await icon(fa.FaCheck, "#111111"),
  };
  const LOGO_W = await spiral("#FFFFFF");
  const LOGO_K = await spiral("#111111");
  const LOGO_DIM = await spiral("#2E2E2E");

  const footer = (dark) => ({ text: { text: "Team Vortex · CRIMEATHON’26 · Case CR-26-047", options: {
    x: L, y: 7.0, w: 8, h: 0.3, fontSize: 10, color: dark ? K.mid : K.soft, margin: 0, isTextBox: true } } });
  const sn = (dark) => ({ x: 12.23, y: 7.0, w: 0.5, h: 0.3, fontSize: 10, color: dark ? K.mid : K.soft, align: "right" });

  pres.defineSlideMaster({ title: "VX_TITLE", background: { color: K.ink }, objects: [
    { placeholder: { options: { name: "title", type: "title", x: L, y: 2.15, w: 11.2, h: 1.1, fontSize: 54, bold: true, color: K.white, margin: 0, valign: "top", align: "left" }, text: "" } },
    { placeholder: { options: { name: "body", type: "body", x: L, y: 3.3, w: 8.4, h: 1.0, fontSize: 22, color: K.line, margin: 0, valign: "top", align: "left" }, text: "" } },
  ] });
  pres.defineSlideMaster({ title: "VX_CONTENT", background: { color: K.white }, objects: [
    { placeholder: { options: { name: "kicker", type: "body", x: L, y: 0.4, w: 10, h: 0.3, fontSize: 12, bold: true, color: K.mid, charSpacing: 2, margin: 0 }, text: "" } },
    { placeholder: { options: { name: "title", type: "title", x: L, y: 0.68, w: CW, h: 0.72, fontSize: 34, bold: true, color: K.ink, margin: 0, valign: "top", align: "left" }, text: "" } },
    footer(false),
  ], slideNumber: sn(false) });
  pres.defineSlideMaster({ title: "VX_DARK", background: { color: K.ink }, objects: [
    { placeholder: { options: { name: "kicker", type: "body", x: L, y: 0.4, w: 10, h: 0.3, fontSize: 12, bold: true, color: K.soft, charSpacing: 2, margin: 0 }, text: "" } },
    { placeholder: { options: { name: "title", type: "title", x: L, y: 0.68, w: CW, h: 0.72, fontSize: 34, bold: true, color: K.white, margin: 0, valign: "top", align: "left" }, text: "" } },
    footer(true),
  ], slideNumber: sn(true) });

  // helpers ---------------------------------------------------------------
  const T = (s, text, o) => s.addText(text, Object.assign({ isTextBox: true, margin: 0, fontFace: "Calibri", color: K.ink, valign: "top" }, o));
  const box = (s, x, y, w, h, fill, name, line) => s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x, y, w, h, rectRadius: 0.08, fill: { color: fill }, line: line ? { color: line, width: 1 } : { color: fill, width: 0 }, objectName: name });
  const disc = (s, x, y, d, fill, img, name) => {
    s.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { color: fill, width: 0 }, objectName: name });
    if (img) s.addImage({ data: img, x: x + d * 0.24, y: y + d * 0.24, w: d * 0.52, h: d * 0.52, altText: name });
  };
  const num = (s, x, y, d, n, fill, ink, size) => {
    s.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { color: fill, width: 0 }, objectName: `num ${n}` });
    T(s, String(n), { x, y, w: d, h: d, fontSize: size || 13, bold: true, color: ink, align: "center", valign: "middle" });
  };
  const head = (s, kicker, title) => { s.addText(kicker, { placeholder: "kicker" }); s.addText(title, { placeholder: "title" }); };

  // 1 — title -------------------------------------------------------------
  pres.addSection({ title: "The case" });
  let s = pres.addSlide({ masterName: "VX_TITLE", sectionTitle: "The case" });
  s.addImage({ data: LOGO_DIM, x: 9.35, y: 1.55, w: 3.4, h: 3.4, altText: "Vortex spiral watermark" });
  s.addImage({ data: LOGO_W, x: L, y: 0.55, w: 0.6, h: 0.6, altText: "Vortex spiral mark" });
  T(s, "VORTEX", { x: 1.35, y: 0.55, w: 4, h: 0.6, fontSize: 20, bold: true, color: K.white, charSpacing: 8, valign: "middle" });
  T(s, "CRIMEATHON’26 · Tier 2 · Technical concept", { x: 7.2, y: 0.62, w: 5.53, h: 0.45, fontSize: 13, color: K.pale, align: "right", valign: "middle" });
  s.addText("Double-Entry Defense", { placeholder: "title" });
  s.addText("Catching a trusted integration that changes where we pay — before the money moves.", { placeholder: "body" });
  const meta = [["CASE", "CR-26-047 · Harbor & Finch Freight"], ["APPROACH", "Defense, locked at Tier 1"], ["BUILT", "Python engine, runs on the released evidence"]];
  meta.forEach(([k, v], i) => {
    const x = L + i * 4.1;
    T(s, k, { x, y: 5.55, w: 3.8, h: 0.3, fontSize: 11, bold: true, color: K.soft, charSpacing: 2 });
    T(s, v, { x, y: 5.88, w: 3.9, h: 0.6, fontSize: 16, color: K.white });
  });
  s.addNotes("We are Team Vortex, Defense track. One sentence: a trusted vendor key was used to change where Harbor & Finch pays a supplier, five days before a payment run, and every log was there but nothing joined them. Double-Entry Defense joins them, holds the payment, and tells each person what to do.");

  // 2 — problem + evidence --------------------------------------------------
  s = pres.addSlide({ masterName: "VX_CONTENT", sectionTitle: "The case" });
  head(s, "01 · THE PROBLEM AND THE EVIDENCE", "A trusted key changed where we pay a vendor");
  T(s, [{ text: "The problem we chose: ", options: { bold: true } },
        { text: "a third-party integration can change where money goes, and nothing cross-checks that change." }],
    { x: L, y: 1.55, w: CW, h: 0.5, fontSize: 16, color: K.dark });
  s.addShape(pres.shapes.LINE, { x: 0.72, y: 2.52, w: 11.95, h: 0, line: { color: K.ink, width: 2 }, objectName: "timeline rail" });
  const tl = [
    ["9 Aug", "Probe from off the link", "Key used from a home IP, posing as retired client 3.4.1", "E01 req-c28d87e49d"],
    ["11 Aug", "Secret hunt in tickets", "Reads TKT-48213, which holds key bvk-7f3a; 10 exports deleted", "E02 evt-20d941e9bc"],
    ["12 Aug", "Vendor list exported", "Two exports: 9,840 + 9,835 records", "E01 req-c35c2ccaff"],
    ["14–16 Aug", "Stolen key used", "Reads vendor-bank-details-2026.xlsx from BlueVault", "E05 bv-edb0081dad"],
    ["15 Aug", "Admin password tried", "Password accepted; only MFA stops the sign-in", "E03 sso-562f41d2b5"],
    ["17–19 Aug", "Vendor build host", "tb-build-02, inside our link, exports 4,210 payments", "E15 flw-67f0a99b5c"],
    ["3 Sep", "Payee bank changed", "V-0412 ****4417 → ****9083, no approval", "E19 chg-8b9888c39b"],
  ];
  tl.forEach(([d, h, t, id], i) => {
    const x = L + i * 1.735, last = i === tl.length - 1;
    if (last) box(s, x - 0.1, 2.72, 1.82, 2.5, K.ink, "fraud card");
    s.addShape(pres.shapes.OVAL, { x: x + 0.02, y: 2.4, w: 0.24, h: 0.24, fill: { color: last ? K.ink : K.white }, line: { color: K.ink, width: 2 }, objectName: `node ${d}` });
    const ink = last ? K.white : K.ink;
    T(s, d, { x, y: 2.82, w: 1.62, h: 0.32, fontSize: 15, bold: true, color: ink });
    T(s, h, { x, y: 3.14, w: 1.62, h: 0.55, fontSize: 13, bold: true, color: ink });
    T(s, t, { x, y: 3.7, w: 1.62, h: 0.95, fontSize: 12, color: last ? K.line : K.dark });
    T(s, id, { x, y: 4.68, w: 1.62, h: 0.42, fontSize: 10, color: last ? K.pale : K.mid, fontFace: MONO });
  });
  T(s, "WHY IT WASN’T CAUGHT", { x: L, y: 5.45, w: 6, h: 0.28, fontSize: 11, bold: true, color: K.mid, charSpacing: 2 });
  [["Keys never expire, no IP limit", "E04 register"], ["Audit findings 2–7 still open", "E11 internal audit, Sep 2025"],
   ["No alert on exports or deletes", "E10 policy §4.1"], ["Logs kept, nobody reads them", "Case file §3"]].forEach(([a, b], i) => {
    const x = L + i * 3.08;
    box(s, x, 5.8, 2.9, 0.95, K.panel, `gap ${i + 1}`);
    T(s, a, { x: x + 0.2, y: 5.92, w: 2.55, h: 0.4, fontSize: 14, bold: true });
    T(s, b, { x: x + 0.2, y: 6.36, w: 2.55, h: 0.3, fontSize: 11, color: K.mid });
  });
  s.addNotes("Read the timeline left to right. Each card names one exact record, so any judge can open the file and check. The same TallyBridge keys acted from home broadband in early August, then from the vendor's own build server inside our private link, and on 3 September changed V-0412's bank account with no approval. The bottom row is why nobody noticed: the controls existed on paper only.");

  // 3 — alternatives --------------------------------------------------------
  s = pres.addSlide({ masterName: "VX_CONTENT", sectionTitle: "The case" });
  head(s, "02 · OTHER EXPLANATIONS", "Six other explanations, tested against the records");
  const hdr = (t) => ({ text: t, options: { bold: true, color: K.white, fill: { color: K.ink }, fontSize: 12 } });
  const verdict = (v, why) => ({ text: [{ text: v, options: { bold: true, breakLine: true } }, { text: why, options: { color: K.mid, fontSize: 11 } }] });
  const rows3 = [
    [hdr("Explanation"), hdr("What the records show"), hdr("Verdict")],
    ["Insider: former AP clerk Rohan Menon", "One sign-in after leaving, two minutes after IT reported it (E03 sso-bb8ab61e08, E13); no activity in any other log", verdict("Ruled out", "leaver-access gap, not the actor")],
    ["The vendor’s account: outsider only, 11–12 Aug, metadata only (E16)", "Build host on our private link (E15); activity until 6 Sep (E18); finance files read (E05); host missing from their indicator list (E17)", verdict("Set aside", "contradicted 6 of 6 times")],
    ["A legitimate vendor change", "Contact sync announced (E16 §7, E20-C 3.6.0); payment exports and bank reads or edits announced nowhere", verdict("Partly", "contact sync only")],
    ["“That address is a staff member”", "198.18.7.0/24 is dynamic home broadband (E20-G); staff used .24 and .58 on other days", verdict("Ruled out", "we attribute by credential")],
    ["Finance insider: the V-0233 change", "Approval APR-1182 out of sequence (numbers had reached APR-1237), 3 days before a run; usual device and address", verdict("Verify", "not proven")],
    ["Ordinary look-alikes", "Colin’s travel, Sunita’s Tuesday exports, Farah’s 22 Jul audit export, the 31 Jul bulk import, 429 retries", verdict("Ordinary", "never alerted")],
  ];
  s.addTable(rows3, { x: L, y: 1.6, w: CW, colW: [2.85, 6.78, 2.5], rowH: [0.4, 0.7, 0.7, 0.7, 0.7, 0.7, 0.7], fontSize: 13, fontFace: "Calibri",
    color: K.ink, valign: "middle", margin: [0.05, 0.12, 0.05, 0.12],
    border: [{ type: "none" }, { type: "none" }, { pt: 0.75, color: K.line }, { type: "none" }], objectName: "alternatives table" });
    T(s, "Our rule: attribute by credential and behaviour, never by an address alone.", { x: L, y: 6.4, w: CW, h: 0.35, fontSize: 14, italic: true, color: K.dark });
  s.addNotes("Every alternative was tested against records, not opinion. The insider theory fails because Rohan's only post-exit sign-in is IT checking the report. The vendor's own story fails on all six claims we can test. The V-0233 change we deliberately leave as 'verify' — suspicious, not proven. Ordinary events like Colin's travel never raised an alert.");

  // 4 — solution ----------------------------------------------------------
  pres.addSection({ title: "The solution" });
  s = pres.addSlide({ masterName: "VX_CONTENT", sectionTitle: "The solution" });
  head(s, "03 · THE SOLUTION AND ITS OBJECTIVES", "Check what must be true, not what looks odd");
  T(s, [{ text: "Double-Entry Defense ", options: { bold: true } },
        { text: "joins the records of five systems and tests four business invariants. An attacker can borrow an address, a client name or an hour — not the invariants." }],
    { x: L, y: 1.55, w: CW, h: 0.7, fontSize: 16, color: K.dark });
  const inv = [
    [I.eye, "Witness", "A link identity acts only from a known host, confirmed by the network flow log.", "the build host inside our link"],
    [I.scale, "Ledger + grammar", "Every record the sync reads must reach the partner system. Anything else lands in a suspense account.", "probes, exports, bank reads"],
    [I.link, "Chain", "A key read out of a ticket and then used from new addresses is one incident, not two.", "TKT-48213 → BlueVault theft"],
    [I.shield, "Payment-run firewall", "Bank details change only with a person’s approval. A hold list goes out before every run.", "V-0412 before 8 Sep"],
  ];
  inv.forEach(([img, name, rule, catches], i) => {
    const x = L + i * 3.11;
    box(s, x, 2.45, 2.85, 3.0, K.panel, `card ${name}`);
    disc(s, x + 0.25, 2.68, 0.62, K.ink, img, `${name} icon`);
    T(s, name, { x: x + 0.25, y: 3.45, w: 2.4, h: 0.4, fontSize: 18, bold: true });
    T(s, rule, { x: x + 0.25, y: 3.88, w: 2.4, h: 1.0, fontSize: 13, color: K.dark });
    T(s, [{ text: "Catches: ", options: { bold: true } }, { text: catches }], { x: x + 0.25, y: 4.92, w: 2.4, h: 0.45, fontSize: 12, color: K.ink });
  });
  T(s, "OBJECTIVES", { x: L, y: 5.68, w: 4, h: 0.28, fontSize: 11, bold: true, color: K.mid, charSpacing: 2 });
  ["Catch it before money moves", "Hold the payment, not just raise an alert", "Cite the exact record behind every finding", "Stay quiet on ordinary work"].forEach((o, i) => {
    const x = L + i * 3.11;
    disc(s, x, 6.04, 0.34, K.ink, I.check, `objective ${i + 1}`);
    T(s, o, { x: x + 0.45, y: 5.98, w: 2.45, h: 0.6, fontSize: 14, valign: "middle" });
  });
  s.addNotes("The obvious tools look for things that look odd. Our attacker looked normal: the right key, the right client name, inside the sync window. So we test what must be true instead. The four invariants each caught a different stage of this case, and the objectives are what a small finance company actually needs: stop the payment, cite the evidence, and do not drown one security admin in alerts.");

  // 5 — architecture --------------------------------------------------------
  s = pres.addSlide({ masterName: "VX_CONTENT", sectionTitle: "The solution" });
  head(s, "04 · ARCHITECTURE AND WORKFLOW", "From raw logs to a hold list in one pass");
  const stages = [
    ["1  INGEST", ["LedgerOne API · E01, E18", "HelpDeskr audit · E02", "Sign-ins · E03", "BlueVault · E05", "Link flows · E15", "Vendor changes · E19", "Registers · E04, E14, E17", "context.json: facts typed from documents"]],
    ["2  NORMALISE", ["Format-tolerant loaders (dd/mm dates, user: and key: prefixes)", "Clock solver: aligns unsynced logs by cross-correlation", "Identity resolver: one actor, many names"]],
    ["3  CHECK", ["Witness", "Ledger + grammar", "Ticket-to-key chain", "Payment-run firewall", "Plus: exports, billing, storage, MFA, leavers, passport, IOC gap"]],
    ["4  TRIAGE", ["Weight by days to the next run (8th, 23rd)", "Join alerts into incident threads", "Daily alert budget for a one-person team"]],
    ["5  ACT", ["Hold list with last-known-good accounts", "Four briefs: GM, Finance, Legal, IT", "Vendor claims, checked", "Least-privilege policy", "Report + findings, every row cited"]],
  ];
  stages.forEach(([h, items], i) => {
    const x = L + i * 2.48;
    box(s, x, 1.6, 2.2, 0.45, K.ink, `stage ${i + 1} header`);
    T(s, h, { x: x + 0.15, y: 1.6, w: 2.0, h: 0.45, fontSize: 13, bold: true, color: K.white, valign: "middle", charSpacing: 1 });
    box(s, x, 2.15, 2.2, 3.4, K.panel, `stage ${i + 1} body`);
    T(s, items.map((t, j) => ({ text: t, options: { bullet: { indent: 12 }, breakLine: j < items.length - 1 } })),
      { x: x + 0.12, y: 2.3, w: 2.0, h: 3.15, fontSize: 13, color: K.dark, paraSpaceAfter: 6 });
    if (i < stages.length - 1) s.addShape(pres.shapes.CHEVRON, { x: x + 2.25, y: 3.68, w: 0.18, h: 0.34, fill: { color: K.mid }, line: { color: K.mid, width: 0 }, objectName: `flow ${i + 1}` });
  });
  T(s, "WORKFLOW", { x: L, y: 5.72, w: 4, h: 0.28, fontSize: 11, bold: true, color: K.mid, charSpacing: 2 });
  ["Runs nightly and before each payment run", "One incident thread to review, not 30,000 alerts", "Finance holds the listed vendors", "IT re-issues keys under the learned policy"].forEach((t, i) => {
    const x = L + i * 3.11;
    box(s, x, 6.05, 2.85, 0.62, K.white, `workflow ${i + 1}`, K.ink);
    T(s, t, { x: x + 0.15, y: 6.05, w: 2.6, h: 0.62, fontSize: 13, valign: "middle" });
    if (i < 3) s.addShape(pres.shapes.CHEVRON, { x: x + 2.92, y: 6.22, w: 0.16, h: 0.28, fill: { color: K.mid }, line: { color: K.mid, width: 0 }, objectName: `step ${i + 1}` });
  });
  s.addNotes("Five stages. Ingest takes the evidence files plus a small context file of facts we typed from the PDFs, each with its source. Normalise fixes the traps in the data: day-first dates, prefixed identities, and a BlueVault clock that was never synced. Check runs the four invariants plus supporting checks. Triage weights findings by how close the next payment run is and joins them into threads. Act writes outputs people can use directly.");

  // 6 — innovation ------------------------------------------------------------
  s = pres.addSlide({ masterName: "VX_CONTENT", sectionTitle: "The solution" });
  head(s, "05 · WHAT IS DIFFERENT", "Invariants an attacker cannot borrow");
  const c = (t, o) => ({ text: t, options: o || {} });
  const rows6 = [
    [hdr(""), hdr("Obvious: per-log rules"), hdr("Double-Entry Defense")],
    [c("Looks at", { bold: true }), "One log line at a time", "Records joined across five systems"],
    [c("Signal", { bold: true }), "New IP, off-hours, volume", "Witness, balance, grammar, approval"],
    [c("Attacker inside the link, real client name", { bold: true }), "Invisible", c("Caught three separate ways", { bold: true })],
    [c("Staff on dynamic home IPs", { bold: true }), "Thousands of alerts", "Ignored: attribution by credential"],
    [c("Learns normal from", { bold: true }), "Hand-tuned thresholds", "Witnessed sessions, by itself"],
    [c("Output", { bold: true }), "Alerts", c("A hold list with cited records", { bold: true })],
  ];
  s.addTable(rows6, { x: L, y: 1.6, w: 7.45, colW: [2.45, 2.35, 2.65], rowH: [0.42, 0.6, 0.6, 0.72, 0.6, 0.6, 0.6], fontSize: 13, fontFace: "Calibri",
    color: K.ink, valign: "middle", margin: [0.05, 0.12, 0.05, 0.12],
    border: [{ type: "none" }, { type: "none" }, { pt: 0.75, color: K.line }, { type: "none" }], objectName: "comparison table" });
  T(s, [{ text: "On this evidence: ", options: { bold: true } }, { text: "the obvious approach raised 29,961 false alarms; ours raised none." }],
    { x: L, y: 6.05, w: 7.45, h: 0.55, fontSize: 15, color: K.dark });
  box(s, 8.35, 1.6, 4.38, 5.05, K.panel, "techniques panel");
  T(s, "Four techniques we built for this case", { x: 8.6, y: 1.78, w: 3.9, h: 0.4, fontSize: 16, bold: true });
  [["Double-entry for data flows", "Every read must be posted to the partner system; the rest goes to a suspense account."],
   ["The network log as a witness", "Its match window calibrates itself to cover 95% of genuine link traffic."],
   ["A clock solver", "Aligns unsynced clocks by cross-correlation, and refuses to guess when there is no signal."],
   ["The invoice as a sensor", "A bill cannot be deleted: 14 export jobs billed, 4 routine (E06)."]].forEach(([h, d], i) => {
    const y = 2.35 + i * 1.05;
    num(s, 8.6, y + 0.03, 0.38, i + 1, K.ink, K.white, 13);
    T(s, h, { x: 9.15, y, w: 3.4, h: 0.32, fontSize: 14, bold: true });
    T(s, d, { x: 9.15, y: y + 0.33, w: 3.4, h: 0.65, fontSize: 12, color: K.dark });
  });
  s.addNotes("The difference is the unit of analysis. Per-log rules ask whether one line looks odd; we ask whether the books balance across systems. That is why the attacker inside our private link, with the real client name, in the sync window, is invisible to the obvious approach and caught three ways by ours. On the right are four techniques we have not seen packaged elsewhere; each one grew out of a specific trap in this evidence.");

  // 7 — creative features ---------------------------------------------------
  s = pres.addSlide({ masterName: "VX_CONTENT", sectionTitle: "The solution" });
  head(s, "06 · BEYOND DETECTION", "Four features that act, not just alert");
  const feats = [
    [I.claim, "Vendor-claim checker", "Each claim in the vendor’s incident notice becomes a test, checked against our logs with the rows cited.", "6/6", "vendor claims contradicted (E16, E20-A)", "vendor_claims_checked.csv"],
    [I.lock, "Least-privilege replay", "Learns the sync’s real needs from June and July (4 actions, 6 hosts, 01:00–02:45 UTC), then replays August and September.", "133/133", "attacker requests refused; the only genuine refusals are the unreviewed 1 Sep change", "least_privilege_policy.json"],
    [I.phone, "Call-back guard", "A call-back proves nothing if software rewrote the phone number. Flags every vendor whose contacts it changed.", "66", "vendors with untrusted call-back numbers, incl. V-0162 on Finance’s list", "hold_list.csv · callback"],
    [I.users, "One incident, four briefs", "The same findings written for the GM, Finance, Legal and IT. Every line is generated, none typed.", "4", "briefs from one run, one per Appendix C reader", "briefs.md"],
  ];
  feats.forEach(([img, name, desc, big, label, file], i) => {
    const x = L + (i % 2) * 6.15, y = 1.6 + Math.floor(i / 2) * 2.6;
    box(s, x, y, 5.98, 2.4, K.panel, `feature ${name}`);
    disc(s, x + 0.28, y + 0.3, 0.62, K.ink, img, `${name} icon`);
    T(s, name, { x: x + 1.1, y: y + 0.3, w: 3.0, h: 0.42, fontSize: 18, bold: true });
    T(s, desc, { x: x + 1.1, y: y + 0.78, w: 3.0, h: 1.05, fontSize: 13, color: K.dark });
    T(s, "output: " + file, { x: x + 1.1, y: y + 1.92, w: 3.0, h: 0.3, fontSize: 10, color: K.mid, fontFace: MONO });
    T(s, big, { x: x + 4.25, y: y + 0.25, w: 1.6, h: 0.62, fontSize: 30, bold: true });
    T(s, label, { x: x + 4.25, y: y + 0.9, w: 1.6, h: 1.35, fontSize: 11, color: K.mid });
  });
  s.addNotes("These four go past detection and are working today on the released evidence. The claim checker turns the vendor's email into tests: all six claims fail. The policy generator learns the sync's real needs from June and July and replays August and September: it would have refused every one of the 133 attacker requests, and the only genuine thing it refuses is the new contact sync that nobody reviewed. The call-back guard matters because 66 vendors' phone numbers were rewritten by software in September. The briefs give each stakeholder exactly what Appendix C says they want.");

  // 8 — built + tech ----------------------------------------------------------
  pres.addSection({ title: "Proof" });
  s = pres.addSlide({ masterName: "VX_CONTENT", sectionTitle: "Proof" });
  head(s, "07 · BUILT SO FAR AND TECHNOLOGY", "Working today, offline, on a laptop");
  s.addImage({ path: path.join(__dirname, "report_briefs.png"), x: L, y: 1.55, w: 6.3, h: 4.92, altText: "Screenshot of the tool's report showing four generated briefs",
    shadow: { type: "outer", color: "000000", blur: 6, offset: 2, angle: 90, opacity: 0.18 } });
  T(s, "The tool’s own report on the released evidence — one 8-second run.", { x: L, y: 6.55, w: 6.3, h: 0.3, fontSize: 11, italic: true, color: K.mid });
  [["20", "Python modules"], ["3,325", "lines of code"], ["8 s", "for 109,853 rows"]].forEach(([b, l], i) => {
    const x = 7.3 + i * 1.85;
    T(s, b, { x, y: 1.55, w: 1.75, h: 0.6, fontSize: 30, bold: true });
    T(s, l, { x, y: 2.15, w: 1.75, h: 0.3, fontSize: 11, color: K.mid });
  });
  T(s, "What works now", { x: 7.3, y: 2.68, w: 5.4, h: 0.35, fontSize: 15, bold: true });
  const works = ["Loaders for E01–E19", "Clock solver", "Identity resolver", "Witness + new-host check", "Ledger + grammar", "Ticket-to-key chain", "Payment firewall + hold list",
                 "Vendor-claim checker", "Least-privilege replay", "Call-back guard", "Four briefs", "Exports, storage, MFA, leavers", "Synthetic world: 6 attacks", "Evaluator vs the baseline"];
  works.forEach((w, i) => {
    const x = 7.3 + Math.floor(i / 7) * 2.75, y = 3.12 + (i % 7) * 0.37;
    s.addImage({ data: I.checkInk, x, y: y + 0.06, w: 0.17, h: 0.17, altText: "done" });
    T(s, w, { x: x + 0.27, y, w: 2.45, h: 0.32, fontSize: 12, valign: "middle" });
  });
  T(s, "BUILT WITH", { x: 7.3, y: 5.82, w: 3, h: 0.28, fontSize: 11, bold: true, color: K.mid, charSpacing: 2 });
  [["Python 3.13", "pandas", "numpy", "ipaddress (stdlib)"], ["HTML/CSS report", "argparse CLI", "no cloud, no SIEM"]].forEach((row, r) => {
    let cx = 7.3;
    row.forEach((t) => {
      const w = 0.3 + t.length * 0.082;
      box(s, cx, 6.13 + r * 0.42, w, 0.34, K.white, `tech ${t}`, K.ink);
      T(s, t, { x: cx, y: 6.13 + r * 0.42, w, h: 0.34, fontSize: 11.5, align: "center", valign: "middle" });
      cx += w + 0.1;
    });
  });
  s.addNotes("Everything on this slide runs today. The screenshot is the tool's own report on the released evidence: four briefs written from one eight-second run over about 110,000 rows. It is plain Python with pandas and numpy, no cloud and no SIEM, so a 24-person IT team can run it on one laptop the night before every payment run.");

  // 9 — testing + results ----------------------------------------------------
  s = pres.addSlide({ masterName: "VX_CONTENT", sectionTitle: "Proof" });
  head(s, "08 · HOW WE TEST, AND RESULTS SO FAR", "181 of 181 attacker events, zero false alarms");
  [["181 / 181", "attacker events flagged on the real evidence, 9 of 9 stages", "obvious approach: 134"],
   ["0", "false alarms on 109,853 rows", "obvious approach: 29,961"],
   ["1", "incident thread · 1 vendor held (V-0412)", "plus 4 to verify, each with a reason"]].forEach(([b, l, cmp], i) => {
    const y = 1.6 + i * 1.32;
    T(s, b, { x: L, y, w: 4.4, h: 0.68, fontSize: 40, bold: true });
    T(s, l, { x: L, y: y + 0.68, w: 4.4, h: 0.3, fontSize: 13, color: K.dark });
    T(s, cmp, { x: L, y: y + 0.97, w: 4.4, h: 0.28, fontSize: 11, color: K.mid });
  });
  s.addChart(pres.charts.BAR, [
    { name: "Double-Entry Defense", labels: ["Reference", "On the link", "Mimic", "Insider", "Forged approval", "Hijacked sync host"], values: [100, 100, 100, 100, 100, 50] },
    { name: "Per-log rules", labels: ["Reference", "On the link", "Mimic", "Insider", "Forged approval", "Hijacked sync host"], values: [86, 86, 84, 92, 68, 25] },
  ], { x: 5.3, y: 1.55, w: 7.43, h: 3.85, barDir: "col", barGrouping: "clustered", barGapWidthPct: 60,
       chartColors: ["111111", "BFBFBF"], showTitle: true, title: "Recall on unseen attack variations (%, mean of 3 seeds)",
       titleFontSize: 13, titleColor: "111111", titleFontFace: "+mn-lt",
       showValue: true, dataLabelPosition: "outEnd", dataLabelFontSize: 10, dataLabelColor: "333333", dataLabelFontFace: "+mn-lt",
       catAxisLabelColor: "333333", catAxisLabelFontSize: 11, catAxisLabelFontFace: "+mn-lt",
       valAxisHidden: true, valAxisMaxVal: 110, valAxisMinVal: 0, valGridLine: { style: "none" }, catGridLine: { style: "none" },
       showLegend: true, legendPos: "b", legendFontSize: 11, legendFontFace: "+mn-lt", legendColor: "333333", objectName: "recall chart" });
  T(s, "Six attacks generated into fresh data, 3 seeds each; the engine is not told which. False alarms per world: ours 0, per-log rules about 490. Real-evidence scores use our own labels after one documented calibration pass.",
    { x: 5.3, y: 5.42, w: 7.43, h: 0.45, fontSize: 10.5, italic: true, color: K.mid });
  [["Real evidence vs our labels", "make_labels.py: every rule arguable"], ["6 attacks × 3 seeds", "one built to beat us"], ["The obvious approach", "same data, SIEM-style rules"], ["Robustness", "missing files, ISO and dd/mm dates"]].forEach(([a, b], i) => {
    const x = L + i * 3.08;
    box(s, x, 5.98, 2.9, 0.78, K.panel, `test ${i + 1}`);
    T(s, a, { x: x + 0.2, y: 6.06, w: 2.55, h: 0.32, fontSize: 13, bold: true });
    T(s, b, { x: x + 0.2, y: 6.38, w: 2.55, h: 0.3, fontSize: 11, color: K.mid });
  });
  s.addNotes("We test four ways. On the real evidence, against labels we wrote down as explicit rules, we flag all 181 attacker events with no false alarms, where the obvious approach raises almost thirty thousand. For hidden variations we generate six different attacks into fresh synthetic data with different clock skews. Note the last pair of bars: we built one attack specifically to beat us, a hijacked sync host that copies the sync's pattern, and we only catch half of it. That honesty is deliberate.");

  // 10 — limits + next ---------------------------------------------------------
  pres.addSection({ title: "Next" });
  s = pres.addSlide({ masterName: "VX_DARK", sectionTitle: "Next" });
  head(s, "09 · LIMITS AND NEXT STEPS", "What it misses, and where it goes next");
  T(s, "Known limits", { x: L, y: 1.6, w: 5.9, h: 0.4, fontSize: 17, bold: true, color: K.white });
  const lim = [
    "A hijacked sync host that copies the sync’s own pattern: small thefts are partly missed (44–56%); its bank edits are still held.",
    "A thief who also writes the stolen records into the partner system balances the ledger.",
    "Coverage gaps: no flow log after 31 Aug; BlueVault’s clock skew cannot be measured.",
    "Approval numbers are checked for sequence only, until Finance’s approval register is connected.",
    "Our labels and synthetic world are our own, and we tuned once on this data.",
  ];
  lim.forEach((t, i) => {
    const y = 2.1 + i * 0.7;
    T(s, "—", { x: L, y, w: 0.3, h: 0.3, fontSize: 13, color: K.soft });
    T(s, t, { x: L + 0.32, y, w: 5.6, h: 0.65, fontSize: 13, color: K.line });
  });
  T(s, "Next steps", { x: 7.05, y: 1.6, w: 5.6, h: 0.4, fontSize: 17, bold: true, color: K.white });
  const nx = [
    ["Pre-commit hold", "Stop bank-detail edits by integration keys at the API until a person approves."],
    ["Tripwires", "A canary vendor that is never paid and a decoy key planted in a ticket: any use is certain attack."],
    ["Close the loop with Finance", "Join the approval register and the contract call-back numbers to the firewall."],
    ["Streaming and harder tests", "Run on each new log batch; add slow theft and contact-swap-then-bank-change attacks."],
  ];
  nx.forEach(([h, d], i) => {
    const y = 2.1 + i * 0.86;
    num(s, 7.05, y + 0.02, 0.36, i + 1, K.white, K.ink, 13);
    T(s, h, { x: 7.55, y, w: 5.15, h: 0.32, fontSize: 14, bold: true, color: K.white });
    T(s, d, { x: 7.55, y: y + 0.32, w: 5.15, h: 0.5, fontSize: 12.5, color: K.line });
  });
  box(s, L, 5.75, CW, 0.98, K.ink, "outcome", K.white);
  T(s, [{ text: "Expected outcome: ", options: { bold: true, color: K.white } },
        { text: "before every payment run, Finance gets one short list of vendors to hold — each line backed by the exact records — and the security team reviews one incident thread instead of 30,000 alerts.", options: { color: K.line } }],
    { x: L + 0.3, y: 5.75, w: CW - 0.6, h: 0.98, fontSize: 15, valign: "middle" });
  s.addNotes("We are explicit about what this misses. The biggest gap is a hijacked sync host that behaves exactly like the sync; the ledger cannot see small thefts inside a genuine session, but the payment firewall still holds its bank edits, so the money stays safe. Next we move from detecting to preventing: a pre-commit hold at the API, tripwires that no legitimate process ever touches, and the approval register joined in. The outcome: one short, evidenced hold list before every run.");

  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log("wrote", OUT);
})().catch((e) => { console.error(e); process.exit(1); });
