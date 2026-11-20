"""Self-contained HTML report (no external assets; opens offline)."""
from __future__ import annotations

import html

import pandas as pd

from .util import fmt_ist, fmt_ts

CSS = """
:root{--bg:#f7f6f3;--panel:#fff;--ink:#1d1d1b;--mute:#6b6a65;--line:#e4e2dc;--crit:#b42318;--crit-bg:#fdecea;
--warn:#a15c07;--warn-bg:#fef3e2;--ok:#1f7a4d;--ok-bg:#e6f4ec;--info:#2b5c9e;--info-bg:#e8eff9;--mono:ui-monospace,SFMono-Regular,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--panel:#1d1d1b;--ink:#ecebe6;--mute:#9b9a93;--line:#2f2e2b;
--crit:#ff8a7a;--crit-bg:#3a1b17;--warn:#f5b45b;--warn-bg:#36280f;--ok:#6fd3a0;--ok-bg:#12301f;--info:#8db4ef;--info-bg:#17253a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 16px 80px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:36px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:18px 0 6px}.sub{color:var(--mute)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:18px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card .v{font-size:26px;font-weight:650}.card .k{color:var(--mute);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mute);font-weight:600;font-size:12px;white-space:nowrap}td.mono,.mono{font-family:var(--mono);font-size:12px}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.HOLD,.crit{background:var(--crit-bg);color:var(--crit)}.VERIFY,.warn,.REVIEW-PAID{background:var(--warn-bg);color:var(--warn)}
.OK,.ok{background:var(--ok-bg);color:var(--ok)}.info{background:var(--info-bg);color:var(--info)}
.banner{border-left:4px solid var(--crit);background:var(--crit-bg);padding:12px 16px;border-radius:8px;margin:14px 0}
.banner b{color:var(--crit)}.muted{color:var(--mute)}details summary{cursor:pointer;color:var(--info)}
.sev{font-weight:700}.small{font-size:12px}ul{margin:6px 0 6px 18px;padding:0}
.briefs{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:10px;margin:10px 0}
.briefs .panel{margin:0}.briefs h3{margin-top:0}.briefs ul{margin-left:16px}
.v-Contradicted{background:var(--crit-bg);color:var(--crit)}.v-Consistent{background:var(--ok-bg);color:var(--ok)}.v-Untestable{background:var(--info-bg);color:var(--info)}
.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden;min-width:80px}.bar i{display:block;height:100%;background:var(--crit)}
"""


def e(x) -> str:
    if x is None or (isinstance(x, float) and pd.isna(x)):
        return ""
    if isinstance(x, pd.Timestamp):
        return fmt_ts(x)
    return html.escape(str(x))


def sev_pill(s) -> str:
    s = int(s)
    cls = "crit" if s >= 80 else "warn" if s >= 60 else "info"
    return f'<span class="pill {cls}">{s}</span>'


def table(df: pd.DataFrame, cols: list, fmt: dict | None = None, max_rows: int = 400) -> str:
    if df is None or len(df) == 0:
        return '<p class="muted">Nothing to show.</p>'
    fmt = fmt or {}
    h = "<table><thead><tr>" + "".join(f"<th>{e(c[1] if isinstance(c, tuple) else c)}</th>" for c in cols) + "</tr></thead><tbody>"
    for _, r in df.head(max_rows).iterrows():
        h += "<tr>"
        for c in cols:
            key = c[0] if isinstance(c, tuple) else c
            v = r.get(key, "")
            h += f"<td>{fmt[key](v, r) if key in fmt else e(v)}</td>"
        h += "</tr>"
    h += "</tbody></table>"
    if len(df) > max_rows:
        h += f'<p class="muted small">{len(df) - max_rows} more rows in the CSV outputs.</p>'
    return h


def render(res: dict) -> str:
    ev, f = res["ev"], res["findings"]
    alerts = f[f["alert"]] if len(f) else f
    gov = f[f["category"] == "governance"] if len(f) else f
    vendors = res["vendors"]
    hold = vendors[vendors["verdict"] == "HOLD"] if len(vendors) else vendors
    paid = vendors[vendors["verdict"] == "REVIEW-PAID"] if len(vendors) else vendors
    end = res["analysis_end"]
    nxt = next((r for r in res["runs"] if r > end), None)
    exposed = set()
    if len(vendors):
        for s in vendors["exposed_runs"]:
            exposed |= {x.strip() for x in str(s).split(",") if x.strip()}

    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>Double-Entry Defense</title><style>{CSS}</style></head><body><main>"]
    out.append("<h1>Double-Entry Defense &mdash; findings</h1>")
    out.append(f"<div class='sub'>Evidence folder <span class='mono'>{e(ev.folder)}</span> &middot; analysis end {e(end)} UTC "
               f"&middot; all times UTC unless marked IST</div>")

    if len(hold):
        out.append(f"<div class='banner'><b>Before the {nxt:%d %b} payment run:</b> hold {len(hold)} vendor(s) whose payment "
                   f"instructions were changed without a valid human approval and are still tampered. "
                   + (f"Past run(s) already exposed: <b>{e(', '.join(sorted(exposed)))}</b>." if exposed else "") + "</div>")

    out.append("<div class='cards'>")
    for k, v in [("Alerts (paged)", int(alerts["paged"].sum()) if len(alerts) else 0),
                 ("Incident threads", len(res["threads"])),
                 ("Vendors to hold", len(hold)),
                 ("Runs exposed", len(exposed)),
                 ("Governance gaps", len(gov)),
                 ("Witness tolerance", f"{res['witness_info'].get('tolerance_s')}s" if res['witness_info'].get('tolerance_s') else "n/a")]:
        out.append(f"<div class='card'><div class='k'>{e(k)}</div><div class='v'>{e(v)}</div></div>")
    out.append("</div>")

    b = res.get("briefs", {})
    if b:
        out.append("<h2>0 &middot; One incident, four briefs</h2><p class='muted'>The same findings written for each reader in Appendix C. Every line is generated from the analysis.</p><div class='briefs'>")
        for who, lines in b.items():
            out.append(f"<div class='panel'><h3>{e(who)}</h3><ul>" + "".join(f"<li>{e(x)}</li>" for x in lines) + "</ul></div>")
        out.append("</div>")
    # 1 hold list
    out.append("<h2>1 &middot; Payment-run firewall: hold list</h2>")
    out.append("<p class='muted'>Every bank-field change in E19, scored with evidence from E18/E01 (who and where), E14 (still employed?), "
               "the approval reference and the payment calendar. Restore to the last-known-good value and confirm by phone, "
               "using a number from the contract, never the vendor record.</p>")
    out.append("<div class='panel'>" + table(vendors, [
        ("verdict", "Verdict"), ("vendor_id", "Vendor"), ("vendor_name", "Name"), ("max_score", "Score"),
        ("current", "Current (tampered?)"), ("last_known_good", "Last known good"), ("exposed_runs", "Runs exposed"), ("action", "Action")],
        fmt={"verdict": lambda v, r: f"<span class='pill {e(v)}'>{e(v)}</span>",
             "current": lambda v, r: f"<span class='mono'>{e(v)}</span>",
             "last_known_good": lambda v, r: f"<span class='mono'>{e(v)}</span>"}) + "</div>")
    cbr = res.get("callback", {}).get("rows")
    if cbr is not None and len(cbr):
        out.append("<h3>Call-back guard</h3><p class='muted'>Vendors whose contact details were rewritten by software in the 30 days before the run. "
                   "A call-back to the number on file proves nothing for them: use the contract.</p>")
        out.append("<div class='panel'>" + table(cbr.sort_values(["on_payment_list", "last"], ascending=[False, False]),
                   [("vendor_id", "Vendor"), ("vendor_name", "Name"), ("on_payment_list", "On hold/verify list"), ("changes", "Changes"),
                    ("fields", "Fields"), ("by", "Changed by"), ("last", "Last change (UTC)")], max_rows=80) + "</div>")
    fw = res["firewall"]
    if len(fw):
        fwv = fw.copy()
        fwv["why_txt"] = fwv["why"].map(lambda w: "; ".join(w))
        fwv = fwv.sort_values("ts")
        out.append("<details><summary>All scored bank-field changes (" + str(len(fwv)) + ")</summary><div class='panel'>" + table(fwv, [
            ("ts", "When (UTC)"), ("verdict", "Verdict"), ("score", "Score"), ("vendor_id", "Vendor"), ("field", "Field"),
            ("actor", "Changed by"), ("ip", "From"), ("approval", "Approval"), ("why_txt", "Why"), ("ref", "Evidence")],
            fmt={"verdict": lambda v, r: f"<span class='pill {e(v)}'>{e(v)}</span>", "ref": lambda v, r: f"<span class='mono'>{e(v)} {e(r['req_ref'])}</span>"}) + "</div></details>")

    # 2 threads
    out.append("<h2>2 &middot; Incident threads</h2>")
    out.append("<p class='muted'>Alerts joined when they share a credential, an outside address or an entity. One thread = one story to defend.</p>")
    for t in res["threads"]:
        g = alerts[alerts["thread"] == t["thread"]].sort_values("ts_first")
        out.append(f"<div class='panel'><h3>{e(t['thread'])} &middot; {e(', '.join(t['entities'])[:120])} {sev_pill(t['max_severity'])}</h3>"
                   f"<div class='small muted'>{e(t['first'])} &rarr; {e(t['last'])} UTC &middot; {t['findings']} findings &middot; "
                   f"modules: {e(', '.join(t['modules']))} &middot; outside addresses: <span class='mono'>{e(', '.join(i for i in t['ips'] if not i.startswith(('10.20.4', '172.16')))[:200]) or 'none'}</span></div>")
        out.append(table(g, [("ts_first", "First (UTC)"), ("severity", "Sev"), ("module", "Module"), ("title", "Finding"), ("summary", "What the records show"), ("refs", "Evidence")],
                         fmt={"severity": lambda v, r: sev_pill(v),
                              "ts_first": lambda v, r: f"{e(v)}<br><span class='muted small'>{e(fmt_ist(v))}</span>",
                              "refs": lambda v, r: f"<details><summary>{len(v)} rows</summary><span class='mono small'>{e(', '.join(v[:40]))}{' ...' if len(v) > 40 else ''}</span></details>"}))
        out.append("</div>")

    # 3 suspense account
    out.append("<h2>3 &middot; Suspense account (double-entry ledger)</h2>")
    li = res["ledger_info"]
    if li.get("median_ratio") is not None:
        out.append(f"<p class='muted'>Learned from {li['trusted_sessions']} witnessed sync sessions: every record the sync reads is written "
                   f"to the partner system at a rate of {li['median_ratio']:.2f} (floor {li['low']:.2f}). Entries below have no balancing entry.</p>")
    sus = pd.DataFrame(li.get("suspense", []))
    out.append("<div class='panel'>" + table(sus, [("start", "Start (UTC)"), ("kind", "Entry"), ("cred", "Credential"), ("ip", "From"),
                                                    ("trust", "Session"), ("debit", "Debit"), ("credit", "Credit"), ("tokens", "Actions")]) + "</div>")
    voc = li.get("vocab", {})
    if voc:
        out.append("<details><summary>Learned sync vocabulary per credential</summary><div class='panel small mono'>" +
                   "<br>".join(f"<b>{e(k)}</b>: {e(', '.join(v) if v else '(not enough witnessed sessions)')}" for k, v in voc.items()) + "</div></details>")

    # 4 witness
    out.append("<h2>4 &middot; Witness quorum (API log &times; network flow log)</h2>")
    wi = res["witness_info"]
    cov = wi.get("coverage", (None, None))
    out.append(f"<p class='muted'>Link-resident entities (learned): {e(', '.join(wi.get('link_entities', [])) or 'none')}. "
               f"Flow-log coverage {e(cov[0])} &rarr; {e(cov[1])}. Self-calibrated tolerance {e(wi.get('tolerance_s'))}s "
               f"witnesses {((wi.get('witness_rate') or 0) * 100):.1f}% of on-link events.</p>")
    ws = res["witness_stats"]
    if len(ws):
        cols = [c for c in ws.columns]
        out.append("<div class='panel'>" + table(ws, cols) + "</div>")

    # 5 grammar
    out.append("<h2>5 &middot; Sync grammar</h2>")
    g = res["grammar"]
    if len(g):
        flagged = g[g["score"] >= res["cfg"]["alert_threshold"]].sort_values("start")
        out.append(f"<p class='muted'>{len(g)} sessions scored against the grammar learned from witnessed sessions; {len(flagged)} fail to parse.</p>")
        out.append("<div class='panel'>" + table(flagged, [("start", "Start (UTC)"), ("cred", "Credential"), ("ip", "From"), ("n", "Events"),
                                                          ("trust", "Session"), ("novel_tokens", "Unknown actions"), ("novel_bigram_frac", "Unknown transitions"),
                                                          ("start_z", "Start z"), ("ua_flags", "Client version"), ("score", "Score")],
                                                     fmt={"score": lambda v, r: sev_pill(v)}) + "</div>")

    # 6 exports / bluevault
    out.append("<h2>6 &middot; Support exports and storage territory</h2>")
    jobs = res["jobs"]
    if len(jobs):
        out.append("<div class='panel'>" + table(jobs.sort_values("created"), [
            ("created", "Created (UTC)"), ("actor", "Actor"), ("ip", "From"), ("routine", "Routine"), ("integration", "Software"),
            ("antiforensic", "Deleted fast"), ("severity", "Sev"), ("details", "Details")],
            fmt={"severity": lambda v, r: sev_pill(v) if v else "", "created": lambda v, r: f"{e(v)}<br><span class='muted small'>{e(fmt_ist(v))}</span>"}) + "</div>")
    if res["billing"]:
        out.append("<div class='panel'><b>Billing as a sensor (E06 vs E02)</b>" + table(pd.DataFrame([dict(month=k, **v) for k, v in res["billing"].items()]),
                                                                                   ["month", "billed", "logged", "routine", "unexplained"]) + "</div>")
    terr_f = f[f["module"] == "territory"] if len(f) else f
    out.append("<div class='panel'><b>BlueVault reads outside a key's territory</b>" + table(terr_f, [("ts_first", "First (UTC)"), ("severity", "Sev"), ("cred", "Principal"), ("summary", "What")],
                                                                                     fmt={"severity": lambda v, r: sev_pill(v)}) + "</div>")

    # 7 intel
    out.append("<h2>7 &middot; What the vendor told us vs what our logs show</h2>")
    out.append("<div class='panel'>" + table(res["iocs"], [("indicator", "Indicator"), ("type", "Type"), ("vendor_first", "Vendor first"), ("vendor_last", "Vendor last"),
                                                            ("our_first", "Ours first (vendor creds)"), ("our_last", "Ours last"), ("our_events", "Our events"), ("shared_use", "Other users of address"), ("gap", "Gap")]) + "</div>")

    vc = res.get("claims") or []
    if vc:
        out.append("<h3>The vendor's statement, machine-checked</h3><p class='muted'>Each claim from the vendor's notice (typed into context.json) tested against the incident records.</p>")
        out.append("<div class='panel'>" + table(pd.DataFrame(vc), [("id", "Source"), ("claim", "They said"), ("verdict", "Verdict"), ("evidence", "Our records"), ("refs", "Rows")],
                   fmt={"verdict": lambda v, r: f"<span class='pill v-{e(v)}'>{e(v)}</span>", "refs": lambda v, r: f"<span class='mono small'>{e(', '.join(v))}</span>"}) + "</div>")
    # 8 governance
    out.append("<h2>8 &middot; Governance: promise vs proof</h2>")
    out.append("<div class='panel'><b>Integration passport (E04)</b>" + table(res["passport"], [
        ("credential", "Credential"), ("entity", "Entity"), ("owner", "Owner"), ("scope", "Scope"), ("seen_in_logs", "Events"),
        ("distinct_actions_used", "Actions used"), ("issues", "Issues")]) + "</div>")
    lv = f[f["module"] == "leavers"] if len(f) else f
    out.append("<div class='panel'><b>Leavers</b>" + table(lv, [("ts_first", "First after leaving"), ("summary", "What")]) +
               ("<ul>" + "".join(f"<li>{e(n)}</li>" for n in res["leaver_notes"]) + "</ul>" if res["leaver_notes"] else "") + "</div>")

    pol = res.get("policy", {})
    if pol.get("rows"):
        out.append(f"<h3>Least-privilege policy, learned and replayed</h3><p class='muted'>Learned from witnessed behaviour before {e(pol['split'])} UTC, "
                   "then every later request replayed through it: what it would have refused.</p>")
        pr = pd.DataFrame(pol["rows"]).assign(needed=lambda d: d["needed"].map(", ".join), hosts=lambda d: d["hosts"].map(", ".join),
                                              attacker=lambda d: d["attacker_refused"].astype(str) + " / " + d["attacker_requests"].astype(str),
                                              genuine=lambda d: d["genuine_refused"].astype(str) + " / " + d["genuine_requests"].astype(str),
                                              genuine_refused_tokens=lambda d: d["genuine_refused_tokens"].map(", ".join))
        out.append("<div class='panel'>" + table(pr, [("credential", "Credential"), ("granted", "Granted today"), ("needed", "Actually needed"), ("hosts", "Hosts"),
                   ("window", "Hours"), ("attacker", "Attacker requests refused"), ("genuine", "Genuine requests refused"), ("genuine_refused_tokens", "Refused genuine actions")]) + "</div>")
    # 9 clocks + sources
    out.append("<h2>9 &middot; Clock agreement and sources</h2>")
    out.append("<div class='panel'>" + table(pd.DataFrame(res["clocks"]), [("source", "Source"), ("basis", "Clock basis"), ("offset_s", "Offset (s)"), ("support", "Pairs"), ("verdict", "Verdict")]) + "</div>")
    src = pd.DataFrame([dict(code=k, **v) for k, v in sorted(ev.sources.items())])
    out.append("<div class='panel'>" + table(src, [("code", "Item"), ("file", "File"), ("rows", "Rows"), ("clock", "Clock")]) + "</div>")
    if ev.notes:
        out.append("<ul class='muted'>" + "".join(f"<li>{e(n)}</li>" for n in ev.notes) + "</ul>")

    # 10 all alerts
    out.append("<h2>10 &middot; All alerts (budgeted)</h2>")
    out.append("<div class='panel'>" + table(alerts.sort_values("ts_first") if len(alerts) else alerts, [
        ("fid", "ID"), ("ts_first", "First (UTC)"), ("severity", "Sev"), ("paged", "Paged"), ("thread", "Thread"), ("module", "Module"), ("title", "Finding"), ("cred", "Actor"), ("ip", "From")],
        fmt={"severity": lambda v, r: sev_pill(v)}) + "</div>")
    if "evaluation" in res:
        out.append(res["evaluation"])
    out.append("<p class='muted small'>Synthetic or supplied evidence only. Every conclusion lists the evidence rows it relies on.</p>")
    out.append("</main></body></html>")
    return "".join(out)
