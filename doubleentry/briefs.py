"""One incident, four briefs.

Appendix C: the General Manager wants an account he can act on, Finance wants
certainty about money, Legal wants facts she can rely on, and the one-person
security team wants help that is not more work. The same findings are rendered
four ways; every line comes from the analysis, nothing is typed by hand.
"""
from __future__ import annotations

from itertools import chain

import pandas as pd

from .util import NetSet


def build(res: dict) -> dict:
    ev, cfg, f = res["ev"], res["cfg"], res["findings"]
    alerts = f[f["alert"]] if len(f) else f
    flagged = set(chain.from_iterable(alerts["refs"])) if len(alerts) else set()
    act = res["act"]
    fa = act[act["ref"].isin(flagged)]
    fb = ev.bv[ev.bv["ref"].isin(flagged)] if len(ev.bv) else ev.bv
    link = NetSet(cfg["link_cidrs"])
    labels = res["witness_info"].get("host_labels", {})
    ts = pd.concat([fa["ts"], fb["ts"] if len(fb) else pd.Series(dtype="datetime64[ns]")])
    first, last = (ts.min(), ts.max()) if len(ts) else (None, None)
    nxt = next((r for r in res["runs"] if r > res["analysis_end"]), None)
    v = res["vendors"]
    hold = v[v["verdict"] == "HOLD"] if len(v) else v
    verify = v[v["verdict"].isin(["VERIFY", "REVIEW-PAID"])] if len(v) else v
    claims = res.get("claims", [])
    contra = [c for c in claims if c["verdict"] == "Contradicted"]
    on_link = fa[fa["ip"].map(lambda i: i in link)]
    off_link = fa[fa["external_ip"]]
    cb = res.get("callback", {}).get("rows", pd.DataFrame())

    gm, fin, legal, it = [], [], [], []
    if first is not None:
        gm.append(f"A second actor used the TallyBridge integration keys from {first:%d %b} to {last:%d %b}: "
                  f"{len(off_link)} requests from home-broadband addresses and {len(on_link)} from "
                  + ", ".join(f"{ip} ({labels.get(ip) or 'unlabelled'})" for ip in sorted(set(on_link['ip'])))
                  + " inside our private link.")
    if len(hold):
        gm.append(f"Money at risk: {len(hold)} vendor payment(s) to hold before the {nxt:%d %b} run "
                  f"({', '.join(hold['vendor_id'])}); {len(verify)} more to verify.")
    if claims:
        gm.append(f"The vendor's incident statement: {len(contra)} of {len(claims)} claims are contradicted by our own logs.")
    gm.append("Decision needed today: approve the payment holds and the revocation of the vendor's keys.")

    for _, r in hold.iterrows():
        fin.append(f"HOLD {r['vendor_id']} {r['vendor_name']}: restore {r['last_known_good']} (record now shows {r['current']}).")
    fw = res.get("firewall", pd.DataFrame())
    cbv = res.get("callback", {}).get("by_vendor", {})
    for _, r in verify.iterrows():
        why = []
        if len(fw):
            for w in fw.loc[fw["vendor_id"] == r["vendor_id"], "why"]:
                why += [x for x in w if "payment run" not in x]
        note = "; ".join(dict.fromkeys(why)) or r["action"].lower()
        cbn = " Call the contract number: the record's contact was rewritten by software." if r["vendor_id"] in cbv else ""
        fin.append(f"VERIFY {r['vendor_id']} {r['vendor_name']}: {note}.{cbn}")
    if len(cb):
        listed = cb[cb["on_payment_list"]]
        fin.append(f"Call-back warning: software rewrote contact details for {len(cb)} vendors since {cb['last'].min():%d %b}. "
                   f"Call the number in the contract, not the record" + (f" — including {', '.join(listed['vendor_id'])} on your list." if len(listed) else "."))
    exposed = sorted({x for s in v.get("exposed_runs", []) for x in str(s).split(",") if x.strip()}) if len(v) else []
    fin.append(f"Past runs paid to a tampered account: {', '.join(exposed) if exposed else 'none found in the records'}.")

    exp = fa[fa["op"] == "export_create"]
    if len(exp):
        legal.append(f"Support tickets: {len(exp)} bulk export jobs of HelpDeskr data on {exp['ts'].min():%d %b}, downloaded and then deleted.")
    srch = fa[fa["token"].str.contains("search") & (fa["system"] == "HelpDeskr")]
    if len(srch):
        legal.append(f"{len(srch)} ticket searches for credentials and bank terms; at least one customer key was taken from a ticket.")
    lx = fa[(fa["system"] == "LedgerOne") & fa["token"].str.contains(r"/export$", regex=True)]
    for tok, g in lx.groupby("token"):
        legal.append(f"Finance system: {len(g)} × {tok.split()[-1]} ({int(g['records'].sum()):,} records).")
    if len(fb):
        legal.append(f"Stored files: {len(fb)} reads/listings under {', '.join(sorted(set(fb['path'].str.extract(r'^(/[^/]+)')[0].dropna())))} "
                     f"({fb['bytes'].sum() / 1e6:.0f} MB) using a customer partner's storage key.")
    if first is not None:
        legal.append(f"Earliest incident record: {first:%d %b %Y %H:%M} UTC; latest: {last:%d %b %Y %H:%M} UTC. "
                     f"Contract and regulator notification periods should be checked from the earliest date.")

    creds = sorted(set(fa["cred"]) | set(fb["principal"].str.replace(r"^\w+:", "", regex=True)) if len(fb) else set(fa["cred"]))
    it.append(f"Revoke and re-issue: {', '.join(c for c in creds if c)}.")
    if len(on_link):
        it.append(f"Block on the link: {', '.join(sorted(set(on_link['ip'])))} — not one of the hosts that carry the sync.")
    ext = sorted(set(off_link["ip"]) | (set(fb.loc[fb["ip"] != "", "ip"]) if len(fb) else set()))
    if ext:
        it.append(f"Block at the edge (temporary — dynamic home addresses): {', '.join(ext)}.")
    for _, r in f[f["module"] == "identity"].iterrows():
        it.append(f"Reset the password of {r['cred']}: it was accepted from {r['ip']}; only MFA stopped the sign-in.")
    for _, r in f[f["module"] == "leavers"].iterrows():
        it.append(f"Disable {r['cred']}: former employee whose account still signs in.")
    for p in res.get("policy", {}).get("rows", []):
        it.append(f"Re-issue {p['credential']} limited to {len(p['needed'])} action(s), hosts {', '.join(p['hosts'])}, {p['window']} "
                  f"(granted today: '{p['granted']}').")
    return {"General Manager": gm, "Finance": fin, "Legal": legal, "IT security": it}


def to_markdown(b: dict) -> str:
    out = ["# One incident, four briefs\n"]
    for who, lines in b.items():
        out.append(f"## {who}\n")
        out += [f"- {x}" for x in lines]
        out.append("")
    return "\n".join(out)
