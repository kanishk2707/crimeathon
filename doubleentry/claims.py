"""Vendor-claim checker: machine-test a third party's incident statement.

A vendor's notice is a document written by someone with a stake in how the story
looks. Each claim is typed into context.json as a testable statement and checked
against what our own logs recorded about the incident (the alert-level findings):

  window          "activity only between FROM and TO"
  no_access       "none of these resources were touched"   (patterns)
  exports_removed "all export files were removed"
  no_link_hosts   "nothing on the private link was involved"
  no_use_after    "credentials rotated at AT"               (creds)
  no_label        "hosts labelled X never reach production" (label_regex)
"""
from __future__ import annotations

import re

import pandas as pd

from .util import NetSet


def run(ev, act, winfo, flagged: set, cfg) -> list:
    claims = ev.context.get("vendor_claims", [])
    if not claims:
        return []
    fa = act[act["ref"].isin(flagged)]
    fb = ev.bv[ev.bv["ref"].isin(flagged)] if len(ev.bv) else ev.bv
    link = NetSet(cfg["link_cidrs"])
    allts = pd.concat([fa["ts"], fb["ts"] if len(fb) else pd.Series(dtype="datetime64[ns]")])
    out = []
    for c in claims:
        t, verdict, ev_txt, refs = c.get("test"), "Untestable", "", []
        if t == "window":
            a, b = pd.Timestamp(c["from"]), pd.Timestamp(c["to"])
            outside = allts[(allts < a) | (allts > b)]
            if len(allts):
                verdict = "Contradicted" if len(outside) else "Consistent"
                ev_txt = f"incident activity runs {allts.min():%d %b %H:%M} → {allts.max():%d %b %H:%M} UTC; {len(outside)} event(s) outside the claimed window"
                refs = list(fa[(fa['ts'] < a) | (fa['ts'] > b)]["ref"][:3])
        elif t == "no_access":
            pat = re.compile("|".join(c["patterns"]), re.I)
            hit_a = fa[fa["token"].str.contains(pat)]
            hit_b = fb[fb["path"].str.contains(pat)] if len(fb) else fb
            n = len(hit_a) + len(hit_b)
            verdict = "Contradicted" if n else "Consistent"
            parts = []
            if len(hit_a):
                parts.append(f"{len(hit_a)} API call(s) to {', '.join(sorted(set(hit_a['token'])))[:110]}")
            if len(hit_b):
                parts.append(f"{len(hit_b)} storage read(s) ({int(hit_b['bytes'].sum()) / 1e6:.0f} MB)")
            ev_txt = "; ".join(parts) or "no matching access"
            refs = list(hit_a["ref"][:2]) + (list(hit_b["ref"][:2]) if len(hit_b) else [])
        elif t == "exports_removed":
            jobs = {}
            hd = ev.hd.set_index("ref") if len(ev.hd) else None
            for _, r in fa[fa["op"].str.startswith("export")].iterrows():
                job = hd.at[r["ref"], "object_id"] if hd is not None and r["ref"] in hd.index else ""
                j = jobs.setdefault(("E02", job), {"dl": False, "del": False})
                j["dl"] |= r["op"] == "export_download"
                j["del"] |= (r["op"] == "export_delete") and bool(r["ok"])
            for _, r in fa[fa["src"].isin(["E01", "E18"])].iterrows():
                m = re.search(r"/exports/(\d+)", ev.api.loc[ev.api["ref"] == r["ref"], "endpoint"].iloc[0])
                if m:
                    j = jobs.setdefault(("LedgerOne", m.group(1)), {"dl": False, "del": False})
                    j["dl"] |= r["token"].endswith("/download")
                    j["del"] |= r["token"].startswith("DELETE") and bool(r["ok"])
            left = [f"{s} {j}" for (s, j), v in jobs.items() if v["dl"] and not v["del"]]
            verdict = "Contradicted" if left else ("Consistent" if jobs else "Untestable")
            ev_txt = f"{len(jobs)} export job(s) touched; downloaded and never removed: {', '.join(left) or 'none'}"
        elif t == "no_link_hosts":
            on = fa[fa["ip"].map(lambda i: i in link)]
            verdict = "Contradicted" if len(on) else "Consistent"
            labels = winfo.get("host_labels", {})
            ev_txt = (f"{len(on)} incident request(s) from " + ", ".join(
                f"{ip} ({labels.get(ip) or 'unlabelled'})" for ip in sorted(set(on["ip"])))) if len(on) else "no incident request from the link"
            refs = list(on["ref"][:3])
        elif t == "no_use_after":
            at = pd.Timestamp(c["at"])
            creds = {x.lower() for x in c.get("creds", [])}
            late = fa[(fa["ts"] > at) & fa["cred"].str.lower().isin(creds)]
            verdict = "Contradicted" if len(late) else "Consistent"
            ev_txt = (f"{len(late)} incident request(s) still accepted after {at:%d %b}, last {late['ts'].max():%d %b %H:%M} UTC"
                      if len(late) else "no incident use after the rotation date")
            refs = list(late["ref"][:3])
        elif t == "no_label":
            fl = ev.flows
            rx = re.compile(c["label_regex"], re.I)
            prod = fl[fl["label"].str.contains(rx) & fl["system"].isin(["LedgerOne", "HelpDeskr", "BlueVault"])]
            verdict = "Contradicted" if len(prod) else "Consistent"
            ev_txt = (f"{len(prod)} flow(s) from {', '.join(sorted(set(prod['label'])))} to production "
                      f"{', '.join(sorted(set(prod['system'])))}, {prod['ts'].min():%d %b}–{prod['ts'].max():%d %b}") if len(prod) else "no such flow"
            refs = list(prod["ref"][:3])
        out.append(dict(id=c.get("id", ""), claim=c.get("claim", ""), verdict=verdict, evidence=ev_txt, refs=refs))
    return out
