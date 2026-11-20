"""Pipeline: load -> align clocks -> resolve identities -> witness -> ledger ->
grammar -> firewall -> exfil -> territory -> governance -> triage."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from itertools import chain

from . import briefs, callback, claims, clocks, exfil, firewall, grammar, intel, ledger, shrinkwrap, territory, triage, witness
from .identity import Identity
from .load import load_evidence


def analyze(folder, cfg) -> dict:
    ev = load_evidence(folder, cfg)
    clock_rows = clocks.align(ev)
    ident = Identity(ev, cfg)

    ends = [x for x in [ev.api["ts"].max(), ev.hd["ts"].max() if len(ev.hd) else None,
                        ev.changes["ts"].max() if len(ev.changes) else None] if x is not None and pd.notna(x)]
    analysis_end = pd.Timestamp(cfg["analysis_end"]) if cfg.get("analysis_end") else (max(ends) if ends else pd.Timestamp.now())

    act, wf, wstats, winfo = witness.run(ev, ident, cfg)
    la, sess, lf, linfo = ledger.run(act, ident, cfg, ev.context.get("announced_changes"))
    if len(la):
        act = act.merge(la[["ref", "sid", "trust"]], on="ref", how="left")
    gram, gf = grammar.run(la, sess, cfg, ev.context.get("announced_changes")) if len(la) else (pd.DataFrame(), [])
    fw, vendors, ff, runs = firewall.run(ev, ident, act, cfg, analysis_end)
    jobs, ef, billing = exfil.run(ev, ident, act, cfg)
    tf, terr = territory.run(ev, cfg)
    pp, pf = intel.passport(ev, ident, act, cfg, analysis_end)
    lvf, lnotes = intel.leavers(ev, ident, act, cfg)
    sf, pw_only = intel.sso_checks(ev, cfg)
    cf = intel.exposure_chain(ev, act, cfg)
    lnotes = lnotes + intel.roster_inconsistencies(ev, cfg)
    cb = callback.run(ev, ident, vendors, analysis_end, cfg)
    if len(vendors) and cb["by_vendor"]:
        vendors = vendors.copy()
        vendors["callback"] = vendors["vendor_id"].map(
            lambda v: f"use the contract number - record rewritten by {cb['by_vendor'][v]['by']} on {cb['by_vendor'][v]['last']:%d %b}"
            if v in cb["by_vendor"] else "number on file not changed by software")
    all_f = wf + lf + gf + ff + ef + tf + pf + lvf + sf + cf + cb["findings"]
    iocs, _ = intel.ioc_gap(ev, ident, act, all_f)
    if not runs:
        runs = firewall.payment_runs(act["ts"].min(), analysis_end, cfg) if len(act) else []
    fdf = triage.assemble(all_f, runs, ident, cfg)
    flagged = set(chain.from_iterable(fdf.loc[fdf["alert"], "refs"])) if len(fdf) else set()
    policy = shrinkwrap.run(la, winfo, ident, flagged, cfg)
    vclaims = claims.run(ev, act, winfo, flagged, cfg)
    res = dict(
        ev=ev, ident=ident, cfg=cfg, analysis_end=analysis_end, clocks=clock_rows, act=act,
        witness_stats=wstats, witness_info=winfo, sessions=sess, ledger_info=linfo, grammar=gram,
        firewall=fw, vendors=vendors, runs=runs, jobs=jobs, billing=billing, territory=terr,
        passport=pp, leaver_notes=lnotes, password_only=pw_only, iocs=iocs, findings=fdf, threads=triage.threads(fdf),
        callback=cb, policy=policy, claims=vclaims,
    )
    res["briefs"] = briefs.build(res)
    return res


def _jsonable(v):
    if isinstance(v, (pd.Timestamp,)):
        return None if pd.isna(v) else v.isoformat()
    if isinstance(v, float) and pd.isna(v):
        return None
    if isinstance(v, (set, tuple)):
        return list(v)
    return v


def write_outputs(res: dict, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    f = res["findings"]
    recs = []
    for _, r in f.iterrows():
        recs.append({k: _jsonable(v) for k, v in r.items()})
    (out / "findings.json").write_text(json.dumps(recs, indent=1, default=str), encoding="utf-8")
    if len(res["vendors"]):
        res["vendors"].drop(columns=["refs"]).to_csv(out / "hold_list.csv", index=False)
    if len(res["firewall"]):
        fw = res["firewall"].copy()
        fw["why"] = fw["why"].map(lambda w: "; ".join(w))
        fw.drop(columns=["idx"]).to_csv(out / "payment_changes_scored.csv", index=False)
    if len(f):
        tl = f[f["alert"]][["fid", "thread", "ts_first", "ts_last", "severity", "module", "title", "cred", "ip", "summary"]]
        tl.to_csv(out / "timeline.csv", index=False)
    (out / "briefs.md").write_text(briefs.to_markdown(res["briefs"]), encoding="utf-8")
    if res.get("claims"):
        pd.DataFrame(res["claims"]).assign(refs=lambda d: d["refs"].map(", ".join)).to_csv(out / "vendor_claims_checked.csv", index=False)
    if res.get("policy", {}).get("rows"):
        (out / "least_privilege_policy.json").write_text(json.dumps(
            {"learned_until": str(res["policy"]["split"]), "credentials": res["policy"]["rows"]}, indent=1, default=str), encoding="utf-8")
    from .report import render
    (out / "report.html").write_text(render(res), encoding="utf-8")
    return out / "report.html"
