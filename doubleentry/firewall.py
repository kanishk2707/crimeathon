"""Payment-run firewall.

Every change to a vendor's payment instructions (E19) is scored before money
moves, using evidence from other systems:

  * approval reference present and well formed   (Appendix B process)
  * who made it: a person, or software? (E04 register / E18 request join)
  * is that person still employed? (E14)
  * where did the request come from? (E18 caller_ip vs learned home / link)
  * did the same actor look up bank details or search payments first? (recon)
  * how close is the next payment run? (8th / 23rd)
  * was it changed and later changed back? (flip-flop around a run)

Output: HOLD / VERIFY / OK per change, a per-vendor hold list with the
last-known-good account to restore, and which past runs were exposed.
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd

from .util import NetSet


def payment_runs(start, end, cfg):
    hh, mm = (int(x) for x in cfg["payment_run_time_ist"].split(":"))
    runs = []
    month = pd.Timestamp(start.year, start.month, 1)
    stop = end + pd.DateOffset(months=1)
    while month <= stop:
        for d in cfg["payment_run_days"]:
            try:
                t = pd.Timestamp(month.year, month.month, int(d), hh, mm) - pd.Timedelta(minutes=330)
            except ValueError:
                continue
            runs.append(t)
        month += pd.DateOffset(months=1)
    return sorted(runs)


def _approval_state(ref: str, cfg, register_refs):
    r = (ref or "").strip()
    if r.lower() in cfg["approval_placeholders"]:
        return "missing"
    if register_refs is not None:
        return "valid" if r in register_refs else "unknown-ref"
    return "valid" if re.search(cfg["approval_ref_regex"], r) else "malformed"


def _sequence_check(c, ch: pd.DataFrame) -> str:
    """Approval numbers are issued in order. A reference far below the numbers already
    issued by that date, or one already used for another vendor, is reused or backdated."""
    m = re.match(r"^([A-Za-z]+)[-_/ ]?(\d+)$", (c["approval"] or "").strip())
    if not m:
        return ""
    pre, n = m.group(1).upper(), int(m.group(2))
    refs = ch[ch["approval"].str.upper().str.startswith(pre) & (ch["approval"] != c["approval"])].copy()
    refs["num"] = pd.to_numeric(refs["approval"].str.extract(r"(\d+)$")[0], errors="coerce")
    before = refs[(refs["ts"] < c["ts"]) & (refs["ts"] >= c["ts"] - pd.Timedelta(days=30))]
    # one reference covering a same-day batch (a bulk import) is normal; the same reference on another day is not
    reused = ch[(ch["approval"] == c["approval"]) & (ch["vendor_id"] != c["vendor_id"])
                & (ch["ts"] < c["ts"] - pd.Timedelta(days=1))]
    if len(reused):
        return f"approval {c['approval']} was already used for {reused['vendor_id'].iloc[0]}"
    if len(before) >= 2 and n < before["num"].max() - 20:
        return (f"approval {c['approval']} is out of sequence: numbers issued in the previous 30 days reached "
                f"{pre}-{int(before['num'].max())}")
    return ""


def run(ev, ident, act, cfg, analysis_end):
    ch = ev.changes.copy()
    if ch.empty:
        return pd.DataFrame(), pd.DataFrame(), [], []
    bank_re = re.compile(cfg["bank_field_regex"], re.I)
    term_re = re.compile(cfg["terminated_status_regex"], re.I)
    link, internal = NetSet(cfg["link_cidrs"]), NetSet(cfg["internal_cidrs"])
    reg_refs = set(ev.context.get("approval_refs", [])) or None
    start = min(x for x in [ch["ts"].min(), act["ts"].min() if len(act) else None] if x is not None)
    runs = payment_runs(start, analysis_end, cfg)
    ch["is_bank"] = ch["field"].str.contains(bank_re)

    api_act = act[act["src"].isin(["E01", "E18"])] if len(act) else act
    req = api_act.set_index("rid")[["cred", "ip", "ua", "witness", "ts", "ref", "entity"]] if len(api_act) else pd.DataFrame()
    req = req[~req.index.duplicated()]
    roster = ev.roster.set_index("username") if len(ev.roster) else pd.DataFrame()

    out = []
    bank = ch[ch["is_bank"]].sort_values("ts")
    for i, c in bank.iterrows():
        score, why = 0, []
        appr = _approval_state(c["approval"], cfg, reg_refs)
        if appr == "missing":
            score += 35; why.append("no approval reference")
        elif appr in ("malformed", "unknown-ref"):
            score += 20; why.append(f"approval reference {appr}")
        elif appr == "valid":
            seq = _sequence_check(c, ch)
            if seq:
                score += 25; why.append(seq)

        rq = req.loc[c["request_id"]] if c["request_id"] and c["request_id"] in req.index else None
        actor = c["changed_by"]
        cred = rq["cred"] if rq is not None else (actor if ident.is_credential(actor) else "")
        ip = (rq["ip"] if rq is not None else "") or c["ip"]
        kind = "integration" if (cred and (ident.is_credential(cred) or ident.is_external(ident.entity(cred)))) else (
            "person" if ident.is_human(actor) else "unknown")
        if kind == "integration":
            score += 35; why.append(f"made by software credential {cred} - no integration needs to edit payment instructions")
        elif kind == "unknown":
            score += 15; why.append(f"actor '{actor}' is neither a known person nor a registered credential")
        else:
            if len(roster) and actor.lower() in roster.index:
                r = roster.loc[actor.lower()]
                if isinstance(r, pd.DataFrame):
                    r = r.iloc[0]
                td = r["termination_date"]
                if term_re.search(str(r["status"])) or (pd.notna(td) and td < c["ts"]):
                    score += 40; why.append(f"{actor} left the company ({str(td)[:10] if pd.notna(td) else r['status']})")
        if ip:
            if not (ip in internal or ip in link):
                score += 15; why.append(f"request from external address {ip}")
            elif rq is not None and rq["witness"] in ("OFF_LINK", "OFF_HOME", "UNWITNESSED", "NEW_LINK_HOST"):
                score += 10; why.append(f"request came from an unusual host ({rq['witness']})")
        # recon (software actors only: people look vendors up all day as part of their job)
        if len(act) and kind != "person":
            w0 = c["ts"] - pd.Timedelta(days=7)
            prior = act[(act["ts"] >= w0) & (act["ts"] < c["ts"]) & (act["op"] == "read")
                        & act["token"].str.contains(r"bank|payee|payment|vendor", case=False, regex=True)]
            prior = prior[((prior["cred"] == cred) & (cred != "")) | ((prior["ip"] == ip) & (ip != ""))]
            if len(prior):
                score += 10; why.append(f"preceded by {len(prior)} bank/payment lookup(s) from the same actor")
        nxt = next((r for r in runs if r > c["ts"]), None)
        days = (nxt - c["ts"]).total_seconds() / 86400 if nxt is not None else None
        if days is not None and days <= 3:
            score += 15; why.append(f"{days:.1f} days before the {nxt:%d %b} payment run")
        elif days is not None and days <= 7:
            score += 8; why.append(f"{days:.1f} days before the {nxt:%d %b} payment run")
        out.append(dict(idx=i, ref=c["ref"], ts=c["ts"], vendor_id=c["vendor_id"], vendor_name=c["vendor_name"],
                        field=c["field"], old=c["old"], new=c["new"], actor=actor, cred=cred, ip=ip, kind=kind,
                        approval=appr, next_run=nxt, days_to_run=days, score=score, why=why,
                        req_ref=rq["ref"] if rq is not None else ""))
    res = pd.DataFrame(out)
    if res.empty:
        return res, pd.DataFrame(), [], runs

    # flip-flop: a later change on the same vendor+field restores the old value
    why = {i: list(w) for i, w in res["why"].items()}
    res["reverted_at"] = pd.NaT
    for i, r in res.iterrows():
        if r["score"] < 35:
            continue  # an approved correction later undone by another approved correction is ordinary
        later = res[(res["vendor_id"] == r["vendor_id"]) & (res["field"] == r["field"]) & (res["ts"] > r["ts"])
                    & (res["new"] == r["old"]) & (res["ts"] <= r["ts"] + pd.Timedelta(days=45))]
        if len(later):
            j = later.index[0]
            between = [x for x in runs if r["ts"] < x < res.at[j, "ts"]]
            res.at[i, "reverted_at"] = res.at[j, "ts"]
            bonus = 20 if between else 10
            res.at[i, "score"] += bonus
            why[i].append(f"changed back on {res.at[j, 'ts']:%d %b}" + (
                f" after the {between[0]:%d %b} run had used it" if between else ""))
            res.at[j, "score"] += bonus
            why[j].append("restores a value set by an earlier suspicious change (change-and-revert)")
    # batches: one actor, unapproved bank edits across >=3 vendors within 24h
    un = res[res["approval"] != "valid"]
    for actor, g in un.groupby("actor"):
        g = g.sort_values("ts")
        for i, r in g.iterrows():
            win = g[(g["ts"] >= r["ts"] - pd.Timedelta(hours=24)) & (g["ts"] <= r["ts"] + pd.Timedelta(hours=24))]
            if win["vendor_id"].nunique() >= 3:
                res.at[i, "score"] += 10
                why[i].append(f"part of an unapproved batch across {win['vendor_id'].nunique()} vendors")
    res["why"] = [why[i] for i in res.index]
    res["score"] = res["score"].clip(upper=100)
    res["verdict"] = np.select([res["score"] >= 60, res["score"] >= 35], ["HOLD", "VERIFY"], "OK")

    # vendor hold list
    vend = []
    upcoming = next((r for r in runs if r > analysis_end), None)
    for vid, g in res.groupby("vendor_id"):
        g = g.sort_values("ts")
        bad = g[g["verdict"] == "HOLD"]
        if bad.empty and not (g["verdict"] == "VERIFY").any():
            continue
        current, lkg, exposed = {}, {}, set()
        for fld, gf in g.groupby("field"):
            current[fld] = gf.iloc[-1]["new"]
            bf = bad[bad["field"] == fld]
            if len(bf):
                lkg[fld] = bf.iloc[0]["old"]
                t0 = bf.iloc[0]["ts"]
                t1 = bf["reverted_at"].dropna().max() if bf["reverted_at"].notna().any() else None
                if t1 is not None and current[fld] != lkg[fld]:
                    t1 = None  # restored then tampered again
                for x in runs:
                    if x > t0 and (t1 is None or x < t1) and x <= analysis_end:
                        exposed.add(x)
        tampered_now = any(current.get(f) != v for f, v in lkg.items())
        verdict = "HOLD" if (len(bad) and tampered_now) else ("REVIEW-PAID" if len(bad) else "VERIFY")
        vend.append(dict(
            vendor_id=vid, vendor_name=g["vendor_name"].iloc[0], verdict=verdict, max_score=int(g["score"].max()),
            changes=len(g), current=" | ".join(f"{k}={v}" for k, v in current.items()),
            last_known_good=" | ".join(f"{k}={v}" for k, v in lkg.items()),
            exposed_runs=", ".join(f"{x:%d %b}" for x in sorted(exposed)),
            next_run=f"{upcoming:%d %b %Y}" if upcoming is not None else "",
            action=("Hold payment; restore last-known-good; call vendor on number from contract, not from the record"
                    if verdict == "HOLD" else
                    "Account restored, but a run paid the tampered account: recover funds, report to bank" if verdict == "REVIEW-PAID"
                    else "Call-back verification before the run"),
            refs=list(g["ref"]),
        ))
    vendors = pd.DataFrame(vend)
    if len(vendors):
        vendors = vendors.sort_values(["verdict", "max_score"], ascending=[True, False])

    findings = []
    hold = res[res["verdict"] == "HOLD"]
    for (actor, day), g in hold.groupby(["actor", hold["ts"].dt.date]):
        refs = list(g["ref"]) + [x for x in g["req_ref"] if x]
        reasons = sorted({w for ws in g["why"] for w in ws})
        findings.append(dict(
            module="firewall", category="detection", severity=int(min(100, g["score"].max())),
            title="Vendor payment instructions changed without a valid human approval",
            ts_first=g["ts"].min(), ts_last=g["ts"].max(), entity=ident.entity(g["cred"].iloc[0] or actor),
            cred=g["cred"].iloc[0] or actor, ip=g["ip"].iloc[0], refs=refs,
            summary=f"{len(g)} bank-field change(s) to {g['vendor_id'].nunique()} vendor(s) ({', '.join(sorted(set(g['vendor_id'])))}) "
                    f"by {actor}. " + "; ".join(reasons[:5]) + ".",
            details={"vendors": sorted(set(g["vendor_id"])), "score": int(g["score"].max())},
        ))
    return res, vendors, findings, runs
