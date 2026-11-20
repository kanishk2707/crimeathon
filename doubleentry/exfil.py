"""HelpDeskr export jobs and secret hunting.

* Export lifecycle: create -> download -> delete. Deleting a job minutes after
  downloading it removes the artefact but not the audit row or the bill.
* Routine exports are learned (same actor, same weekday, most weeks: e.g. the
  Support Team Lead's Tuesday review) and credited; everything else goes to suspense.
* Billing as a sensor: if context.json supplies the billed export count (E06),
  the invoice is compared with the audit log. The meter is the one witness the
  actor cannot delete.
* Secret hunting: searches for 'password', 'access key', 'token' ... by software
  identities or from outside the office.
"""
from __future__ import annotations

import re

import pandas as pd

from .util import NetSet


def run(ev, ident, act, cfg):
    hd = act[act["src"] == "E02"].copy()
    findings, jobs_out = [], []
    if hd.empty:
        return pd.DataFrame(), findings, {}
    ex = hd[hd["op"].str.startswith("export")].merge(
        ev.hd[["rid", "object_id", "details", "actor_type"]], on="rid", how="left")
    if len(ex):
        ex["ist"] = ex["ts"] + pd.Timedelta(minutes=330)
        weeks_total = max(1, int((hd["ts"].max() - hd["ts"].min()).days // 7) + 1)
        creates = ex[ex["op"] == "export_create"]
        routine = set()
        for (actor, wd), g in creates.groupby(["cred", creates["ist"].dt.weekday]):
            if g["ist"].dt.to_period("W").nunique() / weeks_total >= cfg["routine_min_weeks_fraction"]:
                routine.add((actor, wd))
        ex["job"] = ex["object_id"].where(ex["object_id"].astype(str).str.strip() != "", ex["cred"] + "@" + ex["ts"].dt.strftime("%Y%m%d%H"))
        for job, g in ex.groupby("job"):
            g = g.sort_values("ts")
            actor = g["cred"].iloc[0]
            c = g[g["op"] == "export_create"]
            d = g[g["op"] == "export_download"]
            x = g[g["op"] == "export_delete"]
            t_create = c["ts"].min() if len(c) else g["ts"].min()
            wd = (t_create + pd.Timedelta(minutes=330)).weekday()
            is_routine = (actor, wd) in routine
            integ = bool(g["link_expected"].iloc[0]) or ident.is_external(g["entity"].iloc[0])
            antiforensic = len(d) and len(x) and (x["ts"].min() - d["ts"].max()) <= pd.Timedelta(minutes=cfg["antiforensic_window_minutes"]) \
                and x["ts"].min() >= d["ts"].max()
            sev = 0
            why = []
            if integ:
                sev = 80; why.append("export run by a software identity (the sync never needs bulk exports)")
            elif not is_routine:
                sev = 40; why.append("not part of a learned weekly routine")
            if antiforensic:
                sev += 15; why.append(f"job deleted {(x['ts'].min() - d['ts'].max()).total_seconds() / 60:.0f} min after download")
            if g["witness"].isin(["OFF_LINK", "OFF_HOME"]).any() or g["external_ip"].any():
                sev += 5; why.append(f"from {', '.join(sorted(set(g['ip'])))}")
            det = " ".join(g["details"].astype(str))
            jobs_out.append(dict(job=job, actor=actor, ip=", ".join(sorted(set(g["ip"]))), created=t_create,
                                 downloaded=d["ts"].min() if len(d) else pd.NaT, deleted=x["ts"].min() if len(x) else pd.NaT,
                                 routine=is_routine, integration=integ, antiforensic=bool(antiforensic),
                                 severity=min(sev, 100), details=det[:120]))
            if sev >= 40:
                findings.append(dict(
                    module="exfil", category="detection", severity=min(sev, 100),
                    title="HelpDeskr export job outside any routine",
                    ts_first=g["ts"].min(), ts_last=g["ts"].max(), entity=g["entity"].iloc[0], cred=actor,
                    ip=", ".join(sorted(set(g["ip"]))), refs=list(g["ref"]),
                    summary=f"Export {job} by {actor}: " + "; ".join(why) + (f". Job details: {det[:90]}" if det.strip() else "."),
                    details={"routine": is_routine, "antiforensic": bool(antiforensic)},
                ))
    jobs = pd.DataFrame(jobs_out)

    # secret hunting
    sq = re.compile(cfg["secret_query_regex"], re.I)
    srch = hd[hd["token"].str.contains(r"search|query|find", regex=True)].merge(ev.hd[["rid", "details"]], on="rid", how="left")
    srch = srch[srch["details"].astype(str).str.contains(sq)]
    for (actor, day), g in srch.groupby(["cred", srch["ts"].dt.date]):
        integ = bool(g["link_expected"].iloc[0]) or ident.is_external(g["entity"].iloc[0]) or ident.is_credential(actor)
        if not integ:
            continue  # agents legitimately search 'password reset'; software has no reason to
        findings.append(dict(
            module="exfil", category="detection", severity=75,
            title="Searching support tickets for secrets",
            ts_first=g["ts"].min(), ts_last=g["ts"].max(), entity=g["entity"].iloc[0], cred=actor,
            ip=", ".join(sorted(set(g["ip"]))), refs=list(g["ref"]),
            summary=f"{len(g)} ticket search(es) by {actor} for credential-like terms: "
                    f"{'; '.join(sorted(set(g['details'].astype(str).str[:60])))[:160]}",
            details={},
        ))

    # billing as a sensor
    billing = {}
    billed = ev.context.get("billed_exports") or {}
    if len(jobs):
        jobs["month"] = jobs["created"].dt.strftime("%Y-%m")
        for month, n_billed in billed.items():
            logged = jobs[jobs["month"] == month]
            billing[month] = dict(billed=int(n_billed), logged=len(logged), routine=int(logged["routine"].sum()),
                                  unexplained=len(logged) - int(logged["routine"].sum()))
            if int(n_billed) != len(logged) or billing[month]["unexplained"]:
                findings.append(dict(
                    module="exfil", category="governance", severity=50,
                    title="Invoice and audit log disagree on export jobs",
                    ts_first=pd.Timestamp(month + "-01"), ts_last=pd.Timestamp(month + "-01") + pd.offsets.MonthEnd(1),
                    entity="HelpDeskr", cred="", ip="", refs=[],
                    summary=f"{month}: billed {n_billed} export jobs (E06); audit log shows {len(logged)}, of which "
                            f"{billing[month]['routine']} match a routine. {billing[month]['unexplained']} unexplained.",
                    details=billing[month],
                ))
    return jobs, findings, billing
