"""Witness quorum: an integration action is believed only when an independent
system saw it too.

For an entity that normally reaches us over the private link, every API/audit
event should (a) come from the link range and (b) have a matching network flow
in E15 from the same host to the same system. The matching tolerance is
self-calibrated: the smallest window that witnesses >= 95% of on-link events.

Statuses:
  WITNESSED    on the link and seen by the flow log
  UNWITNESSED  claims a link address but the flow log never saw it
  OFF_LINK     link-only identity used from somewhere else
  NO_COVERAGE  on the link but outside the flow log's time range (e.g. E18 in Sep)
  HOME / OFF_HOME / NO_ADDRESS  for non-link credentials, against their learned home networks
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .util import NetSet, net24, truthy


def build_activity(ev, ident) -> pd.DataFrame:
    cols = ["ts", "src", "ref", "rid", "cred", "ip", "ua", "ep", "token", "op", "records", "system", "ok"]
    api = ev.api[cols].copy()
    hd = ev.hd[cols].copy()
    act = pd.concat([api, hd], ignore_index=True)
    act = act[act["ts"].notna()].sort_values("ts").reset_index(drop=True)
    act["entity"] = ident.entity_series(act["cred"])
    return act


def _home_nets(ips: pd.Series, min_share: float) -> set:
    nets = ips[ips != ""].map(net24)
    if nets.empty:
        return set()
    share = nets.value_counts(normalize=True)
    return set(share[share >= min_share].index)


def run(ev, ident, cfg):
    link = NetSet(cfg["link_cidrs"])
    internal = NetSet(cfg["internal_cidrs"])
    act = build_activity(ev, ident)
    act["on_link"] = act["ip"].map(lambda i: i in link)

    # which entities live on the private link? (learned, not assumed)
    share = act.groupby("entity")["on_link"].mean()
    link_entities = set(share[share >= 0.5].index)
    act["link_expected"] = act["entity"].isin(link_entities)

    # flow index
    fl = ev.flows[ev.flows["ts"].notna()]
    cov = (fl["ts"].min(), fl["ts"].max()) if len(fl) else (None, None)
    index = {}
    for (ip, sysname), g in fl.groupby(["src_ip", "system"]):
        index[(ip, sysname)] = np.sort(g["ts"].values.astype("datetime64[ns]").astype(np.int64))
    any_sys = {}
    for ip, g in fl.groupby("src_ip"):
        any_sys[ip] = np.sort(g["ts"].values.astype("datetime64[ns]").astype(np.int64))

    act["flow_gap_s"] = np.nan
    cand = act["link_expected"] & act["on_link"]
    if cov[0] is not None:
        cand &= act["ts"].between(cov[0] - pd.Timedelta(minutes=5), cov[1] + pd.Timedelta(minutes=5))
    else:
        cand &= False
    for (ip, sysname), g in act[cand].groupby(["ip", "system"]):
        arr = index.get((ip, sysname))
        if arr is None:
            arr = any_sys.get(ip)
        if arr is None or len(arr) == 0:
            continue
        xs = g["ts"].values.astype("datetime64[ns]").astype(np.int64)
        i = np.searchsorted(arr, xs)
        lo = arr[np.clip(i - 1, 0, len(arr) - 1)]
        hi = arr[np.clip(i, 0, len(arr) - 1)]
        gap = np.minimum(np.abs(xs - lo), np.abs(xs - hi)) / 1e9
        act.loc[g.index, "flow_gap_s"] = gap

    # self-calibrate tolerance
    gaps = act.loc[cand, "flow_gap_s"]
    tol, rate = None, None
    if cand.sum():
        for t in cfg["witness_tolerances_s"]:
            r = float((gaps <= t).mean())
            tol, rate = t, r
            if r >= cfg["witness_target_rate"]:
                break

    status = pd.Series("", index=act.index, dtype=object)
    le = act["link_expected"]
    status[le & ~act["on_link"]] = "OFF_LINK"
    status[le & act["on_link"] & ~cand] = "NO_COVERAGE"
    if tol is not None:
        status[cand & (act["flow_gap_s"] <= tol)] = "WITNESSED"
        status[cand & ~(act["flow_gap_s"] <= tol)] = "UNWITNESSED"

    # A link entity speaks through a stable set of hosts. A host that appears on only a few
    # days is a NEW_LINK_HOST even if it sits inside the link range and the flow log saw it.
    roster, host_label = {}, {}
    if len(fl):
        for ip, g in fl.groupby("src_ip"):
            host_label[ip] = ", ".join(sorted(set(g["label"]) - {""}))
    for ent, g in act[le & act["on_link"]].groupby("entity"):
        days_total = g["ts"].dt.date.nunique()
        per_ip = g.groupby("ip")["ts"].agg(lambda x: x.dt.date.nunique())
        need = max(5, 0.10 * days_total)
        roster[ent] = set(per_ip[per_ip >= need].index)
    newhost = le & act["on_link"] & pd.Series(
        [ip not in roster.get(e, set()) for ip, e in zip(act["ip"], act["entity"])], index=act.index)
    status[newhost] = "NEW_LINK_HOST"

    # non-link credentials: learned home networks (or explicit CIDRs in E04 ip_restriction)
    home = {}
    for cred, g in act[~le].groupby("cred"):
        restr = ident.meta.get(cred, {}).get("ip_restriction", "")
        if truthy(restr) is None and str(restr).strip():
            home[cred] = ("cidr", NetSet([x.strip() for x in str(restr).replace(";", ",").split(",")]))
        else:  # boolean flag or blank: the register does not say *which* addresses, so learn them
            home[cred] = ("nets", _home_nets(g["ip"], cfg["home_net_min_share"]))
    nl = act[~le]
    def _home_status(row_ip, cred):
        if not row_ip:
            return "NO_ADDRESS"
        kind, h = home.get(cred, ("nets", set()))
        ok = (row_ip in h) if kind == "cidr" else (net24(row_ip) in h)
        return "HOME" if ok else "OFF_HOME"
    status[nl.index] = [_home_status(i, c) for i, c in zip(nl["ip"], nl["cred"])]
    act["witness"] = status
    act["external_ip"] = act["ip"].map(lambda i: bool(i) and (i not in internal) and (i not in link))

    stats = (
        act[act["link_expected"]].groupby(["entity", "cred", "witness"]).size().unstack(fill_value=0).reset_index()
        if le.any() else pd.DataFrame()
    )

    findings = []
    off = act[act["witness"] == "OFF_LINK"]
    for (cred, ip, day), g in off.groupby(["cred", "ip", off["ts"].dt.date]):
        findings.append(dict(
            module="witness", category="detection", severity=80,
            title="Link-only integration identity used off the private link",
            ts_first=g["ts"].min(), ts_last=g["ts"].max(), entity=g["entity"].iloc[0], cred=cred, ip=ip,
            refs=list(g["ref"]),
            summary=f"{len(g)} {g['system'].iloc[0]} event(s) by {cred} from {ip or 'no address'}; this identity normally "
                    f"acts only from {', '.join(cfg['link_cidrs'])} and no E15 flow can witness it.",
            details={"tokens": sorted(set(g["token"]))[:8], "user_agents": sorted(set(g["ua"]) - {""})},
        ))
    nh = act[act["witness"] == "NEW_LINK_HOST"]
    for (cred, ip, day), g in nh.groupby(["cred", "ip", nh["ts"].dt.date]):
        lab = host_label.get(ip, "")
        findings.append(dict(
            module="witness", category="detection", severity=78,
            title="New host speaking for a link integration",
            ts_first=g["ts"].min(), ts_last=g["ts"].max(), entity=g["entity"].iloc[0], cred=cred, ip=ip,
            refs=list(g["ref"]),
            summary=f"{len(g)} {g['system'].iloc[0]} event(s) by {cred} from {ip}, inside the link range but not one of the "
                    f"{len(roster.get(g['entity'].iloc[0], []))} hosts that carry this integration day to day"
                    + (f"; the vendor's flow log labels it '{lab}'" if lab else "; the flow log has no label for it") + ".",
            details={"tokens": sorted(set(g["token"]))[:8], "flow_label": lab},
        ))
    un = act[act["witness"] == "UNWITNESSED"]
    for (cred, day), g in un.groupby(["cred", un["ts"].dt.date]):
        findings.append(dict(
            module="witness", category="detection", severity=55 if len(g) < 5 else 62,
            title="Link address claimed but the flow log never saw it",
            ts_first=g["ts"].min(), ts_last=g["ts"].max(), entity=g["entity"].iloc[0], cred=cred,
            ip=",".join(sorted(set(g["ip"]))), refs=list(g["ref"]),
            summary=f"{len(g)} on-link event(s) by {cred} with no E15 flow within {tol}s. Either a spoofed/NATed source or a gap in "
                    f"the vendor-supplied flow log.",
            details={"tokens": sorted(set(g["token"]))[:8]},
        ))
    oh = act[(act["witness"] == "OFF_HOME")]
    for (cred, ip), g in oh.groupby(["cred", "ip"]):
        ext = bool(g["external_ip"].iloc[0])
        if not ident.is_credential(cred):
            continue  # people roam (remote staff, travel); this module judges software credentials only
        findings.append(dict(
            module="witness", category="detection", severity=70 if ext else 40,
            title="Credential used outside its home network",
            ts_first=g["ts"].min(), ts_last=g["ts"].max(), entity=g["entity"].iloc[0], cred=cred, ip=ip,
            refs=list(g["ref"]),
            summary=f"{len(g)} event(s) by {cred} from {ip} ({'external' if ext else 'internal, unusual subnet'}).",
            details={"tokens": sorted(set(g["token"]))[:8]},
        ))

    # legacy / dormant credentials that are still being used
    for cred, m in ident.meta.items():
        used = act[act["cred"].str.lower() == cred.lower()]
        if used.empty:
            continue
        status_txt = f"{m.get('status', '')} {m.get('notes', '')} {m.get('integration', '')}".lower()
        legacy = "legacy" in status_txt or "deprecat" in status_txt or "retired" in status_txt
        last_used = pd.to_datetime(m.get("last_used", ""), errors="coerce")
        dormant = pd.notna(last_used) and (used["ts"].min() - last_used).days > cfg["dormant_days"]
        if legacy or dormant:
            findings.append(dict(
                module="witness", category="detection", severity=78,
                title="Legacy / dormant credential still accepted and used",
                ts_first=used["ts"].min(), ts_last=used["ts"].max(), entity=m["entity"], cred=cred,
                ip=",".join(sorted(set(used["ip"]))[:4]), refs=list(used["ref"]),
                summary=f"E04 marks {cred} as {'legacy' if legacy else 'dormant'} (last_used={m.get('last_used', '?')}) "
                        f"yet {len(used)} call(s) were accepted.",
                details={"tokens": sorted(set(used["token"]))[:8]},
            ))

    info = dict(tolerance_s=tol, witness_rate=rate, coverage=cov, link_entities=sorted(link_entities),
                link_hosts={k: sorted(v) for k, v in roster.items()}, host_labels=host_label)
    return act, findings, stats, info
