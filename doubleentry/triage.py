"""Triage: time-to-money weighting, incident threads, and a daily alert budget.

A small team (one acting security owner) cannot read 200 alerts. Findings are
weighted by how close the next payment run is, joined into threads that share a
credential or an outside address, and capped at N paged alerts per day.
"""
from __future__ import annotations

import pandas as pd

from .util import NetSet


def assemble(findings: list, runs: list, ident, cfg) -> pd.DataFrame:
    if not findings:
        return pd.DataFrame(columns=["fid", "module", "category", "severity", "title", "ts_first", "alert", "thread"])
    df = pd.DataFrame(findings)
    df["ts_first"] = pd.to_datetime(df["ts_first"])
    df["ts_last"] = pd.to_datetime(df["ts_last"])
    df = df.sort_values(["ts_first", "severity"], ascending=[True, False]).reset_index(drop=True)
    df["fid"] = [f"F{i + 1:03d}" for i in range(len(df))]

    def days_to_run(t):
        nxt = next((r for r in runs if r > t), None) if pd.notna(t) else None
        return (nxt - t).total_seconds() / 86400 if nxt is not None else None

    df["days_to_run"] = df["ts_first"].map(days_to_run)
    boost = df["days_to_run"].map(lambda d: 1.1 if d is not None and d <= 3 else 1.0)
    df["base_severity"] = df["severity"]
    df["severity"] = (df["severity"] * boost).clip(upper=100).round().astype(int)
    df["alert"] = (df["category"] == "detection") & (df["severity"] >= cfg["alert_threshold"])

    # daily budget
    df["paged"] = False
    for day, g in df[df["alert"]].groupby(df["ts_first"].dt.date):
        top = g.sort_values("severity", ascending=False).head(cfg["alert_budget_per_day"]).index
        df.loc[top, "paged"] = True

    # threads (union-find on shared credential / outside address / evidence rows)
    link, internal = NetSet(cfg["link_cidrs"]), NetSet(cfg["internal_cidrs"])
    parent = list(range(len(df)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        a, b = find(i), find(j)
        if a != b:
            parent[b] = a

    keys = {}
    for i, f in df.iterrows():
        if not f["alert"] and f["category"] != "governance":
            continue
        tags = set()
        ent = f.get("entity", "")
        if ent and ident.is_external(ent):
            tags.add(("ent", ent))
        cred = f.get("cred", "")
        if cred:
            tags.add(("cred", cred))
        for ip in str(f.get("ip", "")).split(","):
            ip = ip.strip()
            if ip and ip != "(blank)" and ip not in internal and ip not in link:
                tags.add(("ip", ip))
        for t in tags:
            if t in keys:
                union(i, keys[t])
            else:
                keys[t] = i
    roots = {}
    df["thread"] = ""
    for i, f in df.iterrows():
        if not f["alert"]:
            continue
        r = find(i)
        roots.setdefault(r, f"T{len(roots) + 1}")
        df.at[i, "thread"] = roots[r]
    return df


def threads(df: pd.DataFrame) -> list:
    out = []
    for t, g in df[df["thread"] != ""].groupby("thread"):
        g = g.sort_values("ts_first")
        ents = sorted(set(g["entity"]) - {""})
        ips = sorted({ip.strip() for s in g["ip"] for ip in str(s).split(",") if ip.strip()})
        out.append(dict(
            thread=t, findings=len(g), max_severity=int(g["severity"].max()), first=g["ts_first"].min(),
            last=g["ts_last"].max(), entities=ents, ips=ips, modules=sorted(set(g["module"])),
            stages=list(dict.fromkeys(g["title"])), refs=sum(len(r) for r in g["refs"]),
        ))
    return sorted(out, key=lambda x: (-x["max_severity"], x["first"]))
