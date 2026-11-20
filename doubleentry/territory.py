"""BlueVault territory.

Each principal has a territory: the folders it touches week after week from its
home networks. A read of new territory from a blank or foreign address is the
pivot signature (e.g. a customer-portal access key, leaked in a ticket, reading
/finance/bank-instructions). Runs on clock-corrected BlueVault time.
"""
from __future__ import annotations

import re

import pandas as pd

from .util import NetSet, bare, net24, norm_ep


def _prefix(path: str, depth: int = 2) -> str:
    """'/customers/C0123/docs/x.pdf' -> '/customers/{id}' ; '/finance/statements/2026-07.pdf' -> '/finance/statements'"""
    segs = [s for s in norm_ep(str(path).replace("\\", "/")).split("/") if s]
    return "/" + "/".join(segs[:depth]) if segs else "/"


def run(ev, cfg):
    bv = ev.bv.copy()
    if bv.empty:
        return [], {}
    sens = re.compile(r"financ|bank|payment|payee|statement|vendor", re.I)
    link, internal = NetSet(cfg["link_cidrs"]), NetSet(cfg["internal_cidrs"])
    bv["prefix"] = bv["path"].map(_prefix)
    bv["net"] = bv["ip"].map(net24)
    bv["week"] = bv["ts"].dt.to_period("W")
    findings, terr = [], {}
    people = set(ev.roster["username"]) if len(ev.roster) else set()
    for p, g in bv.groupby("principal"):
        nets = g.loc[g["net"] != "", "net"].value_counts(normalize=True)
        home = set(nets[nets >= cfg["home_net_min_share"]].index)
        hg = g[g["net"].isin(home)]
        weeks = hg.groupby("prefix")["week"].nunique()
        territory = set(weeks[weeks >= cfg["territory_min_weeks"]].index)
        terr[p] = dict(home=sorted(home), territory=sorted(territory))
        if not territory:
            continue  # too little history to judge this principal
        g = g.assign(new_terr=~g["prefix"].isin(territory),
                     blank=g["ip"] == "",
                     foreign=(g["ip"] != "") & ~g["net"].isin(home),
                     external=g["ip"].map(lambda i: bool(i) and i not in internal and i not in link))
        person = bare(p) in people
        odd = g[g["new_terr"] & (g["external"] if person else (g["blank"] | g["foreign"]))]
        for day, d in odd.groupby(odd["ts"].dt.date):
            if person and not d["foreign"].any():
                continue  # people + blank address only: E05 is known to drop addresses
            sev = 40 + (15 if d["prefix"].str.contains(sens).any() else 0) + (
                30 if d["external"].any() else 10 if d["foreign"].any() else 5)  # software key, no address at all: weakest
            findings.append(dict(
                module="territory", category="detection", severity=min(sev, 95),
                title="Storage key reading outside its territory",
                ts_first=d["ts"].min(), ts_last=d["ts"].max(), entity=p, cred=p,
                ip=", ".join(sorted(set(d["ip"].replace("", "(blank)")))), refs=list(d["ref"]),
                summary=f"{len(d)} BlueVault {'/'.join(sorted(set(d['action'])))} by {p} under "
                        f"{', '.join(sorted(set(d['prefix'])))} - folders it never uses - from "
                        f"{', '.join(sorted(set(d['ip'].replace('', 'no address'))))}. {int(d['bytes'].sum()):,} bytes.",
                details={"paths": sorted(set(d["path"]))[:6]},
            ))
    return findings, terr
