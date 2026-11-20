"""The OBVIOUS approach, implemented honestly so we can measure it.

Typical SIEM / UEBA starter rules, one log at a time:
  B1 off-hours activity with above-p95 volume for that actor
  B2 new source address for an actor (not seen in its first 14 days)
  B3 impossible travel (city change within 3 hours)
  B4 more than one export per actor per week
  B5 bulk vendor changes (>10 per actor per day)
  B6 global volume outliers (> p99 records/bytes)
  B7 bank-field change with no approval reference
"""
from __future__ import annotations

import re

import pandas as pd


def run(ev, act, cfg) -> set:
    flagged = set()
    # B1 off-hours (outside 08:30-19:00 IST) and heavy
    if len(act):
        ist = act["ts"] + pd.Timedelta(minutes=330)
        mins = ist.dt.hour * 60 + ist.dt.minute
        off = (mins < 8 * 60 + 30) | (mins >= 19 * 60)
        p95 = act.groupby("cred")["records"].transform(lambda x: x.quantile(0.95))
        flagged |= set(act.loc[off & (act["records"] > p95), "ref"])
        # B2 new address per actor
        first = act.groupby("cred")["ts"].transform("min")
        early = act[act["ts"] <= first + pd.Timedelta(days=14)]
        known = set(zip(early["cred"], early["ip"]))
        late = act[act["ts"] > first + pd.Timedelta(days=14)]
        flagged |= set(late.loc[[(c, i) not in known for c, i in zip(late["cred"], late["ip"])], "ref"])
        # B6 global outliers
        flagged |= set(act.loc[act["records"] > act["records"].quantile(0.99), "ref"])
    sso = ev.sso
    if len(sso):
        s = sso[sso["ok"]].sort_values(["user", "ts"])
        prev_city = s.groupby("user")["city"].shift()
        prev_ts = s.groupby("user")["ts"].shift()
        jump = (prev_city.notna()) & (s["city"] != prev_city) & ((s["ts"] - prev_ts) < pd.Timedelta(hours=3))
        flagged |= set(s.loc[jump, "ref"])
        first = s.groupby("user")["ts"].transform("min")
        early = s[s["ts"] <= first + pd.Timedelta(days=14)]
        known = set(zip(early["user"], early["ip"]))
        late = s[s["ts"] > first + pd.Timedelta(days=14)]
        flagged |= set(late.loc[[(u, i) not in known for u, i in zip(late["user"], late["ip"])], "ref"])
    # B4 exports per week
    if len(ev.hd):
        ex = act[act["op"] == "export_create"]
        wk = ex.groupby(["cred", ex["ts"].dt.to_period("W")])["ref"].transform("count")
        flagged |= set(ex.loc[wk > 1, "ref"])
    # B5 bulk vendor changes, B7 unapproved bank changes
    ch = ev.changes
    if len(ch):
        per_day = ch.groupby(["changed_by", ch["ts"].dt.date])["ref"].transform("count")
        flagged |= set(ch.loc[per_day > 10, "ref"])
        bank = ch["field"].str.contains(cfg["bank_field_regex"], flags=re.I, regex=True)
        noappr = ch["approval"].str.strip().str.lower().isin(cfg["approval_placeholders"])
        flagged |= set(ch.loc[bank & noappr, "ref"])
    if len(ev.bv):
        flagged |= set(ev.bv.loc[ev.bv["bytes"] > ev.bv["bytes"].quantile(0.99), "ref"])
    return flagged
