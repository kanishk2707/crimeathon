"""Least-privilege policy generator ("shrink-wrap").

E04 grants the TallyBridge keys 'read:write all-modules' and 'admin'. What does the
sync actually need? Learn it from witnessed behaviour in the first half of the
evidence (actions, hosts, hours), then REPLAY the second half through that policy:

  * attacker requests it would have refused  (prevention, not just detection)
  * genuine requests it would have refused   (the cost of the policy)

Learning and testing on different months keeps the replay honest.
"""
from __future__ import annotations

import pandas as pd

from .util import circ_mean_std


def _fmt_window(lo: float, hi: float) -> str:
    f = lambda m: f"{int(m // 60) % 24:02d}:{int(m % 60):02d}"
    return f"{f(lo)}–{f(hi)} UTC"


def run(la: pd.DataFrame, winfo: dict, ident, flagged: set, cfg) -> dict:
    if la is None or la.empty:
        return {"rows": [], "split": None}
    t0, t1 = la["ts"].min(), la["ts"].max()
    split = pd.Timestamp(cfg["policy_train_until"]) if cfg.get("policy_train_until") else t0 + (t1 - t0) / 2
    rows = []
    for cred, g in la.groupby("cred"):
        if cred not in ident.meta:
            continue
        train = g[(g["ts"] < split) & (g["trust"] == "trusted") & g["ok"]]
        if len(train) < 20:
            continue
        counts = train["token"].value_counts()
        days = train["ts"].dt.date.nunique()
        per_day = train.groupby("token")["ts"].agg(lambda x: x.dt.date.nunique())
        needed = sorted(per_day[per_day >= max(3, 0.2 * days)].index)
        hosts = sorted(set(train["ip"]))
        mins = (train["ts"].dt.hour * 60 + train["ts"].dt.minute).to_numpy(float)
        mean, std = circ_mean_std(mins)
        # window: observed spread around the circular mean, padded by 30 min
        d = ((mins - mean + 720) % 1440) - 720
        lo, hi = mean + d.min() - 30, mean + d.max() + 30

        def outside(ts):
            m = ts.dt.hour * 60 + ts.dt.minute
            dd = ((m - mean + 720) % 1440) - 720
            return (dd < (lo - mean)) | (dd > (hi - mean))

        test = g[g["ts"] >= split]
        why = pd.DataFrame({
            "action": ~test["token"].isin(needed),
            "host": ~test["ip"].isin(hosts),
            "hour": outside(test["ts"]),
        }, index=test.index)
        refused = why.any(axis=1)
        bad = test["ref"].isin(flagged)
        meta = ident.meta[cred]
        rows.append(dict(
            credential=cred, system=meta.get("system", ""), granted=meta.get("scope", ""),
            needed=needed, hosts=hosts, window=_fmt_window(lo, hi),
            attacker_requests=int(bad.sum()), attacker_refused=int((refused & bad).sum()),
            genuine_requests=int((~bad).sum()), genuine_refused=int((refused & ~bad).sum()),
            genuine_refused_tokens=sorted(set(test.loc[refused & ~bad, "token"]))[:4],
            refused_by_action=int((why["action"] & bad).sum()), refused_by_host=int((why["host"] & bad).sum()),
            refused_by_hour=int((why["hour"] & bad).sum()),
        ))
    return {"rows": rows, "split": split}
