"""Double-entry integration ledger.

Idea: a sync service is bookkeeping. Every record it READS from one system is a
debit that must be balanced by a WRITE into the partner system (the credit),
shortly afterwards, by the same entity. What a sync reads and never writes
anywhere we own has left the building: it goes to the *suspense account*.

Also posted to suspense: anything the integration does outside its learned
vocabulary (endpoints/actions that legitimate, witnessed sync sessions never use,
e.g. vendor bank details, payment search, export jobs).

The 'exchange rate' between debit units and credit units is learned from
trusted (witnessed) sessions, so it works whether the partner logs records,
rows or one event per page.
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd


def build_sessions(act: pd.DataFrame, gap_min: int) -> pd.DataFrame:
    a = act.sort_values(["cred", "ip", "ts"]).copy()
    new = (a["cred"] != a["cred"].shift()) | (a["ip"] != a["ip"].shift()) | (
        (a["ts"] - a["ts"].shift()) > pd.Timedelta(minutes=gap_min)
    )
    a["sid"] = new.cumsum().astype(int)
    return a


def session_table(a: pd.DataFrame) -> pd.DataFrame:
    def trust(g):
        w = g["witness"]
        if (w.isin(["WITNESSED", "HOME"])).mean() >= 0.8:
            return "trusted"
        if (w == "NO_COVERAGE").all():
            return "provisional"
        return "untrusted"

    rows = []
    for sid, g in a.groupby("sid", sort=False):
        g = g.sort_values("ts")
        rows.append(dict(
            sid=sid, cred=g["cred"].iloc[0], entity=g["entity"].iloc[0], system=g["system"].iloc[0],
            ip=g["ip"].iloc[0], start=g["ts"].iloc[0], end=g["ts"].iloc[-1], n=len(g),
            tokens=list(g["token"]), trust=trust(g),
            uas=sorted(set(g["ua"]) - {""}),
        ))
    return pd.DataFrame(rows)


def learn_vocab(a: pd.DataFrame, sess: pd.DataFrame, min_share: float) -> dict:
    vocab = {}
    for cred, s in sess.groupby("cred"):
        base = s[s["trust"] == "trusted"]
        if len(base) < 3:
            base = s[s["trust"].isin(["trusted", "provisional"])]
        if len(base) < 3:
            vocab[cred] = None  # unknown: cannot judge vocabulary
            continue
        counts = {}
        for toks in base["tokens"]:
            for t in set(toks):
                counts[t] = counts.get(t, 0) + 1
        vocab[cred] = {t for t, c in counts.items() if c / len(base) >= min_share}
    return vocab


def run(act: pd.DataFrame, ident, cfg, announced=None):
    sens = re.compile(cfg["sensitive_token_regex"], re.I)
    integ = act[act["link_expected"] | act["entity"].map(ident.is_external)].copy()
    if integ.empty:
        return pd.DataFrame(), pd.DataFrame(), [], {}
    a = build_sessions(integ, cfg["session_gap_minutes"])
    sess = session_table(a)
    vocab = learn_vocab(a, sess, cfg["vocab_min_session_share"])

    a["in_vocab"] = [
        (vocab.get(c) is None) or (t in vocab[c]) for c, t in zip(a["cred"], a["token"])
    ]
    a["is_export"] = a["op"].str.startswith("export")
    a["debit"] = np.where((a["op"] == "read") & a["in_vocab"] & a["ok"], a["records"], 0.0)
    a["creditable_write"] = (a["op"] == "write") & a["in_vocab"] & a["ok"]
    a["suspense"] = ~a["in_vocab"] | a["is_export"]

    trust_of = dict(zip(sess["sid"], sess["trust"]))
    a["trust"] = a["sid"].map(trust_of)
    lag = pd.Timedelta(minutes=cfg["credit_lag_minutes"])

    # partner credit pools: writes into a *different* system by the same entity
    consumed = pd.Series(False, index=a.index)
    sess = sess.copy()
    sess["debit"] = a.groupby("sid")["debit"].sum().reindex(sess["sid"]).to_numpy()
    sess["credit"] = 0.0
    order = sess.assign(_o=sess["trust"].map({"trusted": 0, "provisional": 1, "untrusted": 2})).sort_values(["_o", "start"])
    writes = a[a["creditable_write"]]
    # a balance can only be judged while the partner system's log is running
    cov = act.groupby("system")["ts"].agg(["min", "max"])
    ent_systems = a.groupby("entity")["system"].agg(lambda x: set(x)).to_dict()
    sess["covered"] = True
    for i, s in sess.iterrows():
        partners = ent_systems.get(s["entity"], set()) - {s["system"]}
        if not partners:
            sess.at[i, "covered"] = False
            continue
        for p in partners:
            if p not in cov.index or s["start"] < cov.at[p, "min"] or s["end"] + lag > cov.at[p, "max"]:
                sess.at[i, "covered"] = False
    # Posting: each partner write is credited to the nearest *preceding* read of the same entity in
    # another system (within the lag), preferring reads from witnessed sessions. No greedy windows,
    # so a rogue session sitting next to the real sync cannot swallow the sync's credits.
    debits = a[a["debit"] > 0]
    credit_by_sid = {}
    lag_ns = lag.value
    for ent, w in writes.groupby("entity"):
        d_ent = debits[debits["entity"] == ent]
        if d_ent.empty:
            continue
        for sysname, w_sys in w.groupby("system"):
            cand = d_ent[d_ent["system"] != sysname].sort_values("ts")
            if cand.empty:
                continue
            c_ts = cand["ts"].values.astype("datetime64[ns]").astype(np.int64)
            c_sid = cand["sid"].to_numpy()
            c_trusted = (cand["trust"] == "trusted").to_numpy()
            for idx, wt, rec in zip(w_sys.index, w_sys["ts"].values.astype("datetime64[ns]").astype(np.int64), w_sys["records"]):
                hi = np.searchsorted(c_ts, wt, side="right")
                lo = np.searchsorted(c_ts, wt - lag_ns, side="left")
                if hi <= lo:
                    continue
                window = np.arange(lo, hi)
                tw = window[c_trusted[window]]
                j = (tw[-1] if len(tw) else window[-1])
                credit_by_sid[c_sid[j]] = credit_by_sid.get(c_sid[j], 0.0) + float(rec)
                consumed[idx] = True
    sess["credit"] = sess["sid"].map(credit_by_sid).fillna(0.0)
    a["consumed"] = consumed

    base = sess[(sess["trust"] == "trusted") & (sess["debit"] > 0)]
    if len(base) >= 3:
        r = (base["credit"] / base["debit"]).to_numpy()
        med = float(np.median(r))
        mad = float(np.median(np.abs(r - med))) * 1.4826
        low = med - max(4 * mad, 0.3 * med)
    else:
        med, mad, low = None, None, None
    sess["ratio"] = np.where(sess["debit"] > 0, sess["credit"] / sess["debit"].replace(0, np.nan), np.nan)
    rate_info = dict(median_ratio=med, mad=mad, low=low, trusted_sessions=int(len(base)))

    findings, suspense_rows = [], []
    for _, s in sess.iterrows():
        g = a[a["sid"] == s["sid"]]
        untrusted = s["trust"] == "untrusted"
        sus = g[g["suspense"]]
        if len(sus) and announced:
            ann = pd.Series(False, index=sus.index)
            for an in announced:
                m = sus["token"].str.contains(an.get("token_regex", "$^"), regex=True, case=False)
                if an.get("cred"):
                    m &= sus["cred"].str.lower() == an["cred"].lower()
                if an.get("from"):
                    m &= sus["ts"] >= pd.Timestamp(an["from"])
                if m.any():
                    ann |= m
                    hit = sus[m]
                    findings.append(dict(
                        module="ledger", category="change-control", severity=50,
                        title="Announced vendor behaviour change, never reviewed",
                        ts_first=hit["ts"].min(), ts_last=hit["ts"].max(), entity=s["entity"], cred=s["cred"], ip=s["ip"],
                        refs=list(hit["ref"]),
                        summary=f"{len(hit)} x {', '.join(sorted(set(hit['token'])))} by {s['cred']}: new behaviour announced in "
                                f"{an.get('source', 'a vendor notice')}. Outside the learned sync ledger; needs a change review, "
                                f"not an incident page.",
                        details={"announced": an.get("source", "")},
                    ))
            sus = sus[~ann]
        if len(sus):
            toks = sorted(set(sus["token"]))
            sensitive = any(sens.search(t) for t in toks)
            if s["trust"] == "trusted" and not sensitive:
                sev = 45
            else:
                sev = 60 + (20 if sensitive else 0) + (10 if untrusted else 0)
            findings.append(dict(
                module="ledger", category="detection", severity=min(sev, 95),
                title="Suspense: integration activity with no place in the sync ledger",
                ts_first=sus["ts"].min(), ts_last=sus["ts"].max(), entity=s["entity"], cred=s["cred"], ip=s["ip"],
                refs=list(sus["ref"]),
                summary=f"{len(sus)} event(s) by {s['cred']} ({s['trust']} session from {s['ip'] or 'no address'}) use "
                        f"{len(toks)} action(s) that witnessed sync sessions never use: {', '.join(toks[:5])}"
                        f"{' ...' if len(toks) > 5 else ''}. Records touched: {int(sus['records'].sum())}.",
                details={"tokens": toks[:10], "records": int(sus["records"].sum()), "session_trust": s["trust"]},
            ))
            suspense_rows.append(dict(kind="out-of-vocabulary", entity=s["entity"], cred=s["cred"], ip=s["ip"],
                                      start=s["start"], end=s["end"], debit=float(sus["records"].sum()), credit=0.0,
                                      trust=s["trust"], tokens=", ".join(toks[:4])))
        if med is not None and s["covered"] and s["debit"] > 0 and s["ratio"] < low:
            dg = g[g["debit"] > 0]
            findings.append(dict(
                module="ledger", category="detection", severity=70 + (10 if untrusted else 0),
                title="Unbalanced: data read by the sync was never written to the partner system",
                ts_first=s["start"], ts_last=s["end"], entity=s["entity"], cred=s["cred"], ip=s["ip"],
                refs=list(dg["ref"]),
                summary=f"Session debited {int(s['debit'])} records from {s['system']} but only {int(s['credit'])} credit units "
                        f"appeared in the partner system (learned exchange rate {med:.2f}, floor {low:.2f}, this session "
                        f"{(s['ratio'] if not np.isnan(s['ratio']) else 0):.2f}).",
                details={"debit": int(s["debit"]), "credit": int(s["credit"]), "session_trust": s["trust"]},
            ))
            suspense_rows.append(dict(kind="unbalanced read", entity=s["entity"], cred=s["cred"], ip=s["ip"],
                                      start=s["start"], end=s["end"], debit=float(s["debit"]), credit=float(s["credit"]),
                                      trust=s["trust"], tokens=", ".join(sorted(set(dg["token"]))[:4])))
        # orphan writes: creditable writes in an untrusted session that no debit explains
        if untrusted and s["covered"]:
            orphan = g[g["creditable_write"] & ~g["consumed"]]
            if len(orphan):
                findings.append(dict(
                    module="ledger", category="detection", severity=65,
                    title="Orphan write: data pushed in with no source read",
                    ts_first=orphan["ts"].min(), ts_last=orphan["ts"].max(), entity=s["entity"], cred=s["cred"],
                    ip=s["ip"], refs=list(orphan["ref"]),
                    summary=f"{len(orphan)} write(s) into {s['system']} by {s['cred']} from an untrusted session with no "
                            f"matching read in the partner system.",
                    details={"tokens": sorted(set(orphan["token"]))[:6]},
                ))
    return a, sess, findings, dict(rate_info, vocab={k: sorted(v) if v else None for k, v in vocab.items()},
                                   suspense=suspense_rows)
