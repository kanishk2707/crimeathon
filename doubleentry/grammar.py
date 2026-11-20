"""Sync grammar: one key, two personalities.

A machine sync speaks a tiny, regular language: the same endpoints in the same
order, at roughly the same time of night, with a client version that only ever
moves forward. We learn that language from *witnessed* sessions only (the
witness module labels the training data, so nothing is hand-labelled), then
score every session by how badly it fails to parse:

  novel tokens       endpoints/actions the sync never uses
  novel bigrams      transitions the sync never makes
  start-time drift   circular z-score of session start (weak signal)
  version regression client version older than one the fleet already moved to
  product mismatch   a different client product on the same key
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd

from .util import circ_diff, circ_mean_std, ua_parts


def _bigrams(toks):
    return list(zip(toks, toks[1:]))


def _ua_model(a: pd.DataFrame):
    """Per credential: when each client version was first seen in trusted traffic,
    and the dominant product name."""
    model = {}
    tr = a[a["witness"].isin(["WITNESSED", "HOME", "NO_COVERAGE"]) & (a["ua"] != "")]
    for cred, g in tr.groupby("cred"):
        parts = g["ua"].map(ua_parts)
        prods = parts.map(lambda p: p[0])
        vers = parts.map(lambda p: p[1])
        first = {}
        for ts, v in zip(g["ts"], vers):
            if v and v not in first:
                first[v] = ts
        model[cred] = dict(product=prods.mode().iloc[0] if len(prods) else "", first=first)
    return model


def _ua_flags(cred, ua, ts, model):
    m = model.get(cred)
    if not m or not ua:
        return []
    prod, ver = ua_parts(ua)
    flags = []
    if m["product"] and prod and prod != m["product"]:
        flags.append(f"client product '{prod}' differs from the fleet's '{m['product']}'")
    if ver:
        newer = [v for v, t in m["first"].items() if v > ver and t + pd.Timedelta(days=1) < ts]
        if newer:
            flags.append(f"version {'.'.join(map(str, ver))} after fleet moved to {'.'.join(map(str, max(newer)))}")
        if ver in m["first"] and ts < m["first"][ver] - pd.Timedelta(hours=1):
            flags.append(f"version {'.'.join(map(str, ver))} seen before the fleet adopted it")
        if ver not in m["first"] and m["first"]:
            flags.append(f"version {'.'.join(map(str, ver))} never seen in trusted traffic")
    return flags


def run(a: pd.DataFrame, sess: pd.DataFrame, cfg, announced=None):
    if a is None or a.empty:
        return pd.DataFrame(), []
    ua_model = _ua_model(a)
    models = {}
    for cred, s in sess.groupby("cred"):
        base = s[s["trust"] == "trusted"]
        if len(base) < 5:
            base = s[s["trust"].isin(["trusted", "provisional"])]
        if len(base) < 5:
            continue
        tok_share, bi_count = {}, {}
        for toks in base["tokens"]:
            for t in set(toks):
                tok_share[t] = tok_share.get(t, 0) + 1
            for b in set(_bigrams(toks)):
                bi_count[b] = bi_count.get(b, 0) + 1
        n = len(base)
        tok_share = {t: c / n for t, c in tok_share.items()}
        min_bi = max(cfg["bigram_min_sessions"], int(0.05 * n))
        known_bi = {b for b, c in bi_count.items() if c >= min_bi}
        mean, std = circ_mean_std((base["start"].dt.hour * 60 + base["start"].dt.minute).to_numpy(float))
        models[cred] = dict(tok_share=tok_share, known_bi=known_bi, start_mean=mean, start_std=max(std, 15.0), n=n)

    rows, findings = [], []
    first_row = a.sort_values("ts").groupby("sid").first()
    for _, s in sess.iterrows():
        m = models.get(s["cred"])
        if m is None:
            continue
        toks = s["tokens"]
        for an in announced or []:
            if (not an.get("cred") or an["cred"].lower() == str(s["cred"]).lower()) and (
                    not an.get("from") or s["start"] >= pd.Timestamp(an["from"])):
                toks = [t for t in toks if not re.search(an.get("token_regex", "$^"), t, re.I)]
        if not toks:
            continue  # the whole session is announced behaviour: change control, not an incident
        novel_t = sorted({t for t in toks if m["tok_share"].get(t, 0) < 0.05})
        bis = _bigrams(toks)
        nov_bi = (sum(b not in m["known_bi"] for b in bis) / len(bis)) if bis else (1.0 if novel_t else 0.0)
        z = circ_diff(s["start"].hour * 60 + s["start"].minute, m["start_mean"]) / m["start_std"]
        g = a[a["sid"] == s["sid"]]
        ua_fl = sorted({f for ua, ts in zip(g["ua"], g["ts"]) for f in _ua_flags(s["cred"], ua, ts, ua_model)})
        score = (35 if novel_t else 0) + 40 * min(1.0, nov_bi) + (10 if z > 3 else 0) + (25 if ua_fl else 0) + (
            10 if s["trust"] == "untrusted" else 0)
        score = min(100, round(score))
        rows.append(dict(sid=s["sid"], cred=s["cred"], ip=s["ip"], start=s["start"], n=s["n"], trust=s["trust"],
                         novel_tokens=len(novel_t), novel_bigram_frac=round(nov_bi, 2), start_z=round(z, 1),
                         ua_flags="; ".join(ua_fl), score=score))
        if score >= cfg["alert_threshold"]:
            reasons = []
            if novel_t:
                reasons.append(f"{len(novel_t)} unknown action(s): {', '.join(novel_t[:4])}")
            if nov_bi:
                reasons.append(f"{nov_bi:.0%} of transitions never made by the sync")
            if z > 3:
                reasons.append(f"started {z:.1f} sd away from the usual sync time")
            reasons += ua_fl
            findings.append(dict(
                module="grammar", category="detection", severity=int(score),
                title="Session does not parse as the sync's grammar",
                ts_first=s["start"], ts_last=s["end"], entity=s["entity"], cred=s["cred"], ip=s["ip"],
                refs=list(g["ref"]),
                summary=f"{s['n']}-event session by {s['cred']} from {s['ip'] or 'no address'} ({s['trust']}): " + "; ".join(reasons) + ".",
                details={"score": int(score), "ua_flags": ua_fl},
            ))
    return pd.DataFrame(rows), findings
