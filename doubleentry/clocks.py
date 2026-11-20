"""Clock-agreement solver.

Systems that never synchronised their clocks (BlueVault) or that log in local
time (HelpDeskr) are aligned by finding events that must co-occur: the same
source address talking to two systems within seconds (e.g. the backup agent
pulls from LedgerOne then writes to BlueVault). The offset is the mode of the
nearest-neighbour time differences. No hard-coded skew: it works on data with a
different skew.
"""
from __future__ import annotations

import numpy as np
import pandas as pd


def _nearest_deltas(x: pd.DataFrame, ref: pd.DataFrame, window_s: float, max_pairs: int = 2_000_000) -> np.ndarray:
    """Cross-correlation: every (x, ref) pair from the same address within +-window.
    The true offset shows up as a spike; unrelated pairs spread out evenly. Unlike
    nearest-neighbour matching this still works when the skew exceeds the spacing
    between events."""
    out, total = [], 0
    ref = ref[(ref["ip"] != "") & ref["ts"].notna()]
    x = x[(x["ip"] != "") & x["ts"].notna()]
    groups = {ip: np.sort(g["ts"].values.astype("datetime64[ns]").astype(np.int64)) for ip, g in ref.groupby("ip")}
    w = int(window_s * 1e9)
    for ip, g in x.groupby("ip"):
        r = groups.get(ip)
        if r is None or len(r) == 0:
            continue
        xs = np.sort(g["ts"].values.astype("datetime64[ns]").astype(np.int64))
        lo = np.searchsorted(r, xs - w, side="left")
        hi = np.searchsorted(r, xs + w, side="right")
        for xv, a, b in zip(xs, lo, hi):
            if b > a:
                out.append((xv - r[a:b]) / 1e9)
                total += b - a
                if total > max_pairs:
                    break
    return np.concatenate(out) if out else np.array([])


def estimate_offset(x: pd.DataFrame, ref: pd.DataFrame, window_s: float = 900, min_pairs: int = 20):
    """Return (offset_seconds, support, spread) where x_clock = true + offset."""
    d = _nearest_deltas(x, ref, window_s)
    if len(d) < min_pairs:
        return None, int(len(d)), None
    bins = np.round(d / 10.0) * 10.0
    vals, counts = np.unique(bins, return_counts=True)
    k = np.argmax(counts)
    mode = vals[k]
    background = np.median(counts)
    if counts[k] < 3 * max(background, 1) or counts[k] < min_pairs // 2:
        return None, int(len(d)), None  # no clear spike: refuse to guess
    near = d[np.abs(d - mode) <= 10]
    return float(np.median(near)), int(counts[k]), float(np.std(near))


def align(ev) -> list:
    """Align BlueVault to UTC and verify every other source. Returns a table of
    clock-agreement rows for the report."""
    cfg = ev.cfg
    rows = []
    parts = [ev.api[["ts", "ip"]], ev.flows.rename(columns={"src_ip": "ip"})[["ts", "ip"]]]
    if len(ev.hd):
        parts.append(ev.hd[["ts", "ip"]])
    ref = pd.concat(parts, ignore_index=True)

    # BlueVault: unsynchronised epoch clock
    skew = cfg.get("bluevault_skew_seconds")
    if len(ev.bv):
        if skew is None:
            est, sup, spread = estimate_offset(pd.DataFrame({"ts": ev.bv["ts_raw"], "ip": ev.bv["ip"]}), ref)
            if est is not None:
                skew = est
                rows.append(dict(source="E05 BlueVault", basis="epoch (never synced)", offset_s=round(est, 1),
                                 support=sup, verdict=f"estimated: clock runs {abs(est):.0f}s {'fast' if est > 0 else 'slow'}; corrected"))
            else:
                skew = 0.0
                rows.append(dict(source="E05 BlueVault", basis="epoch (never synced)", offset_s=None, support=sup,
                                 verdict="could not estimate (too few co-occurring events) - left uncorrected"))
        else:
            rows.append(dict(source="E05 BlueVault", basis="epoch (never synced)", offset_s=skew, support=None,
                             verdict="offset supplied in config"))
        ev.bv["ts"] = ev.bv["ts_raw"] - pd.Timedelta(seconds=float(skew))
    ev.bluevault_skew = skew

    # HelpDeskr: verify that the IST->UTC conversion agrees with network flows
    if len(ev.hd) and len(ev.flows):
        est, sup, _ = estimate_offset(ev.hd[["ts", "ip"]], ev.flows.rename(columns={"src_ip": "ip"})[["ts", "ip"]], window_s=1800)
        if est is None:
            # flows may be one-per-session: compare the daily start of link-host activity instead
            link = ev.cfg["link_cidrs"][0].rsplit(".", 2)[0] if ev.cfg["link_cidrs"] else "10.20"
            h = ev.hd[ev.hd["ip"].str.startswith(link)]
            a = ev.api[ev.api["ip"].str.startswith(link)]
            if len(h) and len(a):
                dh, da = h.groupby(h["ts"].dt.date)["ts"].min(), a.groupby(a["ts"].dt.date)["ts"].min()
                both = dh.index.intersection(da.index)
                if len(both) >= 10:
                    est = float(np.median((dh[both] - da[both]).dt.total_seconds()))
                    sup = int(len(both))
        if est is None:
            verdict = "no co-occurring events to verify"
        elif abs(est) < 120:
            verdict = "agrees with E15 after IST->UTC conversion"
        else:
            verdict = f"DISAGREES by {est:.0f}s - check tenant time zone"
        rows.append(dict(source="E02 HelpDeskr", basis="tenant local (IST, UTC+5:30)", offset_s=None if est is None else round(est, 1),
                         support=sup, verdict=verdict))
    for code, label in (("E01", "E01 LedgerOne API"), ("E18", "E18 LedgerOne API (Sep)")):
        part = ev.api[ev.api["src"] == code]
        if len(part) and len(ev.flows):
            est, sup, _ = estimate_offset(part[["ts", "ip"]], ev.flows.rename(columns={"src_ip": "ip"})[["ts", "ip"]], window_s=600)
            if est is None:
                verdict = "outside E15 coverage - cannot cross-check" if code == "E18" else "no co-occurring events to verify"
            else:
                verdict = "agrees with E15" if abs(est) < 60 else f"DISAGREES by {est:.0f}s"
            rows.append(dict(source=label, basis="UTC", offset_s=None if est is None else round(est, 1), support=sup, verdict=verdict))
    return rows
