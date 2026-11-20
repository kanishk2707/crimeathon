"""Measure detection, false alarms and time-to-catch on labelled synthetic data,
for every attack variant, against the obvious-approach baseline."""
from __future__ import annotations

import json
from itertools import chain
from pathlib import Path

import pandas as pd

from . import baseline
from .engine import analyze, write_outputs
from .report import CSS, e
from .synth import VARIANTS, generate


def universe(res) -> set:
    ev = res["ev"]
    u = set(res["act"]["ref"])
    for df in (ev.bv, ev.sso, ev.changes):
        if len(df):
            u |= set(df["ref"])
    return u


def ours_flagged(res) -> set:
    f = res["findings"]
    if f.empty:
        return set()
    sel = f[(f["severity"] >= res["cfg"]["alert_threshold"]) & (f["module"] != "passport")]
    return set(chain.from_iterable(sel["refs"]))


def score(flagged: set, truth: dict, uni: set, findings: pd.DataFrame | None = None) -> dict:
    mal, gov = set(truth["malicious"]) & uni, set(truth["governance"]) & uni
    benign = uni - mal - gov
    tp, fp, fn = flagged & mal, (flagged & benign), mal - flagged
    out = dict(
        malicious=len(mal), flagged=len(flagged & uni), tp=len(tp), fp=len(fp), fn=len(fn),
        precision=round(len(tp) / max(1, len(tp) + len(fp)), 3), recall=round(len(tp) / max(1, len(mal)), 3),
        false_alarm_rate=round(len(fp) / max(1, len(benign)), 5), benign_events=len(benign),
        governance_found=f"{len(flagged & gov)}/{len(gov)}",
    )
    traps = {}
    for k, refs in truth["traps"].items():
        refs = set(refs) & uni
        traps[k] = f"{len(refs & flagged)}/{len(refs)}"
    out["traps"] = traps
    stages = {}
    for k, st in truth["stages"].items():
        refs = set(st["refs"]) & uni
        stages[k] = f"{len(refs & flagged)}/{len(refs)}"
    out["stages"] = stages
    out["stages_detected"] = f"{sum(1 for v in stages.values() if not v.startswith('0/'))}/{len(stages)}"
    if findings is not None and len(findings):
        sel = findings[(findings["severity"] >= 60) & (findings["module"] != "passport")]
        hit = sel[sel["refs"].map(lambda r: bool(set(r) & mal))]
        first_alert = hit["ts_first"].min() if len(hit) else None
        first_mal = min(pd.Timestamp(st["first"]) for st in truth["stages"].values()) if truth["stages"] else None
        money = [pd.Timestamp(m["run"]) + pd.Timedelta(hours=4, minutes=30) for m in truth["money"] if m["kind"].startswith("paid")]
        first_money = min(money) if money else None
        out["first_malicious"] = str(first_mal) if first_mal is not None else ""
        out["first_alert"] = str(first_alert) if first_alert is not None else "never"
        if first_alert is not None and first_mal is not None:
            out["hours_to_detect"] = round((first_alert - first_mal).total_seconds() / 3600, 1)
        if first_money is not None and first_alert is not None:
            out["caught_before_first_payout"] = bool(first_alert < first_money)
            out["lead_time_days"] = round((first_money - first_alert).total_seconds() / 86400, 1)
    return out


def money_check(res, truth) -> dict:
    v = res["vendors"]
    held = set(v.loc[v["verdict"].isin(["HOLD", "REVIEW-PAID"]), "vendor_id"]) if len(v) else set()
    target = set(chain.from_iterable(m["vendors"] for m in truth["money"]))
    false_hold = held - target
    return dict(target_vendors=len(target), held_or_flagged=len(held & target), missed=sorted(target - held),
                false_holds=sorted(false_hold))


def run(out: Path, variants=None, seeds=(7,), cfg=None, quiet=False):
    from .config import load_config
    cfg = cfg or load_config()
    out = Path(out)
    variants = variants or VARIANTS
    rows = []
    for v in variants:
        for seed in seeds:
            d = out / f"{v}_s{seed}"
            ev_dir = generate(d / "evidence", variant=v, seed=seed, bv_skew=180 + (seed * 37) % 240)
            truth = json.loads((ev_dir / "ground_truth.json").read_text(encoding="utf-8"))
            res = analyze(ev_dir, cfg)
            uni = universe(res)
            ours = score(ours_flagged(res), truth, uni, res["findings"])
            base = score(baseline.run(res["ev"], res["act"], cfg), truth, uni)
            money = money_check(res, truth)
            res["evaluation"] = _eval_block(v, seed, ours, base, money, res)
            write_outputs(res, d / "out")
            row = dict(variant=v, seed=seed, skew_true=180 + (seed * 37) % 240, skew_est=round(res["ev"].bluevault_skew or 0, 1),
                       ours=ours, baseline=base, money=money)
            rows.append(row)
            if not quiet:
                print(f"[{v} seed={seed}] ours P={ours['precision']} R={ours['recall']} FP={ours['fp']} stages={ours['stages_detected']} "
                      f"| baseline P={base['precision']} R={base['recall']} FP={base['fp']} | vendors held "
                      f"{money['held_or_flagged']}/{money['target_vendors']} false={len(money['false_holds'])}")
    (out / "evaluation.json").write_text(json.dumps(rows, indent=1, default=str), encoding="utf-8")
    (out / "evaluation.html").write_text(_summary_html(rows), encoding="utf-8")
    return rows


def _kv(d: dict) -> str:
    return "<br>".join(f"<span class='mono small'>{e(k)}</span>: {e(v)}" for k, v in d.items())


def _eval_block(v, seed, ours, base, money, res) -> str:
    keys = ["malicious", "flagged", "tp", "fp", "fn", "precision", "recall", "false_alarm_rate", "stages_detected", "governance_found"]
    h = [f"<h2>11 &middot; Evaluation against ground truth (variant <span class='mono'>{e(v)}</span>, seed {seed})</h2><div class='panel'><table>"
         "<thead><tr><th>Metric</th><th>Double-Entry Defense</th><th>Obvious approach (per-log rules)</th></tr></thead><tbody>"]
    for k in keys:
        h.append(f"<tr><td>{e(k)}</td><td><b>{e(ours.get(k))}</b></td><td>{e(base.get(k))}</td></tr>")
    h.append(f"<tr><td>ordinary-event traps flagged</td><td>{_kv(ours['traps'])}</td><td>{_kv(base['traps'])}</td></tr>")
    h.append(f"<tr><td>attack stages (events flagged / total)</td><td>{_kv(ours['stages'])}</td><td>{_kv(base['stages'])}</td></tr>")
    for k in ("first_malicious", "first_alert", "hours_to_detect", "caught_before_first_payout", "lead_time_days"):
        if k in ours:
            h.append(f"<tr><td>{e(k)}</td><td>{e(ours[k])}</td><td></td></tr>")
    h.append(f"<tr><td>vendors correctly held</td><td>{money['held_or_flagged']}/{money['target_vendors']} "
             f"(missed {e(money['missed']) or 'none'}; false holds {e(money['false_holds']) or 'none'})</td><td></td></tr>")
    h.append("</tbody></table></div>")
    return "".join(h)


def _summary_html(rows) -> str:
    h = [f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>Variation Test Results</title><style>{CSS}</style></head><body><main><h1>Variation test results</h1>"
         "<p class='sub'>Each variant is a different attack generated into fresh synthetic evidence, with a different BlueVault clock skew. "
         "The engine is not told which variant it is looking at.</p><div class='panel'><table><thead><tr>"
         "<th>Variant</th><th>Seed</th><th>Skew true / est.</th><th>Precision</th><th>Recall</th><th>False alarms</th><th>Stages</th>"
         "<th>Caught before payout</th><th>Vendors held</th><th>Baseline precision</th><th>Baseline recall</th><th>Baseline false alarms</th></tr></thead><tbody>"]
    for r in rows:
        o, b, m = r["ours"], r["baseline"], r["money"]
        h.append(f"<tr><td class='mono'>{e(r['variant'])}</td><td>{r['seed']}</td><td>{r['skew_true']} / {r['skew_est']}</td>"
                 f"<td><b>{o['precision']}</b></td><td><b>{o['recall']}</b></td><td><b>{o['fp']}</b></td><td>{o['stages_detected']}</td>"
                 f"<td>{e(o.get('caught_before_first_payout', 'n/a'))} {('(' + str(o['lead_time_days']) + ' d lead)') if 'lead_time_days' in o else ''}</td>"
                 f"<td>{m['held_or_flagged']}/{m['target_vendors']} (false {len(m['false_holds'])})</td>"
                 f"<td>{b['precision']}</td><td>{b['recall']}</td><td>{b['fp']}</td></tr>")
    h.append("</tbody></table></div>")
    for r in rows:
        h.append(f"<h3 class='mono'>{e(r['variant'])} seed {r['seed']}</h3><div class='panel small'>"
                 f"<b>Stages (ours)</b><br>{_kv(r['ours']['stages'])}<br><br><b>Traps flagged (ours / baseline)</b><br>"
                 + "<br>".join(f"{e(k)}: {e(v)} / {e(r['baseline']['traps'].get(k))}" for k, v in r["ours"]["traps"].items()) + "</div>")
    h.append("</main></body></html>")
    return "".join(h)
