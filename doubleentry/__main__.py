"""Double-Entry Defense - command line.

  python -m doubleentry generate --out synthetic/reference [--variant reference] [--seed 7]
  python -m doubleentry analyze  <evidence_folder> --out out/ [--config cfg.json] [--truth ground_truth.json]
  python -m doubleentry evaluate --out eval/ [--variants all|reference,on_link,...] [--seeds 7,11]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_config


def main(argv=None):
    p = argparse.ArgumentParser(prog="doubleentry", description="Invariant-based integration abuse detection for CR-26-047")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="write a synthetic evidence folder with ground truth")
    g.add_argument("--out", required=True)
    g.add_argument("--variant", default="reference")
    g.add_argument("--seed", type=int, default=7)

    a = sub.add_parser("analyze", help="analyse an evidence folder (real or synthetic)")
    a.add_argument("folder")
    a.add_argument("--out", default="out")
    a.add_argument("--config")
    a.add_argument("--truth", help="ground_truth.json to score against (synthetic only)")

    v = sub.add_parser("evaluate", help="run every attack variant and compare with the obvious approach")
    v.add_argument("--out", default="eval")
    v.add_argument("--variants", default="all")
    v.add_argument("--seeds", default="7")
    v.add_argument("--config")

    args = p.parse_args(argv)
    if args.cmd == "generate":
        from .synth import generate
        out = generate(args.out, variant=args.variant, seed=args.seed)
        print(f"synthetic evidence written to {out}")
    elif args.cmd == "analyze":
        from .engine import analyze, write_outputs
        cfg = load_config(args.config)
        res = analyze(args.folder, cfg)
        if args.truth:
            from . import baseline
            from .evaluate import _eval_block, money_check, ours_flagged, score, universe
            truth = json.loads(Path(args.truth).read_text(encoding="utf-8"))
            uni = universe(res)
            ours = score(ours_flagged(res), truth, uni, res["findings"])
            base = score(baseline.run(res["ev"], res["act"], cfg), truth, uni)
            res["evaluation"] = _eval_block(truth.get("variant", "?"), "-", ours, base, money_check(res, truth), res)
            print(json.dumps({"ours": ours, "baseline": base}, indent=1, default=str))
        path = write_outputs(res, Path(args.out))
        f = res["findings"]
        n_alert = int(f["alert"].sum()) if len(f) else 0
        v = res["vendors"]
        n_hold = int((v["verdict"] == "HOLD").sum()) if len(v) else 0
        print(f"{n_alert} alerts in {len(res['threads'])} thread(s); {n_hold} vendor(s) to hold. Report: {path}")
    elif args.cmd == "evaluate":
        from .evaluate import run
        from .synth import VARIANTS
        cfg = load_config(args.config)
        variants = VARIANTS if args.variants == "all" else args.variants.split(",")
        seeds = [int(s) for s in args.seeds.split(",")]
        run(Path(args.out), variants, seeds, cfg)
        print(f"summary: {Path(args.out) / 'evaluation.html'}")


if __name__ == "__main__":
    sys.exit(main())
