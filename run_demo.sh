#!/usr/bin/env sh
# Double-Entry Defense - one-command demo (Linux/macOS)
#   ./run_demo.sh          analyse the supplied evidence, score it, open the report
#   ./run_demo.sh --full   also run the 6-variant x 3-seed synthetic suite
set -e
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
echo "== Analysing the supplied evidence (E01-E20) =="
$PY -m doubleentry analyze evidence --out out/real --truth analysis/analyst_labels.json
echo; echo "== Four briefs =="; cat out/real/briefs.md
if [ "$1" = "--full" ]; then
  echo; echo "== Hidden-variation suite (6 variants x 3 seeds) =="
  $PY -m doubleentry evaluate --out eval --variants all --seeds 7,11,23
fi
OPEN=$(command -v xdg-open || command -v open || echo echo)
$OPEN out/real/report.html >/dev/null 2>&1 || echo "Report: out/real/report.html"
