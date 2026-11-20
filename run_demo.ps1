# Double-Entry Defense - one-command demo (Windows PowerShell)
#   .\run_demo.ps1         analyse the supplied evidence, score it, open the report
#   .\run_demo.ps1 -Full   also run the 6-variant x 3-seed synthetic suite
param([switch]$Full)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "== Analysing the supplied evidence (E01-E20) ==" -ForegroundColor White
python -m doubleentry analyze evidence --out out/real --truth analysis/analyst_labels.json
if ($LASTEXITCODE -ne 0) { throw "analysis failed" }
Write-Host "`n== Four briefs ==" -ForegroundColor White
Get-Content out/real/briefs.md -Encoding UTF8
if ($Full) {
    Write-Host "`n== Hidden-variation suite (6 variants x 3 seeds) ==" -ForegroundColor White
    python -m doubleentry evaluate --out eval --variants all --seeds 7,11,23
    if ($LASTEXITCODE -ne 0) { throw "evaluation failed" }
    Start-Process (Resolve-Path eval/evaluation.html)
}
Start-Process (Resolve-Path out/real/report.html)
