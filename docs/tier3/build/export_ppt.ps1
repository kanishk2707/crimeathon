# Export a .pptx to .pdf and slide PNGs with PowerPoint (Windows). Leaves other open presentations alone.
#   powershell -File export_ppt.ps1 <deck.pptx> <out.pdf> [png_prefix]
param([string]$Deck, [string]$Pdf, [string]$PngPrefix = "")
$ErrorActionPreference = "Stop"
$pp = New-Object -ComObject PowerPoint.Application
$p = $pp.Presentations.Open((Resolve-Path $Deck).Path, $true, $false, $false)
$p.SaveAs([IO.Path]::GetFullPath($Pdf), 32)
if ($PngPrefix) { for ($i = 1; $i -le $p.Slides.Count; $i++) { $p.Slides.Item($i).Export([IO.Path]::GetFullPath("$PngPrefix$i.png"), "PNG", 1920, 1080) } }
$n = $p.Slides.Count
$p.Close()
if ($pp.Presentations.Count -eq 0) { $pp.Quit() }
Write-Output "exported $n slide(s) to $Pdf"
