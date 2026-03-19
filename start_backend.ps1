# Kill anything on port 5000 then start backend
$p = Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue |
     Select-Object -ExpandProperty OwningProcess -Unique
if ($p) { Stop-Process -Id $p -Force; Write-Host "Killed old process (PID $p)" }

Set-Location "$PSScriptRoot\backend"
& "$PSScriptRoot\.venv\Scripts\Activate.ps1"
$env:PYTHONUTF8 = 1
$env:PYTHONIOENCODING = "utf-8"
python app.py
