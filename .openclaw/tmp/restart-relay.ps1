$conns = Get-NetTCPConnection -LocalPort 7787 -State Listen -ErrorAction SilentlyContinue
foreach ($procId in ($conns.OwningProcess | Select-Object -Unique)) {
  $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
  if ($p -and $p.ProcessName -eq 'node') { "killing relay pid $procId"; Stop-Process -Id $procId -Force }
}
Start-Sleep -Seconds 1
& powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\dutch\.openclaw\workspace\arthur-morgan\telegraph\scripts\relay-watchdog.ps1"
