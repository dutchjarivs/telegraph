# relay-watchdog.ps1 -- keep the Telegraph relay + its cloudflared tunnel alive.
#
# WHY: 2026-07-27 the relay had a silent public outage (CF 1033) -- the node
# process on :7787 had died AND the 'telegraph' cloudflared tunnel had 0
# connections. The logon scheduled task is one-shot (no keep-alive), so nothing
# brought them back. This script is idempotent: run it on a short interval and it
# only acts on the piece that is actually down. It never touches the unrelated
# 'chirp' tunnel (distinguished by its command line / config file).
#
# SECRETS: this script hardcodes nothing. It sources the relay's env (Stripe
# webhook secret, checkout URLs, trust-proxy) from start-telegraph.cmd -- the
# same gitignored launcher the logon task uses -- so there is one source of
# truth and this file is safe to commit.
#
# ASCII ONLY on purpose: Windows PowerShell reads a no-BOM .ps1 as cp1252 and
# treats smart-quotes as string delimiters, so an em-dash breaks the parse.
#
# Enable (Tristan's call -- infra):
#   schtasks /Create /TN "TelegraphRelayWatchdog" /SC MINUTE /MO 5 /F /TR "powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\dutch\.openclaw\workspace\arthur-morgan\telegraph\scripts\relay-watchdog.ps1"
# Disable:  Unregister-ScheduledTask -TaskName TelegraphRelayWatchdog -Confirm:$false

$ErrorActionPreference = 'Stop'
$root      = 'C:\Users\dutch\.openclaw\workspace\arthur-morgan\telegraph'
$cf        = 'C:\Program Files (x86)\cloudflared\cloudflared.exe'
$cfConfig  = 'C:\Users\dutch\.cloudflared\telegraph-config.yml'
$launcher  = Join-Path $root 'start-telegraph.cmd'
$logFile   = Join-Path $root 'relay-watchdog.log'
$port      = 7787

function Log($msg) {
  $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
  Add-Content -Path $logFile -Value "$ts  $msg"
}

# Apply the `set VAR=value` lines from start-telegraph.cmd to this process env,
# so the relay we start carries the identical Stripe/checkout/proxy config.
function Import-LauncherEnv {
  if (-not (Test-Path $launcher)) { Log "launcher missing: $launcher"; return }
  foreach ($line in Get-Content $launcher) {
    $m = [regex]::Match($line.Trim(), '^set\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
    if ($m.Success) {
      Set-Item -Path ("Env:" + $m.Groups[1].Value) -Value $m.Groups[2].Value
    }
  }
}

# --- 1. Relay process on :$port ------------------------------------------------
# Distinguish "port not listening" (dead -> start one) from "listening but the
# health check failed" (wedged -> do NOT start a duplicate; it would only hit
# EADDRINUSE and exit, and a wedged relay needs a human, not a doomed respawn).
$relayHealthy   = $false
$relayListening = [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
try {
  $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 6 "http://127.0.0.1:$port/v1/health"
  if ($r.StatusCode -eq 200) { $relayHealthy = $true }
} catch { $relayHealthy = $false }

if (-not $relayListening) {
  Log "relay DOWN on :$port (nothing listening) - starting"
  # Start-Process's stdout redirect truncates relay-live.log, and it carries the
  # access log used for funnel analysis -- archive it before the respawn wipes it.
  $liveLog = Join-Path $root 'relay-live.log'
  if ((Test-Path $liveLog) -and ((Get-Item $liveLog).Length -gt 0)) {
    Add-Content -Path (Join-Path $root 'relay-access-archive.log') -Value (Get-Content $liveLog)
    # Clear what we just copied. This branch assumed the respawn below would
    # truncate the file via the stdout redirect -- but if Start-Process doesn't
    # get that far (or something else restarted the relay), the next DOWN pass
    # archives the SAME content again. Measured 2026-08-13: two segments,
    # 16,167 of 38,703 archived rows (42%), present verbatim twice. Nothing
    # detected it, because an undated log cannot tell a duplicate from a repeat.
    Clear-Content -Path $liveLog -ErrorAction SilentlyContinue
  }
  Import-LauncherEnv   # Stripe/checkout/trust-proxy; admin token auto-loads from ./.admin-token
  Set-Location $root
  Start-Process -FilePath 'node' -ArgumentList 'bin\telegraph.js','serve','--port',"$port",'--data','.\data' -RedirectStandardOutput $liveLog -RedirectStandardError (Join-Path $root 'relay-live.err.log') -WindowStyle Hidden | Out-Null
  Start-Sleep -Seconds 3
} elseif (-not $relayHealthy) {
  Log "relay on :$port is LISTENING but health check failed (wedged?) - NOT respawning; needs a look"
}

# --- 2. Telegraph tunnel (never touch chirp) -----------------------------------
# The telegraph tunnel is the cloudflared whose command line references
# telegraph-config.yml. chirp uses config.yml and is left alone.
$tgTunnel = Get-CimInstance Win32_Process -Filter "Name='cloudflared.exe'" | Where-Object { $_.CommandLine -match 'telegraph-config' }

if (-not $tgTunnel) {
  Log 'telegraph tunnel DOWN - starting'
  Start-Process -FilePath $cf -ArgumentList '--config',$cfConfig,'--no-autoupdate','tunnel','run' -RedirectStandardOutput (Join-Path $root 'tunnel-live.out.log') -RedirectStandardError (Join-Path $root 'tunnel-live.log') -WindowStyle Hidden | Out-Null
  Start-Sleep -Seconds 6
}

# --- 3. Verify public reachability (informational) -----------------------------
try {
  $p = Invoke-WebRequest -UseBasicParsing -TimeoutSec 12 'https://telegraphnet.com/v1/health'
  if ($p.StatusCode -ne 200) { Log "public health non-200: $($p.StatusCode)" }
} catch {
  Log "public health check failed: $($_.Exception.Message)"
}
