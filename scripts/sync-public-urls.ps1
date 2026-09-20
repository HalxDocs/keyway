<#
.SYNOPSIS
  Re-points the Keyway stack at the current Cloudflare tunnel URLs and
  syncs the Auth0 OIDC callback allowlist. Idempotent: unchanged URLs are
  no-ops everywhere.

.DESCRIPTION
  Tunnel hostnames rotate whenever cloudflared restarts, which would
  otherwise mean hand-editing .env, compose, the tenant allowlist, and the
  Auth0 dashboard on every reboot. This script closes that loop for the
  machine parts and the Auth0 OIDC callbacks; the SAML2 addon has no stable
  Management API field for its callback, so the script prints the exact
  values to paste (one field plus the JSON block, ~30 seconds).

  Required environment (or .env in the repo root, which this script reads):
    AUTH0_DOMAIN   e.g. dev-xyz.eu.auth0.com
    AUTH0_CLIENT_ID  the application (not M2M) client ID
  Optional (Auth0 OIDC sync off unless all three are set):
    AUTH0_SYNC=true, AUTH0_M2M_ID, AUTH0_M2M_SECRET
    (M2M app authorized for the Management API with update:clients.)

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sync-public-urls.ps1
#>
[CmdletBinding()]
param(
  [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$TunnelLog8080 = "C:\Users\USER\AppData\Local\Temp\opencode\tun8080.log",
  [string]$TunnelLog3000 = "C:\Users\USER\AppData\Local\Temp\opencode\tun3000.log"
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $RepoRoot

function Get-TunnelUrl([string]$log) {
  $m = Select-String -Path $log -Pattern "https://[a-z0-9-]+\.trycloudflare\.com" -ErrorAction SilentlyContinue |
    ForEach-Object { $_.Matches.Value } | Select-Object -Last 1
  if (-not $m) { throw "no tunnel URL in $log (is cloudflared running?)" }
  return $m
}

function Get-DotEnv([string]$path) {
  $env = @{}
  if (Test-Path -LiteralPath $path) {
    Get-Content -LiteralPath $path | ForEach-Object {
      if ($_ -match "^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$") { $env[$Matches[1]] = $Matches[2] }
    }
  }
  return $env
}

function Set-DotEnvValue([string]$path, [string]$key, [string]$value) {
  $lines = @()
  if (Test-Path -LiteralPath $path) { $lines = @(Get-Content -LiteralPath $path) }
  $done = $false
  $lines = @($lines | ForEach-Object {
    if ($_ -match "^\s*$key\s*=") { $done = $true; "$key=$value" } else { $_ }
  })
  if (-not $done) { $lines += "$key=$value" }
  Set-Content -LiteralPath $path -Value $lines
}

$keywayPublic = Get-TunnelUrl $TunnelLog8080
$demoPublic = Get-TunnelUrl $TunnelLog3000
Write-Output "keyway: $keywayPublic"
Write-Output "demo:   $demoPublic"

$envFile = Join-Path $RepoRoot ".env"
$cfg = Get-DotEnv $envFile
$changed = $false
foreach ($kv in @(
    @("KEYWAY_BASE_URL", $keywayPublic),
    @("KEYWAY_PUBLIC_URL", $keywayPublic),
    @("DEMO_REDIRECT", "$demoPublic/callback"))) {
  if ($cfg[$kv[0]] -ne $kv[1]) {
    Set-DotEnvValue $envFile $kv[0] $kv[1]
    $changed = $true
    Write-Output "env: $($kv[0]) updated"
  }
}
if (-not $changed) { Write-Output "env: already current" }

Write-Output "compose: recreating with current env"
docker compose up -d | Write-Output
Start-Sleep -Seconds 12

$master = $cfg["KEYWAY_MASTER_KEY"]
if (-not $master) { $master = $env:KEYWAY_MASTER_KEY }
if (-not $master) { throw "KEYWAY_MASTER_KEY not in .env nor environment" }
$env:KEYWAY_MASTER_KEY = $master
$demoCb = "$demoPublic/callback"
docker compose exec keyway /keyway tenant redirect add --id acme --uri $demoCb --db /data/keyway.db 2>&1 | Write-Output

$oidcConn = $cfg["OIDC_CONNECTION_ID"]
if (-not $oidcConn) { throw "OIDC_CONNECTION_ID not set in .env" }
$samlConn = $cfg["DEMO_CONNECTION_ID"]
if (-not $samlConn) { throw "DEMO_CONNECTION_ID not set in .env" }
$oidcCb = "$keywayPublic/callback/oidc/$oidcConn"
$samlCb = "$keywayPublic/callback/saml/$samlConn"
Write-Output ""
Write-Output "--- Auth0 (manual, ~1 min) ---"
Write-Output "OIDC Allowed Callback URLs, add: $oidcCb"
Write-Output "SAML2 addon Application Callback URL: $samlCb"
Write-Output ('SAML2 addon JSON: {"audience":"' + $keywayPublic + '","recipient":"' + $samlCb + '","destination":"' + $samlCb + '"}')

if ($cfg["AUTH0_SYNC"] -eq "true" -and $cfg["AUTH0_M2M_ID"] -and $cfg["AUTH0_M2M_SECRET"] -and $cfg["AUTH0_DOMAIN"] -and $cfg["AUTH0_CLIENT_ID"]) {
  Write-Output ""
  Write-Output "--- Auth0 OIDC sync (Management API) ---"
  $tokenBody = @{
    client_id = $cfg["AUTH0_M2M_ID"]; client_secret = $cfg["AUTH0_M2M_SECRET"]
    audience = "https://$($cfg['AUTH0_DOMAIN'])/api/v2/"; grant_type = "client_credentials"
  } | ConvertTo-Json
  $token = Invoke-RestMethod -Uri "https://$($cfg['AUTH0_DOMAIN'])/oauth/token" -Method Post -Body $tokenBody -ContentType "application/json"
  $headers = @{ Authorization = "Bearer $($token.access_token)" }
  $app = Invoke-RestMethod -Uri "https://$($cfg['AUTH0_DOMAIN'])/api/v2/clients/$($cfg['AUTH0_CLIENT_ID'])" -Headers $headers
  $callbacks = @($app.callbacks) + $oidcCb | Select-Object -Unique
  $patch = @{ callbacks = $callbacks } | ConvertTo-Json
  Invoke-RestMethod -Uri "https://$($cfg['AUTH0_DOMAIN'])/api/v2/clients/$($cfg['AUTH0_CLIENT_ID'])" -Method Patch -Body $patch -ContentType "application/json" -Headers $headers | Out-Null
  Write-Output "OIDC callbacks synced (kept $($callbacks.Count) total, nothing removed)"
} else {
  Write-Output ""
  Write-Output "OIDC auto-sync off (needs AUTH0_SYNC=true + M2M id/secret + domain + client id); add the URL above by hand."
}
Write-Output "done"
