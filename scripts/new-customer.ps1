<#
.SYNOPSIS
  Scaffolds one isolated per-customer stack (operator model 3).

.DESCRIPTION
  Creates customers/<id>/ with a fresh .env (master key, admin token,
  ports, URLs, SP paths) plus a stable sp.key/sp.crt pair via
  `keyway sp-keygen`, then prints the exact up / provision / Auth0 commands.
  Nothing is started and nothing leaves the machine: review the files,
  then run the printed steps. Customer dirs are gitignored (live secrets).

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\new-customer.ps1 -CustomerId acme -Name Acme
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\new-customer.ps1 -CustomerId globex -KeywayPort 8081 -DemoPort 3001 -KeywayBaseUrl http://127.0.0.1:8081 -DemoRedirect http://localhost:3001/callback
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$CustomerId,
  [string]$Name = "",
  [int]$KeywayPort = 8080,
  [int]$DemoPort = 3000,
  [string]$KeywayBaseUrl = "",
  [string]$DemoRedirect = ""
)

$ErrorActionPreference = "Stop"
if ($CustomerId -notmatch "^[a-z0-9][a-z0-9-]*$") { throw "CustomerId must match ^[a-z0-9][a-z0-9-]*$" }
if (-not $Name) { $Name = $CustomerId }
if (-not $KeywayBaseUrl) { $KeywayBaseUrl = "http://127.0.0.1:$KeywayPort" }
if (-not $DemoRedirect) { $DemoRedirect = "http://localhost:$DemoPort/callback" }

$repo = ""
if ($PSScriptRoot) { $repo = Split-Path -Parent $PSScriptRoot }
if (-not $repo) { $repo = (Get-Location).Path }
Set-Location -LiteralPath $repo

$dir = Join-Path $repo "customers\$CustomerId"
if (Test-Path -LiteralPath $dir) { throw "$dir already exists (refusing to overwrite a live customer)" }
New-Item -ItemType Directory -Path $dir | Out-Null

function New-HexSecret([int]$bytes) {
  $raw = New-Object byte[] $bytes
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($raw)
  return ([BitConverter]::ToString($raw)).Replace("-", "").ToLower()
}

$keyPath = Join-Path $dir "sp.key"
$certPath = Join-Path $dir "sp.crt"
& go run ./cmd/keyway sp-keygen --key $keyPath --cert $certPath
if ($LASTEXITCODE -ne 0) { throw "sp-keygen failed (Go toolchain required)" }

$envLines = @(
  "KEYWAY_MASTER_KEY=$(New-HexSecret 32)",
  "KEYWAY_PORT=$KeywayPort",
  "DEMO_PORT=$DemoPort",
  "KEYWAY_BASE_URL=$KeywayBaseUrl",
  "KEYWAY_PUBLIC_URL=$KeywayBaseUrl",
  "DEMO_TENANT=$CustomerId",
  "DEMO_REDIRECT=$DemoRedirect",
  "DEMO_CONNECTION_ID=",
  "OIDC_CONNECTION_ID=",
  "KEYWAY_ADMIN_TOKEN=$(New-HexSecret 32)",
  "SP_KEY_PATH=./customers/$CustomerId/sp.key",
  "SP_CERT_PATH=./customers/$CustomerId/sp.crt"
)
Set-Content -LiteralPath (Join-Path $dir ".env") -Value $envLines
Write-Output "scaffolded $dir (.env, sp.key, sp.crt)"

$project = "keyway-$CustomerId"
$envFile = "customers/$CustomerId/.env"
Write-Output ""
Write-Output "--- next: start ---"
Write-Output "docker compose --env-file $envFile -p $project up -d --build"
Write-Output ""
Write-Output "--- next: provision (replace IdP values) ---"
Write-Output "docker compose --env-file $envFile -p $project exec keyway /keyway tenant create --id $CustomerId --name `"$Name`" --redirect-uris $DemoRedirect --db /data/keyway.db"
Write-Output "docker compose --env-file $envFile -p $project exec keyway /keyway connection add --tenant $CustomerId --type oidc --issuer https://TENANT.eu.auth0.com/ --client-id ID --client-secret SECRET --email-claim email --name-claim name --db /data/keyway.db"
Write-Output "docker compose --env-file $envFile -p $project exec keyway /keyway connection test --id conn-<id> --db /data/keyway.db"
Write-Output "docker compose --env-file $envFile -p $project exec keyway /keyway connection activate --id conn-<id> --db /data/keyway.db"
Write-Output ""
Write-Output "--- next: Auth0 ---"
Write-Output "Allowlist $KeywayBaseUrl/callback/oidc/conn-<id> (OIDC) and/or $KeywayBaseUrl/callback/saml/conn-<id> (SAML2 addon), then log in."
Write-Output "done"
