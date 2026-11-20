[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PgRoot,
    [Parameter(Mandatory = $true)][string]$UpstreamDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$control = Join-Path $UpstreamDir 'plpgsql_check.control'
# The SQL extension version comes from the real upstream control file, never
# from a hardcoded literal.
$controlText = Get-Content $control -Raw
$controlMatch = [regex]::Match($controlText, "(?m)^default_version\s*=\s*'([^']+)'")
if (-not $controlMatch.Success) { throw 'Upstream control default_version was not found.' }
$sqlVersion = $controlMatch.Groups[1].Value
$sql = Join-Path $UpstreamDir "plpgsql_check--$sqlVersion.sql"
$dll = Join-Path $UpstreamDir 'plpgsql_check.dll'
foreach ($file in @($control, $sql, $dll)) {
    if (-not (Test-Path $file -PathType Leaf)) { throw "Required installation file missing: $file" }
}
$pgVersion = (& (Join-Path $PgRoot 'bin\pg_config.exe') --version).Trim()
if ($LASTEXITCODE -ne 0 -or $pgVersion -notmatch '^PostgreSQL\s+1[4-9](?:\.|\s)') {
    throw "Unsupported target installation: $pgVersion"
}
$targetExtension = Join-Path $PgRoot 'share\extension'
if (-not (Test-Path $targetExtension)) { throw "Missing PostgreSQL extension path: $targetExtension" }
Copy-Item $dll (Join-Path $PgRoot 'lib\plpgsql_check.dll') -Force
Copy-Item $control (Join-Path $targetExtension 'plpgsql_check.control') -Force
$upgradeScripts = @(Get-ChildItem $UpstreamDir -File -Filter 'plpgsql_check--*.sql')
if (-not ($upgradeScripts.Name -contains "plpgsql_check--$sqlVersion.sql")) { throw 'Missing install SQL.' }
foreach ($file in $upgradeScripts) {
    Copy-Item $file.FullName (Join-Path $targetExtension $file.Name) -Force
}
Write-Host "Installed plpgsql_check DLL, control and $($upgradeScripts.Count) SQL script(s)."
