[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$UpstreamDir,
    [Parameter(Mandatory = $true)][string]$UpstreamRepository,
    [Parameter(Mandatory = $true)][string]$UpstreamRef,
    [Parameter(Mandatory = $true)][string]$UpstreamVersion,
    [Parameter(Mandatory = $true)][int]$PostgreSqlMajor,
    [Parameter(Mandatory = $true)][string]$PostgreSqlMinor,
    [string]$DistDir = 'dist'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$manifest = Get-Content (Join-Path $PSScriptRoot '..\..\config\extension.json') -Raw | ConvertFrom-Json
$expectedSha = [string]$manifest.upstream.commit
if ($expectedSha -cnotmatch '^[0-9a-f]{40}$' -or
    $UpstreamRepository -cne 'okbob/plpgsql_check' -or
    $UpstreamRef -cne [string]$manifest.upstream.ref -or
    $UpstreamVersion -cne [string]$manifest.upstream.version -or
    $PostgreSqlMajor -notin @(15,16,17,18) -or
    $PostgreSqlMinor -notmatch ('^' + $PostgreSqlMajor + '\.')) {
    throw 'Unexpected upstream SHA/ref/version or tested PostgreSQL minor in package hook.'
}
$upstreamSha = (& git -C $UpstreamDir rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $upstreamSha -cne $expectedSha) { throw 'Upstream source SHA changed.' }
$control = Get-Content (Join-Path $UpstreamDir 'plpgsql_check.control') -Raw
$match = [regex]::Match($control, "(?m)^default_version\s*=\s*'([^']+)'")
if (-not $match.Success) { throw 'Upstream control version not found.' }
$sqlVersion = $match.Groups[1].Value
$sqlName = "plpgsql_check--$sqlVersion.sql"

$baseName = "plpgsql_check-$UpstreamRef-pg$PostgreSqlMajor-windows-x64"
$stage = Join-Path $DistDir $baseName
$zip = Join-Path $DistDir "$baseName.zip"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
if (Test-Path $zip) { Remove-Item $zip -Force }
New-Item -Path (Join-Path $stage 'lib') -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $stage 'share\extension') -ItemType Directory -Force | Out-Null
$required = @(
    @{ Source = 'plpgsql_check.dll'; Target = 'lib\plpgsql_check.dll' },
    @{ Source = 'plpgsql_check.control'; Target = 'share\extension\plpgsql_check.control' },
    @{ Source = $sqlName; Target = ('share\extension\' + $sqlName) },
    @{ Source = 'LICENSE'; Target = 'LICENSE' },
    @{ Source = 'README.md'; Target = 'UPSTREAM-README.md' }
)
foreach ($mapping in $required) {
    $source = Join-Path $UpstreamDir $mapping.Source
    if (-not (Test-Path $source -PathType Leaf)) { throw "Required package file missing: $source" }
    Copy-Item $source (Join-Path $stage $mapping.Target) -Force
}
# Include only scripts the immutable pinned upstream actually supplies.
foreach ($file in @(Get-ChildItem $UpstreamDir -File -Filter 'plpgsql_check--*.sql')) {
    $target = Join-Path $stage ('share\extension\' + $file.Name)
    if (-not (Test-Path $target)) { Copy-Item $file.FullName $target }
}
$description = @"
plpgsql_check Windows binary package (unofficial pgextwin release)
=======================================================
Upstream repository: $UpstreamRepository
Upstream ref: $UpstreamRef
Upstream commit: $upstreamSha
Extension version: $UpstreamVersion
SQL extension version: $sqlVersion
PostgreSQL major: $PostgreSqlMajor
PostgreSQL tested: $PostgreSqlMinor
Architecture: Windows x64
Compiler: MSVC
License: MIT-style; see LICENSE

This is an unofficial pgextwin Windows binary; not an official upstream distribution.
Copy lib/plpgsql_check.dll to PostgreSQL's lib directory and
share/extension/* to its share/extension directory. CREATE EXTENSION plpgsql_check;
Active linting via plpgsql_check_function_tb does not require shared preload.
Profiler, tracer, passive/shared modes and SQL upgrades are not covered by release CI.
"@
[IO.File]::WriteAllText((Join-Path $stage 'PACKAGE-INFO.txt'), $description, [Text.UTF8Encoding]::new($false))
Copy-Item (Join-Path $PSScriptRoot '..\..\README.md') (Join-Path $stage 'PGEXTWIN-README.md')
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
if (-not (Test-Path $zip)) { throw "ZIP package creation failed: $zip" }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead((Resolve-Path $zip).Path)
try {
    $entryNames = @($archive.Entries | ForEach-Object { $_.FullName.Replace('\','/') })
    foreach ($path in @('lib/plpgsql_check.dll','share/extension/plpgsql_check.control',
                       ('share/extension/' + $sqlName),'LICENSE','PACKAGE-INFO.txt','UPSTREAM-README.md')) {
        if ($entryNames -cnotcontains $path) { throw "Expected ZIP entry missing: $path" }
    }
}
finally { $archive.Dispose() }
Write-Host "Validated release package structure: $zip"
# The shared reusable workflow subsequently injects and validates PACKAGE-INFO.json,
# SPDX SBOM, Grype report and final SHA checksums; no attestation in normal CI.
