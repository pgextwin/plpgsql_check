[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PgRoot,
    [Parameter(Mandatory = $true)][string]$UpstreamDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Commit pin is carried in the manifest. Candidates may change it; tags cannot silently move.
$manifest = Get-Content (Join-Path $PSScriptRoot '..\..\config\extension.json') -Raw | ConvertFrom-Json
$expectedSha = [string]$manifest.upstream.commit
$expectedVersion = [string]$manifest.upstream.version
if ($expectedSha -cnotmatch '^[0-9a-f]{40}$' -or
    $manifest.upstream.repository -cne 'okbob/plpgsql_check') {
    throw 'Missing or malformed pinned upstream source identity.'
}
$actualSha = (& git -C $UpstreamDir rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualSha -cne $expectedSha) {
    throw "Upstream source identity mismatch; expected $expectedSha, got '$actualSha'."
}
$pgConfig = Join-Path $PgRoot 'bin\pg_config.exe'
if (-not (Test-Path $pgConfig)) { throw "Missing pg_config: $pgConfig" }
$pgVersion = (& $pgConfig --version).Trim()
if ($LASTEXITCODE -ne 0 -or $pgVersion -notmatch '^PostgreSQL\s+(1[5-8])(?:\.|\s)') {
    throw "Only PG15-18 are approved for this pilot: $pgVersion"
}
$pgMajor = [int]$Matches[1]

$controlPath = Join-Path $UpstreamDir 'plpgsql_check.control'
$control = Get-Content $controlPath -Raw
$controlMatch = [regex]::Match($control, "(?m)^default_version\s*=\s*'([^']+)'")
if (-not $controlMatch.Success -or $controlMatch.Groups[1].Value -ne '2.10') {
    throw 'Expected upstream SQL default_version 2.10 was not found; aborting.'
}
$sqlPath = Join-Path $UpstreamDir 'plpgsql_check--2.10.sql'
if (-not (Test-Path $sqlPath)) { throw 'The control-required SQL install script is missing.' }
$mesonPath = Join-Path $UpstreamDir 'meson.build'
$meson = Get-Content $mesonPath -Raw
$expectedMesonPattern = "project\('plpgsql_check',\s*\['c'\],\s*version:\s*'" + [regex]::Escape($expectedVersion) + "'\)"
if ($meson -notmatch $expectedMesonPattern) {
    throw 'Upstream Meson project version or structure changed unexpectedly.'
}
$magicSource = Get-Content (Join-Path $UpstreamDir 'src\plpgsql_check.c') -Raw
if ($magicSource -notmatch '\bPG_MODULE_MAGIC(_EXT)?\b' -or $magicSource -notmatch 'void\s+_PG_init\s*\(void\)') {
    throw 'Upstream module magic or _PG_init declaration is missing.'
}

# Cross-audit SQL C entry points against PG_FUNCTION_INFO_V1 definitions.
# A DEF is needed for Windows versions whose extension symbols are not auto-exported.
$symbols = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$sourceFiles = @(Get-ChildItem (Join-Path $UpstreamDir 'src') -Filter '*.c' -File)
if ($sourceFiles.Count -lt 10) { throw 'Unexpected upstream C source inventory.' }
foreach ($f in $sourceFiles) {
    $text = Get-Content $f.FullName -Raw
    foreach ($m in [regex]::Matches($text, '\bPG_FUNCTION_INFO_V1\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')) {
        [void]$symbols.Add($m.Groups[1].Value)
    }
}
# The independent list below was audited against the pinned upstream SQL and C
# sources, not guessed from filenames. It keeps a reviewable export contract.
$audit = Get-Content (Join-Path $PSScriptRoot '..\..\config\export-audit.json') -Raw | ConvertFrom-Json
# For candidate CI, require the audited symbol set to remain identical.
# A new attested release additionally requires a SHA-matching independent export audit.
$isCandidate = ($env:GITHUB_REF -like 'refs/heads/auto-candidate/*') -or
               ($env:GITHUB_EVENT_NAME -eq 'pull_request')
if (-not $isCandidate -and $audit.upstreamCommit -cne $expectedSha) {
    throw 'Formal release requires a source-specific independent export audit.'
}
if ($audit.schemaVersion -ne 1 -or
    $audit.sqlExtensionVersion -cne '2.10' -or
    $audit.moduleMagicExport -cne 'Pg_magic_func' -or
    $audit.moduleInitializerExport -cne '_PG_init') {
    throw 'Independent export audit metadata does not match pinned upstream.'
}
$approved = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($name in @($audit.requiredSqlSymbols)) {
    if (-not $approved.Add([string]$name)) { throw "Duplicate audited symbol: $name" }
}
if ($approved.Count -ne 23) { throw "Expected 23 independently audited SQL symbols; found $($approved.Count)." }
$sql = Get-Content $sqlPath -Raw
$sqlMatches = [regex]::Matches($sql, "(?is)\bAS\s*'MODULE_PATHNAME'\s*,\s*'(?<symbol>[A-Za-z_][A-Za-z0-9_]*)'\s+LANGUAGE\s+C\b")
$sqlExports = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($m in $sqlMatches) {
    [void]$sqlExports.Add($m.Groups['symbol'].Value)
}
foreach ($name in $approved) {
    if (-not $symbols.Contains($name) -or -not $sqlExports.Contains($name)) {
        throw "Audited SQL symbol '$name' is missing from pinned C declarations or extension SQL."
    }
}
if ($symbols.Count -ne $approved.Count -or $sqlExports.Count -ne $approved.Count) {
    throw "New/removed C or SQL symbols require an explicit export audit update: C=$($symbols.Count), SQL=$($sqlExports.Count), expected=$($approved.Count)."
}

$exports = @($audit.moduleMagicExport, $audit.moduleInitializerExport) + @($approved | ForEach-Object { $_; "pg_finfo_$_" })
$exports = @($exports | Sort-Object -Unique -CaseSensitive)
$defFile = Join-Path $UpstreamDir 'pgextwin.exports.def'
[IO.File]::WriteAllLines($defFile, [string[]](@('LIBRARY plpgsql_check', 'EXPORTS') + @($exports | ForEach-Object { "    $_" })), [Text.Encoding]::ASCII)

# Apply a single fail-closed Meson adaptation only to the disposable SHA-verified checkout.
$marker = '  dependencies: postgres_lib,'
if (([regex]::Matches($meson, [regex]::Escape($marker))).Count -ne 1 -or
    $meson -notmatch '(?s)module_lib\s*=\s*shared_module\(') {
    throw 'Expected upstream shared_module block differs; refusing blind patch.'
}
$meson = $meson.Replace($marker, $marker + "`n  vs_module_defs: 'pgextwin.exports.def',")
[IO.File]::WriteAllText($mesonPath, $meson, [Text.UTF8Encoding]::new($false))

$vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "Missing vswhere: $vswhere" }
$vsRoot = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsRoot)) { throw 'VS C++ toolset not found.' }
$devCmd = Join-Path $vsRoot.Trim() 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $devCmd)) { throw "Missing VS developer command: $devCmd" }

$python = (Get-Command python.exe -ErrorAction Stop).Source
& $python -m pip install --disable-pip-version-check --quiet 'meson==1.8.3' 'ninja==1.11.1.4'
if ($LASTEXITCODE -ne 0) { throw 'Pinned Meson/Ninja installation failed.' }
$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$buildDir = Join-Path $tempRoot 'plpgsql-check-meson-build'
$buildCmd = Join-Path $tempRoot 'plpgsql-check-build.cmd'
$dumpCmd = Join-Path $tempRoot 'plpgsql-check-dump.cmd'
try {
    if (Test-Path $buildDir) { Remove-Item $buildDir -Recurse -Force }
    @"
@echo off
call "$devCmd" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b %errorlevel%
set "PATH=$PgRoot\bin;%PATH%"
"$python" -m mesonbuild.mesonmain setup "$buildDir" "$UpstreamDir" --backend ninja --buildtype=plain
if errorlevel 1 exit /b %errorlevel%
"$python" -m mesonbuild.mesonmain compile -C "$buildDir"
if errorlevel 1 exit /b %errorlevel%
"@ | Set-Content $buildCmd -Encoding ascii
    & cmd.exe /d /c $buildCmd
    if ($LASTEXITCODE -ne 0) { throw "Meson/MSVC build failed with code $LASTEXITCODE." }
    $candidates = @(Get-ChildItem $buildDir -Recurse -File -Filter 'plpgsql_check.dll')
    if ($candidates.Count -ne 1) { throw "Expected one built plpgsql_check.dll; found $($candidates.Count)." }
    $dll = Join-Path $UpstreamDir 'plpgsql_check.dll'
    Copy-Item $candidates[0].FullName $dll -Force

    @"
@echo off
call "$devCmd" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b %errorlevel%
dumpbin /nologo /exports "$dll"
if errorlevel 1 exit /b %errorlevel%
"@ | Set-Content $dumpCmd -Encoding ascii
    $lines = @(& cmd.exe /d /c $dumpCmd)
    if ($LASTEXITCODE -ne 0) { throw 'dumpbin /exports failed.' }
    $observed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($line in $lines) {
        if ($line -match '^\s*\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)') {
            [void]$observed.Add($Matches[1])
        }
    }
    foreach ($name in $exports) {
        if (-not $observed.Contains($name)) { throw "Required undecorated export missing: $name" }
    }
    Write-Host "Verified $($exports.Count) DLL exports for PG$pgMajor from pinned $actualSha."
    $lines | ForEach-Object { Write-Host $_ }
}
finally {
    Remove-Item $buildCmd, $dumpCmd -Force -ErrorAction SilentlyContinue
}
 -or $manifest.upstream.repository -cne 'okbob/plpgsql_check') {
    throw 'Missing or malformed plpgsql_check upstream source identity.'
}
$actualSha = (& git -C $UpstreamDir rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualSha -cne $expectedSha) {
    throw "Upstream source identity mismatch; expected $expectedSha, got '$actualSha'."
}
$pgConfig = Join-Path $PgRoot 'bin\pg_config.exe'
if (-not (Test-Path $pgConfig)) { throw "Missing pg_config: $pgConfig" }
$pgVersion = (& $pgConfig --version).Trim()
if ($LASTEXITCODE -ne 0 -or $pgVersion -notmatch '^PostgreSQL\s+(1[5-8])(?:\.|\s)') {
    throw "Only PG15-18 are approved for this pilot: $pgVersion"
}
$pgMajor = [int]$Matches[1]

$controlPath = Join-Path $UpstreamDir 'plpgsql_check.control'
$control = Get-Content $controlPath -Raw
$controlMatch = [regex]::Match($control, "(?m)^default_version\s*=\s*'([^']+)'")
if (-not $controlMatch.Success -or $controlMatch.Groups[1].Value -ne '2.10') {
    throw 'Expected upstream SQL default_version 2.10 was not found; aborting.'
}
$sqlPath = Join-Path $UpstreamDir 'plpgsql_check--2.10.sql'
if (-not (Test-Path $sqlPath)) { throw 'The control-required SQL install script is missing.' }
$mesonPath = Join-Path $UpstreamDir 'meson.build'
$meson = Get-Content $mesonPath -Raw
if ($meson -notmatch ("project\('plpgsql_check',\s*\['c'\],\s*version:\s*'" + [regex]::Escape($expectedVersion) + "'\)")) {
    throw 'Upstream Meson project version or structure changed unexpectedly.'
}
$magicSource = Get-Content (Join-Path $UpstreamDir 'src\plpgsql_check.c') -Raw
if ($magicSource -notmatch '\bPG_MODULE_MAGIC(_EXT)?\b' -or $magicSource -notmatch 'void\s+_PG_init\s*\(void\)') {
    throw 'Upstream module magic or _PG_init declaration is missing.'
}

# Cross-audit SQL C entry points against PG_FUNCTION_INFO_V1 definitions.
# A DEF is needed for Windows versions whose extension symbols are not auto-exported.
$symbols = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$sourceFiles = @(Get-ChildItem (Join-Path $UpstreamDir 'src') -Filter '*.c' -File)
if ($sourceFiles.Count -lt 10) { throw 'Unexpected upstream C source inventory.' }
foreach ($f in $sourceFiles) {
    $text = Get-Content $f.FullName -Raw
    foreach ($m in [regex]::Matches($text, '\bPG_FUNCTION_INFO_V1\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')) {
        [void]$symbols.Add($m.Groups[1].Value)
    }
}
# The independent list below was audited against the pinned upstream SQL and C
# sources, not guessed from filenames. It keeps a reviewable export contract.
$audit = Get-Content (Join-Path $PSScriptRoot '..\..\config\export-audit.json') -Raw | ConvertFrom-Json
if ($audit.schemaVersion -ne 1 -or $audit.upstreamCommit -cne $expectedSha -or
    $audit.sqlExtensionVersion -cne '2.10' -or
    $audit.moduleMagicExport -cne 'Pg_magic_func' -or
    $audit.moduleInitializerExport -cne '_PG_init') {
    throw 'Independent export audit metadata does not match pinned upstream.'
}
$approved = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($name in @($audit.requiredSqlSymbols)) {
    if (-not $approved.Add([string]$name)) { throw "Duplicate audited symbol: $name" }
}
if ($approved.Count -ne 23) { throw "Expected 23 independently audited SQL symbols; found $($approved.Count)." }
$sql = Get-Content $sqlPath -Raw
$sqlMatches = [regex]::Matches($sql, "(?is)\bAS\s*'MODULE_PATHNAME'\s*,\s*'(?<symbol>[A-Za-z_][A-Za-z0-9_]*)'\s+LANGUAGE\s+C\b")
$sqlExports = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($m in $sqlMatches) {
    [void]$sqlExports.Add($m.Groups['symbol'].Value)
}
foreach ($name in $approved) {
    if (-not $symbols.Contains($name) -or -not $sqlExports.Contains($name)) {
        throw "Audited SQL symbol '$name' is missing from pinned C declarations or extension SQL."
    }
}
if ($symbols.Count -ne $approved.Count -or $sqlExports.Count -ne $approved.Count) {
    throw "New/removed C or SQL symbols require an explicit export audit update: C=$($symbols.Count), SQL=$($sqlExports.Count), expected=$($approved.Count)."
}

$exports = @($audit.moduleMagicExport, $audit.moduleInitializerExport) + @($approved | ForEach-Object { $_; "pg_finfo_$_" })
$exports = @($exports | Sort-Object -Unique -CaseSensitive)
$defFile = Join-Path $UpstreamDir 'pgextwin.exports.def'
[IO.File]::WriteAllLines($defFile, [string[]](@('LIBRARY plpgsql_check', 'EXPORTS') + @($exports | ForEach-Object { "    $_" })), [Text.Encoding]::ASCII)

# Apply a single fail-closed Meson adaptation only to the disposable SHA-verified checkout.
$marker = '  dependencies: postgres_lib,'
if (([regex]::Matches($meson, [regex]::Escape($marker))).Count -ne 1 -or
    $meson -notmatch '(?s)module_lib\s*=\s*shared_module\(') {
    throw 'Expected upstream shared_module block differs; refusing blind patch.'
}
$meson = $meson.Replace($marker, $marker + "`n  vs_module_defs: 'pgextwin.exports.def',")
[IO.File]::WriteAllText($mesonPath, $meson, [Text.UTF8Encoding]::new($false))

$vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "Missing vswhere: $vswhere" }
$vsRoot = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsRoot)) { throw 'VS C++ toolset not found.' }
$devCmd = Join-Path $vsRoot.Trim() 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $devCmd)) { throw "Missing VS developer command: $devCmd" }

$python = (Get-Command python.exe -ErrorAction Stop).Source
& $python -m pip install --disable-pip-version-check --quiet 'meson==1.8.3' 'ninja==1.11.1.4'
if ($LASTEXITCODE -ne 0) { throw 'Pinned Meson/Ninja installation failed.' }
$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$buildDir = Join-Path $tempRoot 'plpgsql-check-meson-build'
$buildCmd = Join-Path $tempRoot 'plpgsql-check-build.cmd'
$dumpCmd = Join-Path $tempRoot 'plpgsql-check-dump.cmd'
try {
    if (Test-Path $buildDir) { Remove-Item $buildDir -Recurse -Force }
    @"
@echo off
call "$devCmd" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b %errorlevel%
set "PATH=$PgRoot\bin;%PATH%"
"$python" -m mesonbuild.mesonmain setup "$buildDir" "$UpstreamDir" --backend ninja --buildtype=plain
if errorlevel 1 exit /b %errorlevel%
"$python" -m mesonbuild.mesonmain compile -C "$buildDir"
if errorlevel 1 exit /b %errorlevel%
"@ | Set-Content $buildCmd -Encoding ascii
    & cmd.exe /d /c $buildCmd
    if ($LASTEXITCODE -ne 0) { throw "Meson/MSVC build failed with code $LASTEXITCODE." }
    $candidates = @(Get-ChildItem $buildDir -Recurse -File -Filter 'plpgsql_check.dll')
    if ($candidates.Count -ne 1) { throw "Expected one built plpgsql_check.dll; found $($candidates.Count)." }
    $dll = Join-Path $UpstreamDir 'plpgsql_check.dll'
    Copy-Item $candidates[0].FullName $dll -Force

    @"
@echo off
call "$devCmd" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b %errorlevel%
dumpbin /nologo /exports "$dll"
if errorlevel 1 exit /b %errorlevel%
"@ | Set-Content $dumpCmd -Encoding ascii
    $lines = @(& cmd.exe /d /c $dumpCmd)
    if ($LASTEXITCODE -ne 0) { throw 'dumpbin /exports failed.' }
    $observed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($line in $lines) {
        if ($line -match '^\s*\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)') {
            [void]$observed.Add($Matches[1])
        }
    }
    foreach ($name in $exports) {
        if (-not $observed.Contains($name)) { throw "Required undecorated export missing: $name" }
    }
    Write-Host "Verified $($exports.Count) DLL exports for PG$pgMajor from pinned $actualSha."
    $lines | ForEach-Object { Write-Host $_ }
}
finally {
    Remove-Item $buildCmd, $dumpCmd -Force -ErrorAction SilentlyContinue
}
 -or $manifest.upstream.repository -cne 'okbob/plpgsql_check') {
    throw 'Missing or malformed pinned upstream source identity.'
}
$actualSha = (& git -C $UpstreamDir rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualSha -cne $expectedSha) {
    throw "Upstream source identity mismatch; expected $expectedSha, got '$actualSha'."
}
$pgConfig = Join-Path $PgRoot 'bin\pg_config.exe'
if (-not (Test-Path $pgConfig)) { throw "Missing pg_config: $pgConfig" }
$pgVersion = (& $pgConfig --version).Trim()
if ($LASTEXITCODE -ne 0 -or $pgVersion -notmatch '^PostgreSQL\s+(1[5-8])(?:\.|\s)') {
    throw "Only PG15-18 are approved for this pilot: $pgVersion"
}
$pgMajor = [int]$Matches[1]

$controlPath = Join-Path $UpstreamDir 'plpgsql_check.control'
$control = Get-Content $controlPath -Raw
$controlMatch = [regex]::Match($control, "(?m)^default_version\s*=\s*'([^']+)'")
if (-not $controlMatch.Success -or $controlMatch.Groups[1].Value -ne '2.10') {
    throw 'Expected upstream SQL default_version 2.10 was not found; aborting.'
}
$sqlPath = Join-Path $UpstreamDir 'plpgsql_check--2.10.sql'
if (-not (Test-Path $sqlPath)) { throw 'The control-required SQL install script is missing.' }
$mesonPath = Join-Path $UpstreamDir 'meson.build'
$meson = Get-Content $mesonPath -Raw
if ($meson -notmatch ("project\('plpgsql_check',\s*\['c'\],\s*version:\s*'" + [regex]::Escape($expectedVersion) + "'\)")) {
    throw 'Upstream Meson project version or structure changed unexpectedly.'
}
$magicSource = Get-Content (Join-Path $UpstreamDir 'src\plpgsql_check.c') -Raw
if ($magicSource -notmatch '\bPG_MODULE_MAGIC(_EXT)?\b' -or $magicSource -notmatch 'void\s+_PG_init\s*\(void\)') {
    throw 'Upstream module magic or _PG_init declaration is missing.'
}

# Cross-audit SQL C entry points against PG_FUNCTION_INFO_V1 definitions.
# A DEF is needed for Windows versions whose extension symbols are not auto-exported.
$symbols = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$sourceFiles = @(Get-ChildItem (Join-Path $UpstreamDir 'src') -Filter '*.c' -File)
if ($sourceFiles.Count -lt 10) { throw 'Unexpected upstream C source inventory.' }
foreach ($f in $sourceFiles) {
    $text = Get-Content $f.FullName -Raw
    foreach ($m in [regex]::Matches($text, '\bPG_FUNCTION_INFO_V1\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')) {
        [void]$symbols.Add($m.Groups[1].Value)
    }
}
# The independent list below was audited against the pinned upstream SQL and C
# sources, not guessed from filenames. It keeps a reviewable export contract.
$audit = Get-Content (Join-Path $PSScriptRoot '..\..\config\export-audit.json') -Raw | ConvertFrom-Json
# For candidate CI, require the audited symbol set to remain identical.
# A new attested release additionally requires a SHA-matching independent export audit.
$isCandidate = ($env:GITHUB_REF -like 'refs/heads/auto-candidate/*') -or
               ($env:GITHUB_EVENT_NAME -eq 'pull_request')
if (-not $isCandidate -and $audit.upstreamCommit -cne $expectedSha) {
    throw 'Formal release requires a source-specific independent export audit.'
}
if ($audit.schemaVersion -ne 1 -or
    $audit.sqlExtensionVersion -cne '2.10' -or
    $audit.moduleMagicExport -cne 'Pg_magic_func' -or
    $audit.moduleInitializerExport -cne '_PG_init') {
    throw 'Independent export audit metadata does not match pinned upstream.'
}
$approved = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($name in @($audit.requiredSqlSymbols)) {
    if (-not $approved.Add([string]$name)) { throw "Duplicate audited symbol: $name" }
}
if ($approved.Count -ne 23) { throw "Expected 23 independently audited SQL symbols; found $($approved.Count)." }
$sql = Get-Content $sqlPath -Raw
$sqlMatches = [regex]::Matches($sql, "(?is)\bAS\s*'MODULE_PATHNAME'\s*,\s*'(?<symbol>[A-Za-z_][A-Za-z0-9_]*)'\s+LANGUAGE\s+C\b")
$sqlExports = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($m in $sqlMatches) {
    [void]$sqlExports.Add($m.Groups['symbol'].Value)
}
foreach ($name in $approved) {
    if (-not $symbols.Contains($name) -or -not $sqlExports.Contains($name)) {
        throw "Audited SQL symbol '$name' is missing from pinned C declarations or extension SQL."
    }
}
if ($symbols.Count -ne $approved.Count -or $sqlExports.Count -ne $approved.Count) {
    throw "New/removed C or SQL symbols require an explicit export audit update: C=$($symbols.Count), SQL=$($sqlExports.Count), expected=$($approved.Count)."
}

$exports = @($audit.moduleMagicExport, $audit.moduleInitializerExport) + @($approved | ForEach-Object { $_; "pg_finfo_$_" })
$exports = @($exports | Sort-Object -Unique -CaseSensitive)
$defFile = Join-Path $UpstreamDir 'pgextwin.exports.def'
[IO.File]::WriteAllLines($defFile, [string[]](@('LIBRARY plpgsql_check', 'EXPORTS') + @($exports | ForEach-Object { "    $_" })), [Text.Encoding]::ASCII)

# Apply a single fail-closed Meson adaptation only to the disposable SHA-verified checkout.
$marker = '  dependencies: postgres_lib,'
if (([regex]::Matches($meson, [regex]::Escape($marker))).Count -ne 1 -or
    $meson -notmatch '(?s)module_lib\s*=\s*shared_module\(') {
    throw 'Expected upstream shared_module block differs; refusing blind patch.'
}
$meson = $meson.Replace($marker, $marker + "`n  vs_module_defs: 'pgextwin.exports.def',")
[IO.File]::WriteAllText($mesonPath, $meson, [Text.UTF8Encoding]::new($false))

$vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "Missing vswhere: $vswhere" }
$vsRoot = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsRoot)) { throw 'VS C++ toolset not found.' }
$devCmd = Join-Path $vsRoot.Trim() 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $devCmd)) { throw "Missing VS developer command: $devCmd" }

$python = (Get-Command python.exe -ErrorAction Stop).Source
& $python -m pip install --disable-pip-version-check --quiet 'meson==1.8.3' 'ninja==1.11.1.4'
if ($LASTEXITCODE -ne 0) { throw 'Pinned Meson/Ninja installation failed.' }
$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$buildDir = Join-Path $tempRoot 'plpgsql-check-meson-build'
$buildCmd = Join-Path $tempRoot 'plpgsql-check-build.cmd'
$dumpCmd = Join-Path $tempRoot 'plpgsql-check-dump.cmd'
try {
    if (Test-Path $buildDir) { Remove-Item $buildDir -Recurse -Force }
    @"
@echo off
call "$devCmd" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b %errorlevel%
set "PATH=$PgRoot\bin;%PATH%"
"$python" -m mesonbuild.mesonmain setup "$buildDir" "$UpstreamDir" --backend ninja --buildtype=plain
if errorlevel 1 exit /b %errorlevel%
"$python" -m mesonbuild.mesonmain compile -C "$buildDir"
if errorlevel 1 exit /b %errorlevel%
"@ | Set-Content $buildCmd -Encoding ascii
    & cmd.exe /d /c $buildCmd
    if ($LASTEXITCODE -ne 0) { throw "Meson/MSVC build failed with code $LASTEXITCODE." }
    $candidates = @(Get-ChildItem $buildDir -Recurse -File -Filter 'plpgsql_check.dll')
    if ($candidates.Count -ne 1) { throw "Expected one built plpgsql_check.dll; found $($candidates.Count)." }
    $dll = Join-Path $UpstreamDir 'plpgsql_check.dll'
    Copy-Item $candidates[0].FullName $dll -Force

    @"
@echo off
call "$devCmd" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b %errorlevel%
dumpbin /nologo /exports "$dll"
if errorlevel 1 exit /b %errorlevel%
"@ | Set-Content $dumpCmd -Encoding ascii
    $lines = @(& cmd.exe /d /c $dumpCmd)
    if ($LASTEXITCODE -ne 0) { throw 'dumpbin /exports failed.' }
    $observed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($line in $lines) {
        if ($line -match '^\s*\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)') {
            [void]$observed.Add($Matches[1])
        }
    }
    foreach ($name in $exports) {
        if (-not $observed.Contains($name)) { throw "Required undecorated export missing: $name" }
    }
    Write-Host "Verified $($exports.Count) DLL exports for PG$pgMajor from pinned $actualSha."
    $lines | ForEach-Object { Write-Host $_ }
}
finally {
    Remove-Item $buildCmd, $dumpCmd -Force -ErrorAction SilentlyContinue
}
 -or $manifest.upstream.repository -cne 'okbob/plpgsql_check') {
    throw 'Missing or malformed plpgsql_check upstream source identity.'
}
$actualSha = (& git -C $UpstreamDir rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualSha -cne $expectedSha) {
    throw "Upstream source identity mismatch; expected $expectedSha, got '$actualSha'."
}
$pgConfig = Join-Path $PgRoot 'bin\pg_config.exe'
if (-not (Test-Path $pgConfig)) { throw "Missing pg_config: $pgConfig" }
$pgVersion = (& $pgConfig --version).Trim()
if ($LASTEXITCODE -ne 0 -or $pgVersion -notmatch '^PostgreSQL\s+(1[5-8])(?:\.|\s)') {
    throw "Only PG15-18 are approved for this pilot: $pgVersion"
}
$pgMajor = [int]$Matches[1]

$controlPath = Join-Path $UpstreamDir 'plpgsql_check.control'
$control = Get-Content $controlPath -Raw
$controlMatch = [regex]::Match($control, "(?m)^default_version\s*=\s*'([^']+)'")
if (-not $controlMatch.Success -or $controlMatch.Groups[1].Value -ne '2.10') {
    throw 'Expected upstream SQL default_version 2.10 was not found; aborting.'
}
$sqlPath = Join-Path $UpstreamDir 'plpgsql_check--2.10.sql'
if (-not (Test-Path $sqlPath)) { throw 'The control-required SQL install script is missing.' }
$mesonPath = Join-Path $UpstreamDir 'meson.build'
$meson = Get-Content $mesonPath -Raw
if ($meson -notmatch ("project\('plpgsql_check',\s*\['c'\],\s*version:\s*'" + [regex]::Escape($expectedVersion) + "'\)")) {
    throw 'Upstream Meson project version or structure changed unexpectedly.'
}
$magicSource = Get-Content (Join-Path $UpstreamDir 'src\plpgsql_check.c') -Raw
if ($magicSource -notmatch '\bPG_MODULE_MAGIC(_EXT)?\b' -or $magicSource -notmatch 'void\s+_PG_init\s*\(void\)') {
    throw 'Upstream module magic or _PG_init declaration is missing.'
}

# Cross-audit SQL C entry points against PG_FUNCTION_INFO_V1 definitions.
# A DEF is needed for Windows versions whose extension symbols are not auto-exported.
$symbols = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$sourceFiles = @(Get-ChildItem (Join-Path $UpstreamDir 'src') -Filter '*.c' -File)
if ($sourceFiles.Count -lt 10) { throw 'Unexpected upstream C source inventory.' }
foreach ($f in $sourceFiles) {
    $text = Get-Content $f.FullName -Raw
    foreach ($m in [regex]::Matches($text, '\bPG_FUNCTION_INFO_V1\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')) {
        [void]$symbols.Add($m.Groups[1].Value)
    }
}
# The independent list below was audited against the pinned upstream SQL and C
# sources, not guessed from filenames. It keeps a reviewable export contract.
$audit = Get-Content (Join-Path $PSScriptRoot '..\..\config\export-audit.json') -Raw | ConvertFrom-Json
if ($audit.schemaVersion -ne 1 -or $audit.upstreamCommit -cne $expectedSha -or
    $audit.sqlExtensionVersion -cne '2.10' -or
    $audit.moduleMagicExport -cne 'Pg_magic_func' -or
    $audit.moduleInitializerExport -cne '_PG_init') {
    throw 'Independent export audit metadata does not match pinned upstream.'
}
$approved = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($name in @($audit.requiredSqlSymbols)) {
    if (-not $approved.Add([string]$name)) { throw "Duplicate audited symbol: $name" }
}
if ($approved.Count -ne 23) { throw "Expected 23 independently audited SQL symbols; found $($approved.Count)." }
$sql = Get-Content $sqlPath -Raw
$sqlMatches = [regex]::Matches($sql, "(?is)\bAS\s*'MODULE_PATHNAME'\s*,\s*'(?<symbol>[A-Za-z_][A-Za-z0-9_]*)'\s+LANGUAGE\s+C\b")
$sqlExports = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($m in $sqlMatches) {
    [void]$sqlExports.Add($m.Groups['symbol'].Value)
}
foreach ($name in $approved) {
    if (-not $symbols.Contains($name) -or -not $sqlExports.Contains($name)) {
        throw "Audited SQL symbol '$name' is missing from pinned C declarations or extension SQL."
    }
}
if ($symbols.Count -ne $approved.Count -or $sqlExports.Count -ne $approved.Count) {
    throw "New/removed C or SQL symbols require an explicit export audit update: C=$($symbols.Count), SQL=$($sqlExports.Count), expected=$($approved.Count)."
}

$exports = @($audit.moduleMagicExport, $audit.moduleInitializerExport) + @($approved | ForEach-Object { $_; "pg_finfo_$_" })
$exports = @($exports | Sort-Object -Unique -CaseSensitive)
$defFile = Join-Path $UpstreamDir 'pgextwin.exports.def'
[IO.File]::WriteAllLines($defFile, [string[]](@('LIBRARY plpgsql_check', 'EXPORTS') + @($exports | ForEach-Object { "    $_" })), [Text.Encoding]::ASCII)

# Apply a single fail-closed Meson adaptation only to the disposable SHA-verified checkout.
$marker = '  dependencies: postgres_lib,'
if (([regex]::Matches($meson, [regex]::Escape($marker))).Count -ne 1 -or
    $meson -notmatch '(?s)module_lib\s*=\s*shared_module\(') {
    throw 'Expected upstream shared_module block differs; refusing blind patch.'
}
$meson = $meson.Replace($marker, $marker + "`n  vs_module_defs: 'pgextwin.exports.def',")
[IO.File]::WriteAllText($mesonPath, $meson, [Text.UTF8Encoding]::new($false))

$vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "Missing vswhere: $vswhere" }
$vsRoot = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsRoot)) { throw 'VS C++ toolset not found.' }
$devCmd = Join-Path $vsRoot.Trim() 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $devCmd)) { throw "Missing VS developer command: $devCmd" }

$python = (Get-Command python.exe -ErrorAction Stop).Source
& $python -m pip install --disable-pip-version-check --quiet 'meson==1.8.3' 'ninja==1.11.1.4'
if ($LASTEXITCODE -ne 0) { throw 'Pinned Meson/Ninja installation failed.' }
$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$buildDir = Join-Path $tempRoot 'plpgsql-check-meson-build'
$buildCmd = Join-Path $tempRoot 'plpgsql-check-build.cmd'
$dumpCmd = Join-Path $tempRoot 'plpgsql-check-dump.cmd'
try {
    if (Test-Path $buildDir) { Remove-Item $buildDir -Recurse -Force }
    @"
@echo off
call "$devCmd" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b %errorlevel%
set "PATH=$PgRoot\bin;%PATH%"
"$python" -m mesonbuild.mesonmain setup "$buildDir" "$UpstreamDir" --backend ninja --buildtype=plain
if errorlevel 1 exit /b %errorlevel%
"$python" -m mesonbuild.mesonmain compile -C "$buildDir"
if errorlevel 1 exit /b %errorlevel%
"@ | Set-Content $buildCmd -Encoding ascii
    & cmd.exe /d /c $buildCmd
    if ($LASTEXITCODE -ne 0) { throw "Meson/MSVC build failed with code $LASTEXITCODE." }
    $candidates = @(Get-ChildItem $buildDir -Recurse -File -Filter 'plpgsql_check.dll')
    if ($candidates.Count -ne 1) { throw "Expected one built plpgsql_check.dll; found $($candidates.Count)." }
    $dll = Join-Path $UpstreamDir 'plpgsql_check.dll'
    Copy-Item $candidates[0].FullName $dll -Force

    @"
@echo off
call "$devCmd" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b %errorlevel%
dumpbin /nologo /exports "$dll"
if errorlevel 1 exit /b %errorlevel%
"@ | Set-Content $dumpCmd -Encoding ascii
    $lines = @(& cmd.exe /d /c $dumpCmd)
    if ($LASTEXITCODE -ne 0) { throw 'dumpbin /exports failed.' }
    $observed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($line in $lines) {
        if ($line -match '^\s*\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)') {
            [void]$observed.Add($Matches[1])
        }
    }
    foreach ($name in $exports) {
        if (-not $observed.Contains($name)) { throw "Required undecorated export missing: $name" }
    }
    Write-Host "Verified $($exports.Count) DLL exports for PG$pgMajor from pinned $actualSha."
    $lines | ForEach-Object { Write-Host $_ }
}
finally {
    Remove-Item $buildCmd, $dumpCmd -Force -ErrorAction SilentlyContinue
}
