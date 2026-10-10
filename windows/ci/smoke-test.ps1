[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PgRoot,
    [Parameter(Mandatory = $true)][int]$PgPort,
    [Parameter(Mandatory = $true)][int]$PostgreSqlMajor
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PostgreSqlMajor -notin @(14,15,16,17,18)) { throw "Unsupported PostgreSQL major: $PostgreSqlMajor" }
$pgVersion = (& (Join-Path $PgRoot 'bin\pg_config.exe') --version).Trim()
if ($LASTEXITCODE -ne 0 -or $pgVersion -notmatch ('^PostgreSQL\s+' + $PostgreSqlMajor + '(?:\.|\s)')) {
    throw "PG root/runner major mismatch: expected $PostgreSqlMajor, found $pgVersion"
}
$initdb = Join-Path $PgRoot 'bin\initdb.exe'
$pgCtl = Join-Path $PgRoot 'bin\pg_ctl.exe'
$pgIsReady = Join-Path $PgRoot 'bin\pg_isready.exe'
$psql = Join-Path $PgRoot 'bin\psql.exe'
foreach ($exe in @($initdb,$pgCtl,$pgIsReady,$psql)) {
    if (-not (Test-Path $exe)) { throw "Missing PostgreSQL executable: $exe" }
}
$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$testRoot = Join-Path $tempRoot ('plpgsql-check-pg' + $PostgreSqlMajor + '-' + [Guid]::NewGuid().ToString('N'))
$dataDir = Join-Path $testRoot 'data'
$serverLog = Join-Path $testRoot 'postgres.log'
$sqlPath = Join-Path $testRoot 'functional.sql'
$started = $false

function Print-ServerLog {
    if (Test-Path $serverLog) {
        Write-Host '----- PostgreSQL diagnostic server log -----'
        Get-Content $serverLog -Tail 250 | ForEach-Object { Write-Host $_ }
        Write-Host '------------------------------------------'
    }
}

New-Item -Path $testRoot -ItemType Directory -Force | Out-Null
try {
    & $initdb -D $dataDir -U postgres -A trust --encoding=UTF8 --no-locale
    if ($LASTEXITCODE -ne 0) { throw "initdb failed with code $LASTEXITCODE." }
    # No shared_preload_libraries: prove normal active diagnostics need no preload.
    $pgOptions = "-p $PgPort -c listen_addresses=127.0.0.1"
    & $pgCtl -D $dataDir -l $serverLog -o $pgOptions start
    if ($LASTEXITCODE -ne 0) { throw "pg_ctl start failed: $LASTEXITCODE" }
    $started = $true
    $ready = $false
    for ($i = 0; $i -lt 45; $i++) {
        & $pgIsReady -h 127.0.0.1 -p $PgPort -q
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) { throw 'Temporary PostgreSQL server did not reach ready state.' }

    # Validate the SQL diagnostic itself; a mere SQL failure never counts as a pass.
    @'
\set ON_ERROR_STOP on
CREATE EXTENSION plpgsql_check;
DO $verify$
BEGIN
  IF (SELECT extversion FROM pg_extension WHERE extname = 'plpgsql_check')
      IS DISTINCT FROM '2.10' THEN
    RAISE EXCEPTION 'Unexpected plpgsql_check SQL extension version';
  END IF;
END
$verify$;
CREATE TABLE public.pgextwin_plpgsql_check_probe (a integer NOT NULL);
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM public.pgextwin_plpgsql_check_probe) THEN
    RAISE EXCEPTION 'Probe table must be empty';
  END IF;
END $$;
CREATE FUNCTION public.pgextwin_plpgsql_check_bad() RETURNS void LANGUAGE plpgsql AS $fn$
DECLARE r record;
BEGIN
  FOR r IN SELECT a FROM public.pgextwin_plpgsql_check_probe LOOP
    RAISE NOTICE '%', r.missing;
  END LOOP;
END
$fn$;
DO $$
DECLARE matches_count integer;
BEGIN
  SELECT count(*) INTO matches_count
  FROM plpgsql_check_function_tb('public.pgextwin_plpgsql_check_bad()'::regprocedure)
  WHERE lower(message) LIKE '%missing%'
    AND lower(message) ~ '(field|record|attribute)';
  IF matches_count < 1 THEN
    RAISE EXCEPTION 'detect-invalid-record-field: specific diagnostic not found';
  END IF;
END $$;
CREATE OR REPLACE FUNCTION public.pgextwin_plpgsql_check_bad() RETURNS void LANGUAGE plpgsql AS $fn$
DECLARE r record;
BEGIN
  FOR r IN SELECT a FROM public.pgextwin_plpgsql_check_probe LOOP
    RAISE NOTICE '%', r.a;
  END LOOP;
END
$fn$;
DO $$
DECLARE matches_count integer;
DECLARE errors_count integer;
BEGIN
  SELECT count(*) FILTER (
           WHERE lower(message) LIKE '%missing%'
           AND lower(message) ~ '(field|record|attribute)'
         ),
         count(*) FILTER (WHERE lower(level) ~ '(error|fatal)')
  INTO matches_count, errors_count
  FROM plpgsql_check_function_tb('public.pgextwin_plpgsql_check_bad()'::regprocedure);
  IF matches_count <> 0 OR errors_count <> 0 THEN
    RAISE EXCEPTION 'Corrected function still reports a diagnostic: matched %, errors %',
      matches_count, errors_count;
  END IF;
END $$;
DROP FUNCTION public.pgextwin_plpgsql_check_bad();
DROP TABLE public.pgextwin_plpgsql_check_probe;
DROP EXTENSION plpgsql_check;
'@ | Set-Content $sqlPath -Encoding utf8

    & $psql -X -w -h 127.0.0.1 -p $PgPort -U postgres -d postgres -v ON_ERROR_STOP=1 -f $sqlPath
    if ($LASTEXITCODE -ne 0) { throw "detect-invalid-record-field SQL assertions failed with psql code $LASTEXITCODE" }
    Write-Host "SUCCESS: PG$PostgreSqlMajor CREATE EXTENSION and detect-invalid-record-field on empty table; correction verified."
}
catch {
    Print-ServerLog
    throw
}
finally {
    if ($started -or (Test-Path (Join-Path $dataDir 'postmaster.pid'))) {
        try {
            & $pgCtl -D $dataDir -m fast stop
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Graceful pg_ctl stop returned $LASTEXITCODE; trying immediate shutdown."
                & $pgCtl -D $dataDir -m immediate stop
                if ($LASTEXITCODE -ne 0) { Write-Warning "Immediate pg_ctl stop also failed ($LASTEXITCODE)." }
            }
        }
        catch { Write-Warning "Could not stop temporary PostgreSQL server: $_" }
    }
    # Logs were printed before cleanup on error; on success they are disposable.
    if (Test-Path $testRoot) {
        try { Remove-Item $testRoot -Recurse -Force -ErrorAction Stop }
        catch { Write-Warning "Could not remove temporary test directory $testRoot : $_" }
    }
}
