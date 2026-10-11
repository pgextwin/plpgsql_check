# plpgsql_check Windows x64 非公式バイナリ — pgextwin

**日本語** | [English](README.md)

本リポジトリは[plpgsql_check](https://github.com/okbob/plpgsql_check)の**非公式Windows x64ビルド**を提供するpgextwinプロジェクトです。upstream公式プロジェクトやPostgreSQL本体による公式配布ではありません。

最初の正式Releaseは **`v2.10.13-windows.1`**（PG15〜18の4世代）でした。**現在の正式Releaseは`v2.10.14-windows.1`で、PG14〜18の5世代に対応**しています。コミュニティサポート期間内にある全対象世代のWindows実機CI・Attestation検証に合格したものだけを公開します。

**現在のダウンロード：** [v2.10.14-windows.1](https://github.com/pgextwin/plpgsql_check/releases/tag/v2.10.14-windows.1)（PG14〜18）／[全GitHub Releases](https://github.com/pgextwin/plpgsql_check/releases)。[初回のv2.10.13-windows.1](https://github.com/pgextwin/plpgsql_check/releases/tag/v2.10.13-windows.1)はPG15〜18のみです。通常CIのArtifactを署名付き正式版として扱わないでください。

## バージョンを混同しない

| 区分 | 値 |
| --- | --- |
| upstream repository | `okbob/plpgsql_check` |
| upstream stable release / tag | `2.10.14` / `v2.10.14` |
| upstream commit SHA | `ccdbcce9de51f01e1138c270aeb9fe4e26c6e911` |
| SQL extension version | **`2.10`** |
| 最新pgextwin Release tag | **`v2.10.14-windows.1`**（PG14〜18） |
| 対応対象 | Windows x64 / PostgreSQL **14、15、16、17、18**（PG14は2026-11-12まで） |

upstreamの`plpgsql_check.control`は`default_version = '2.10'`で、導入SQLは`plpgsql_check--2.10.sql`です。Release番号に合わせてSQL拡張バージョンを変更しません。**PG14は最新の`v2.10.14-windows.1`に同梱されていますが、初回の`v2.10.13-windows.1`には含まれていません。**PG14の公式サポートは2026年11月12日で終了し、以後は共通ビルドから自動除外します。PG19は対象外です。

## ZIPの選択・導入

PostgreSQLのメジャーバージョンに合うZIPをReleaseから選びます。

- `plpgsql_check-v2.10.14-pg14-windows-x64.zip`
- `plpgsql_check-v2.10.14-pg15-windows-x64.zip`
- `plpgsql_check-v2.10.14-pg16-windows-x64.zip`
- `plpgsql_check-v2.10.14-pg17-windows-x64.zip`
- `plpgsql_check-v2.10.14-pg18-windows-x64.zip`

ビルドとテストではpgextwin共通CIがChocolatey経由で固定バージョンのWindows版PostgreSQLを導入します。そのため、**すべてのWindows向けPostgreSQLディストリビューションとのABI互換性まで保証するものではありません**。メジャー、x64構成、ビルドと実行環境の互換性を確認し、運用前にはバックアップと事前検証を行ってください。

導入は次の順序です。

1. PostgreSQLサービスを停止してから、使用中の既存DLLの上書きを避けます。
2. ZIPの`lib/plpgsql_check.dll`をPostgreSQLの`lib/`へ配置します。
3. ZIPの`share/extension/`内にあるcontrolとSQLファイルをPostgreSQLの`share/extension/`へ配置します。
4. `LICENSE`、`UPSTREAM-README.md`、`PGEXTWIN-README.md`、`PACKAGE-INFO.txt`、`PACKAGE-INFO.json`を保管します。
5. 必要に応じてサービスを起動し、対象データベースで以下を実行します。

~~~sql
CREATE EXTENSION plpgsql_check;
SELECT extversion FROM pg_extension WHERE extname = 'plpgsql_check';
~~~

通常の能動的なPL/pgSQL診断だけなら`shared_preload_libraries`は不要です。profiler、tracer、passive/shared modeなどは追加設定が必要な場合があり、本ReleaseのCIでは検証していません。これらを使う際はupstream文書に従ってください。

## CIで実際に検証している機能

PG14・15・16・17・18のそれぞれでWindows PostgreSQLサーバーを初期化・起動して`CREATE EXTENSION`を実行し、空テーブルを走査する関数の存在しないrecordフィールドを**関数の実行前に**`plpgsql_check_function_tb`で検出します。フィールド参照の修正後は診断が消えることまで確認します。

~~~sql
CREATE TABLE public.t (a integer);
CREATE FUNCTION public.probe() RETURNS void LANGUAGE plpgsql AS $body$
DECLARE r record;
BEGIN
  FOR r IN SELECT a FROM public.t LOOP
    RAISE NOTICE '%', r.missing;
  END LOOP;
END;
$body$;
SELECT message, sqlstate, level
FROM plpgsql_check_function_tb('public.probe()'::regprocedure);
~~~

上の`r.missing`を`r.a`に修正し、同じ診断が出ないことを確認するのがCIシナリオです。upstreamコミット・LICENSE、MSVC/Meson/Ninjaビルド、DLL export、インストール、ZIP構造、PACKAGE-INFO JSON Schema、SPDX 2.3 SBOM、Grypeの動作も検証します。

**未検証：** profiler、tracer、passive/shared mode、server log assertion、SQL upgrade実行、PG majorをまたぐupgrade。拡張機能が持つすべての機能が検証済みという意味ではありません。

## SHA-256・SBOM・Attestation

Releaseには各majorのZIPに加え`*.spdx.json`（SPDX 2.3 SBOM）、`*.vulnerabilities.json`（Grype結果）、`SHA256SUMS.txt`を添付します。ZIPには`PACKAGE-INFO.json`が入ります。

PowerShellでファイルのSHA-256を計算し、`SHA256SUMS.txt`の該当行と比較してください。

~~~powershell
Get-Content .\SHA256SUMS.txt
(Get-FileHash .\plpgsql_check-v2.10.14-pg17-windows-x64.zip -Algorithm SHA256).Hash
~~~

各ZIP・各SPDXファイル・各脆弱性レポートについて確認します。Attestationの対象は**最終ZIPのdigest**です。Attestation生成後にZIPを変更しません。

**Build Provenance AttestationとSBOM AttestationはGitHub側に保存されます。Release assetとしての個別ファイルは存在しません。** 認証済みGitHub CLIで以下を実行します。

~~~powershell
gh attestation verify .\plpgsql_check-v2.10.14-pg17-windows-x64.zip --repo pgextwin/plpgsql_check --signer-workflow pgextwin/build/.github/workflows/build-extension-attested.yml
gh attestation verify .\plpgsql_check-v2.10.14-pg17-windows-x64.zip --repo pgextwin/plpgsql_check --signer-workflow pgextwin/build/.github/workflows/build-extension-attested.yml --predicate-type https://spdx.dev/Document/v2.3
~~~

各majorについて同様に検証できます。呼出元は`pgextwin/plpgsql_check`、署名workflowは`pgextwin/build/.github/workflows/build-extension-attested.yml`で、immutable full-SHAへpinされます。CIでは署名付きSPDX predicateと公開用SPDX JSONの一致も検証します。

Grypeは**report-only**です。スキャン自体の失敗はCI失敗ですが、脆弱性が検出されたという理由だけでは配布を停止しません。検出ゼロでも安全性の証明ではなく、ビルド時点の脆弱性DBによる分析です。

## GitHub Actionsの権限境界

通常のPR/main CIは読み取り権限でWindowsビルド・実機機能テストを行います。正式公開は信頼された`main`から人が`promote.yml`の`workflow_dispatch`を起動し、`confirm_release=PUBLISH`を明示入力した場合に限ります。自動生成候補PRのマージ、上流監視・candidate-auditのSHA固定証跡、PG14〜18の署名付きWindowsビルド、ZIP/SBOM/GrypeのSHA256とGitHub Attestationを必須とし、**第三者のPR承認と別の承認JSON PRは不要**です。初回の`v2.10.13-windows.1`は旧方式で4世代を公開した履歴です。

新方式ではReleaseタグを一度だけ予約するため、**公開済み・公開途中のPromotionを再実行したり、Releaseタグや成果物を上書きしたりしないでください**。Draftまで作成されて停止した場合は、既存成果物のハッシュを独立検証してから対象Draftだけを復旧します。

[Step 16技術Pilotの履歴](docs/technical-pilot.md)と[共通Attestation解説](https://github.com/pgextwin/build/blob/main/docs/artifact-attestations.md)も参照してください。
