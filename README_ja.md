# plpgsql_check Windows版 — pgextwin Step 16 技術Pilot

日本語 | [English](README.md)

**状態：実装案・技術Pilot。正式GitHub Releaseおよび配布バイナリは未公開です。** このリポジトリは、[plpgsql_check](https://github.com/okbob/plpgsql_check)を通常のWindows x64 PostgreSQL向けに非公式にビルドするためのpgextwin用です。upstreamの公式プロジェクトとは独立しています。

## ソース、対応バージョンとライセンス

- Upstream安定版：`v2.10.13`（2026-10-07 UTC公開）。
- Tag object SHA：`72fa03e2bfc78289bdb4ef732024eefb5e707c64`。
- Tagが指すcommit SHA：`61776b0af7418d3fd593cccea73178e3d93c9ee1`。
- 対象：**PostgreSQL 15・16・17・18 / Windows x64**。PG14・PG19は対象外。
- Upstream Releaseは**2.10.13**ですが、`plpgsql_check.control`の`default_version`は**2.10**で、インストール用SQLは`plpgsql_check--2.10.sql`です。これらを混同しません。
- LICENSE本文はMIT形式。配布時はupstreamの原本を保持します。LICENSEのGit blob SHA：`994f55c62ea0dfedfd915d1559f8f27d386d4989`。

## 基本的な使い方

後続Stepで実機検証を通過し正式公開が認められた場合、PostgreSQL majorに一致するZIPを選択します。PostgreSQL停止後にDLLを`lib/`へ、controlとSQLを`share/extension/`へコピーし、必要に応じて再起動したうえで以下を実行します。

```sql
CREATE EXTENSION plpgsql_check;
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
```

テーブルが空でも、関数の実行前に存在しないrecord fieldを検出する診断が基本的な利用方法です。CIではエラーの内容を検証し、`r.a`へ修正した後は同じ診断が出ないことを確認する設計です。

## preload要件

通常の`plpgsql_check_function_tb`による能動的な診断には、**shared_preload_librariesは不要**です。profiler、tracer、passive/shared modeなどの高度機能は別の設定や事前ロードが関係するため、今回の保証・テスト範囲には含めていません。最低限の診断用途で専用クライアント実行ファイルやbackground workerは不要です。

## Windowsビルド方式

既存のpgextwin共通Buildをfull-SHAで参照し、Windows Hook Contract v1の4本のPowerShell hookを使用します。MSVC x64、Meson、Ninja、対象PGのpg_configとpostgres.libを使用します。upstreamのimmutable tagとcommitを確認してから、使い捨てcheckoutに限定してWindows DEF export設定を追加します。SQLのCエントリーポイントとPG_FUNCTION_INFO_V1を照合し、独立した23個のsymbol監査記録（`config/export-audit.json`）との一致を確かめた上で、完成DLLをdumpbinで検証します。PG15〜18それぞれについて別個にbuild、install、CREATE EXTENSION、診断機能、ZIP構成を確認します。

共通Build側でPACKAGE-INFO.json、SPDX 2.3 SBOM、Grype（report-only）、checksumを扱います。通常CIではAttestationは作成しません。今回のworkflowにはRelease公開ジョブを含めません。更新監視もGitHub Issue通知のみです。

## 未検証事項・制限

- **この設計のWindows実機CIはまだ成功確認されていません。** PG15〜18の成功は、実行結果を確認するまで宣言しません。
- Windowsのpostgres.libにおける依存シンボルと、PL/pgSQL内部関数の動的解決は重要な検証ポイントです。
- profiler、tracer、passive/shared mode、アップグレードSQLの実行検証、異なるPG major間のアップグレードは対象外です。
- LICENSE、README、upstream source provenanceを維持し、公式upstream配布と誤認される表示をしません。
- Release、Distribution Catalog配布登録、Websiteのダウンロードリンク、PG19 production metadata変更は今回行いません。

[技術Pilotの補足資料](docs/technical-pilot.md)も参照してください。

## リポジトリ作成と事前検査

管理者が `gh` を認証したWindows環境では、同梱の [`scripts/bootstrap-repo.ps1`](scripts/bootstrap-repo.ps1) でOrganization内の空リポジトリ作成・レビュー用ブランチpush・Draft PR作成まで実施できます。手順は[こちら](docs/BOOTSTRAP.md)。`python -m unittest discover -s tests -v` でオフライン静的検査もできますが、Windows実機CIの代わりにはなりません。
