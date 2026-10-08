"""Offline contract sanity checks. Canonical schemas are enforced by the reusable CI."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_COMMIT = '61776b0af7418d3fd593cccea73178e3d93c9ee1'
BUILD_COMMIT = '2c6cd6a5b122f0ba1870e9d70cb84cc949bd281d'


def json_file(relative):
    return json.loads((ROOT / relative).read_text(encoding='utf-8'))


class ContractSanityChecks(unittest.TestCase):
    def test_manifest_matrix_and_source(self):
        manifest = json_file('config/extension.json')
        self.assertEqual(manifest['schemaVersion'], 1)
        self.assertEqual(manifest['name'], 'plpgsql_check')
        self.assertEqual(manifest['upstream'], {
            'repository': 'okbob/plpgsql_check',
            'ref': 'v2.10.13',
            'version': '2.10.13',
        })
        self.assertEqual(manifest['postgresql']['majors'], [15, 16, 17, 18])
        self.assertEqual(manifest['windows']['architecture'], 'x64')
        self.assertTrue(manifest['license']['verifyAgainstUpstream'])

    def test_license_is_identical_git_blob(self):
        result = subprocess.run(
            ['git', 'hash-object', str(ROOT / 'LICENSE')],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(result.stdout.strip(), '994f55c62ea0dfedfd915d1559f8f27d386d4989')

    def test_contract_semantics(self):
        c = json_file('config/test-contract.json')
        self.assertEqual(c['contractVersion'], 2)
        self.assertEqual(c['extension'], 'plpgsql_check')
        self.assertEqual(c['runtimeRequirements']['extensionCreation'], 'required')
        self.assertEqual(c['runtimeRequirements']['preload'], 'optional')
        self.assertFalse(c['runtimeRequirements']['backgroundWorker'])
        self.assertFalse(c['runtimeRequirements']['clientExecutable']['required'])
        self.assertEqual(c['testSetup']['preload'], 'none')
        self.assertEqual(c['coverage']['upgrade'], 'not-covered')
        self.assertEqual(c['coverage']['createExtension'], 'covered')
        scenarios = c['functionalScenarios']
        self.assertEqual([x['id'] for x in scenarios], ['detect-invalid-record-field'])
        self.assertTrue((ROOT / c['smokeTest']['script']).is_file())

    def test_hooks_present_and_pinned(self):
        for name in ('build', 'install', 'smoke-test', 'package'):
            self.assertTrue((ROOT / 'windows' / 'ci' / (name + '.ps1')).is_file())
        for name in ('build', 'package'):
            self.assertIn(UPSTREAM_COMMIT, (ROOT / 'windows' / 'ci' / (name + '.ps1')).read_text())

    def test_github_workflows_are_read_only_and_not_release(self):
        workflow = ROOT / '.github/workflows/windows.yml'
        content = workflow.read_text()
        doc = yaml.load(content, Loader=yaml.BaseLoader)
        self.assertEqual(doc['permissions'], {'contents': 'read'})
        self.assertEqual(set(doc['jobs']), {'windows'})
        self.assertIn(f'@{BUILD_COMMIT}', content)
        self.assertNotIn('release-extension.yml', content)
        self.assertNotIn('id-token: write', content)
        self.assertNotIn('attestations: write', content)
        self.assertNotIn('contents: write', content)

    def test_watcher_metadata_only(self):
        w = json_file('config/update-watch.json')
        self.assertEqual(w['strategy'], 'github-releases')
        self.assertEqual(w['repository'], 'okbob/plpgsql_check')
        self.assertFalse(w['prereleases'])
        self.assertIsNotNone(re.fullmatch(w['stableTagPattern'], 'v2.10.13'))
        for test in ('v2.10.13-rc1', 'v2.10.13-beta1', 'main'):
            self.assertIsNone(re.fullmatch(w['stableTagPattern'], test))
        yml = (ROOT / '.github/workflows/update-watch.yml').read_text()
        self.assertIn(f'@{BUILD_COMMIT}', yml)
        self.assertIn('issues: write', yml)
        self.assertNotIn('contents: write', yml)

    def test_export_audit_is_complete_and_immutable(self):
        c = json_file('config/export-audit.json')
        self.assertEqual(c['upstreamCommit'], UPSTREAM_COMMIT)
        self.assertEqual(c['sqlExtensionVersion'], '2.10')
        self.assertEqual(c['moduleMagicExport'], 'Pg_magic_func')
        self.assertEqual(c['moduleInitializerExport'], '_PG_init')
        self.assertEqual(len(c['requiredSqlSymbols']), 23)
        self.assertEqual(len(set(c['requiredSqlSymbols'])), 23)
        script = (ROOT / 'windows/ci/build.ps1').read_text()
        self.assertIn(r'config\export-audit.json', script)
        self.assertIn('dumpbin /nologo /exports', script)

    def test_sql_assertion_checks_real_diagnostic(self):
        script = (ROOT / 'windows/ci/smoke-test.ps1').read_text()
        for expected in (
            "CREATE EXTENSION plpgsql_check",
            'plpgsql_check_function_tb',
            'r.missing',
            'r.a',
            'matches_count < 1',
            'matches_count <> 0',
            'RAISE EXCEPTION',
            'finally',
        ):
            self.assertIn(expected, script)
        self.assertNotIn('shared_preload_libraries=plpgsql_check', script)

    def test_package_contains_dynamic_sql_version(self):
        script = (ROOT / 'windows/ci/package.ps1').read_text()
        self.assertIn('default_version', script)
        self.assertIn('plpgsql_check--$sqlVersion.sql', script)
        for term in ('lib\\plpgsql_check.dll', 'share\\extension', 'PACKAGE-INFO.txt'):
            self.assertIn(term, script)


if __name__ == '__main__':
    unittest.main()
