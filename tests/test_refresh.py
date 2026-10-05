import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import refresh_snis as refresh


REPO = Path(__file__).resolve().parents[1]


class SourceTests(unittest.TestCase):
    def test_rejects_html_truncated_and_invalid_sources(self):
        for text in (
            '<html>upstream error</html>',
            'Rank,Domain\n1,good.ru\n',
            'Rank,Domain\n1,-bad.ru\n2,good.ru\n',
            'Rank,Domain\n1,good.ru\n2,good.ru\n',
            'Rank,Domain\n0,good.ru\n2,other.ru\n',
            'Rank,Domain\n1,good.com\n2,other.ru\n',
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                refresh.read_source(text, minimum=2)

    def test_normalizes_csv_domains(self):
        self.assertEqual(refresh.read_source(
            '\ufeffRank,Domain\n1, Good.RU \n2,xn--p1ai.ru\n', minimum=2),
            {'good.ru': 1, 'xn--p1ai.ru': 2})

    def test_source_shrinkage_is_rejected(self):
        data = ('Rank,Domain\n' + ''.join(
            f'{index + 1},site{index}.ru\n' for index in range(1000))).encode()
        with patch.object(refresh.urllib.request, 'urlopen', side_effect=lambda *a, **k: io.BytesIO(data)), \
                patch.object(refresh.time, 'sleep'), self.assertRaises(ValueError):
            refresh.download_source(previous_count=3000)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.stage = self.root / 'stage'
        self.destination = self.root / 'tracked'
        self.stage.mkdir()
        self.destination.mkdir()
        self.domains = {'good.ru': 1, 'bad.ru': 2}
        self.seeds = ['extra.ru']
        self.rows = {
            host: {'host': host, 'eligible': host in ('good.ru', 'extra.ru'),
                   'tls_ok': host in ('good.ru', 'extra.ru'),
                   'tls': 'TLSv1.3', 'alpn': 'h2', 'certificate_valid': True,
                   'http_status': 200 if host in ('good.ru', 'extra.ru') else 403,
                   'ip': '8.8.8.8', 'checked_utc': '2026-10-05T00:00:00+00:00'}
            for host in ('good.ru', 'bad.ru', 'www.bad.ru', 'extra.ru')
        }
        self.keys = {
            host: {'host': host, 'ip': '8.8.8.8', 'passed': True}
            for host in ('good.ru', 'extra.ru')
        }
        (self.stage / 'russian-sni-source.csv').write_text('Rank,Domain\n1,good.ru\n2,bad.ru\n')
        (self.stage / 'russian-reality-snis.original.txt').write_text('extra.ru\n')
        for filename in refresh.OUTPUT_FILES:
            (self.destination / filename).write_bytes(b'original snapshot\n')
        self.export()

    def export(self):
        for filename, rows in (
            ('sni-verification.jsonl', self.rows),
            ('sni-x25519-verification.jsonl', self.keys),
        ):
            (self.stage / filename).write_text(''.join(json.dumps(row) + '\n' for row in rows.values()))
        subprocess.run([sys.executable, str(REPO / 'export_snis.py'),
                        '--directory', str(self.stage), '--origin', 'test network'],
                       check=True, capture_output=True, text=True)

    def assert_preserved_after_rejection(self, previous_count=2, ratio=0.5):
        with self.assertRaises(ValueError):
            refresh.publish_snapshot(self.stage, self.destination, self.domains,
                                     self.seeds, previous_count, ratio)
        for filename in refresh.OUTPUT_FILES:
            self.assertEqual((self.destination / filename).read_bytes(), b'original snapshot\n')

    def test_success_publishes_all_matching_data_and_keeps_history(self):
        original = self.destination / 'russian-reality-snis.original.txt'
        original.write_text('historic seed\n')
        summary = refresh.publish_snapshot(self.stage, self.destination, self.domains,
                                           self.seeds, 2, 0.5)
        self.assertEqual(summary['selected_hosts'], 2)
        self.assertEqual(summary['verification_origin'], 'test network')
        self.assertEqual(original.read_text(), 'historic seed\n')
        for filename in refresh.OUTPUT_FILES:
            self.assertEqual((self.destination / filename).read_bytes(),
                             (self.stage / filename).read_bytes())

    def test_missing_source_seed_and_fallback_leave_snapshot_untouched(self):
        for host in ('good.ru', 'extra.ru', 'www.bad.ru'):
            with self.subTest(host=host):
                row = self.rows.pop(host)
                self.export()
                self.assert_preserved_after_rejection()
                self.rows[host] = row

    def test_missing_or_wrong_ip_key_check_leaves_snapshot_untouched(self):
        self.keys.pop('extra.ru')
        self.export()
        self.assert_preserved_after_rejection()
        self.keys['extra.ru'] = {'host': 'extra.ru', 'ip': '1.1.1.1', 'passed': True}
        self.export()
        self.assert_preserved_after_rejection()

    def test_empty_list_and_large_drop_leave_snapshot_untouched(self):
        self.assert_preserved_after_rejection(previous_count=5)
        for check in self.keys.values():
            check['passed'] = False
        self.export()
        self.assert_preserved_after_rejection(ratio=0)

    def test_reviewed_drop_can_be_accepted_with_lower_threshold(self):
        self.assertEqual(refresh.validate_snapshot(self.stage, self.domains, self.seeds,
                                                    previous_count=5, minimum_ratio=0.4)
                         ['selected_hosts'], 2)

    def test_tampered_list_summary_and_csv_are_rejected(self):
        (self.stage / 'russian-reality-snis.txt').write_text('bad.ru\n')
        self.assert_preserved_after_rejection()
        self.export()
        path = self.stage / 'sni-verification-summary.json'
        summary = json.loads(path.read_text())
        summary['checked_unique_hosts'] = 99
        path.write_text(json.dumps(summary))
        self.assert_preserved_after_rejection()
        self.export()
        (self.stage / 'sni-verification.csv').write_text('host,included\ngood.ru,True\n')
        self.assert_preserved_after_rejection()

    def test_public_ipv4_is_required(self):
        self.rows['extra.ru']['ip'] = '127.0.0.1'
        self.keys['extra.ru']['ip'] = '127.0.0.1'
        self.export()
        self.assert_preserved_after_rejection()

    def test_incomplete_seed_and_contradictory_protocol_are_rejected(self):
        row = self.rows['extra.ru'].copy()
        self.rows['extra.ru'] = {'host': 'extra.ru'}
        self.export()
        self.assert_preserved_after_rejection()
        self.rows['extra.ru'] = row
        self.rows['extra.ru']['tls'] = 'TLSv1.2'
        self.export()
        self.assert_preserved_after_rejection()

    def test_full_refresh_orchestration_publishes_validated_snapshot(self):
        (self.destination / 'russian-sni-source.csv').write_text('Rank,Domain\n1,good.ru\n')
        (self.destination / 'russian-reality-snis.txt').write_text('extra.ru\n')
        (self.destination / 'russian-reality-snis.original.txt').write_text('extra.ru\n')
        stage = self.root / 'fresh'
        real_run = subprocess.run

        def run(command, **kwargs):
            script = Path(command[1]).name
            if script == 'export_snis.py':
                command[1] = str(REPO / script)
                return real_run(command, capture_output=True, **kwargs)
            filename, rows = (
                ('sni-verification.jsonl', self.rows) if script == 'verify_snis.py'
                else ('sni-x25519-verification.jsonl', self.keys)
            )
            (stage / filename).write_text(''.join(json.dumps(row) + '\n' for row in rows.values()))
            return subprocess.CompletedProcess(command, 0)

        with patch.object(refresh, 'BASE', self.destination), \
                patch.object(sys, 'argv', ['refresh_snis.py', '--stage-dir', str(stage)]), \
                patch.object(refresh, 'download_source', return_value=self.domains), \
                patch.object(refresh.subprocess, 'run', side_effect=run), \
                patch.object(sys, 'stdout', new_callable=io.StringIO):
            refresh.main()
        self.assertEqual((stage / 'previous-snis.txt').read_text(), 'extra.ru\n')
        self.assertEqual((self.destination / 'russian-reality-snis.txt').read_text(),
                         'extra.ru\ngood.ru\n')
        for filename in refresh.OUTPUT_FILES:
            self.assertEqual((self.destination / filename).read_bytes(), (stage / filename).read_bytes())

    def test_scan_process_failure_preserves_tracked_files(self):
        (self.destination / 'russian-sni-source.csv').write_text('Rank,Domain\n1,good.ru\n')
        (self.destination / 'russian-reality-snis.txt').write_text('extra.ru\n')
        (self.destination / 'russian-reality-snis.original.txt').write_text('extra.ru\n')
        before = {name: (self.destination / name).read_bytes() for name in refresh.OUTPUT_FILES}
        with patch.object(refresh, 'BASE', self.destination), \
                patch.object(sys, 'argv', ['refresh_snis.py', '--stage-dir', str(self.root / 'fresh')]), \
                patch.object(refresh, 'download_source', return_value=self.domains), \
                patch.object(refresh.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'scan')), \
                self.assertRaises(subprocess.CalledProcessError):
            refresh.main()
        for name, content in before.items():
            self.assertEqual((self.destination / name).read_bytes(), content)

    def test_invalid_thresholds_are_rejected(self):
        for ratio in (-1, 1.1, float('nan'), float('inf')):
            with self.subTest(ratio=ratio), self.assertRaises(ValueError):
                refresh.validate_snapshot(self.stage, self.domains, self.seeds, 2, ratio)


if __name__ == '__main__':
    unittest.main()
