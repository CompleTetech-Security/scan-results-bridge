"""Synthetic empty-report provenance regressions; no external access."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import test_bridge
from test_bridge import report


class ReportEnvelopeTests(unittest.TestCase):
    cli = test_bridge.BridgeTests.cli
    def convert(self, reports, fmt):
        with tempfile.TemporaryDirectory() as directory:
            args = []
            for index, value in enumerate(reports):
                path = Path(directory)/f'input-{index}.json'
                path.write_text(json.dumps(value), encoding='utf-8')
                args.extend(['--input', str(path)])
            return self.cli(*args, '--format', fmt)

    def envelopes(self, text, fmt):
        if fmt == 'ndjson':
            return json.loads(text.splitlines()[-1])['reports']
        return [entry for run in json.loads(text)['runs']
                for entry in run['properties']['input_reports']]

    def test_empty_snapshot_and_limitation_changes_survive_both_formats(self):
        first = report(); first['results'] = []
        for field in ('snapshot', 'limitations'):
            other = copy.deepcopy(first)
            if field == 'snapshot': other['rules']['snapshot_id'] = 'synthetic-2'
            else: other['limitations'] = ['Synthetic secret limitation SECRET']
            for fmt in ('sarif', 'ndjson'):
                code, left, _ = self.convert([first], fmt)
                other_code, right, _ = self.convert([other], fmt)
                self.assertEqual((0, 0), (code, other_code))
                self.assertNotEqual(left, right)
                self.assertNotEqual(self.envelopes(left, fmt), self.envelopes(right, fmt))
                self.assertNotIn('SECRET', right)
                self.assertNotIn('synthetic-2', right)

    def test_multiple_empty_reports_are_attributable_deterministic_and_private(self):
        first = report(); first['results'] = []
        other = copy.deepcopy(first)
        other['rules']['snapshot_id'] = 'synthetic-2'
        other['limitations'] = ['https://private.invalid?token=SECRET']
        for fmt in ('sarif', 'ndjson'):
            code, text, _ = self.convert([first, other], fmt)
            self.assertEqual(0, code)
            entries = self.envelopes(text, fmt)
            self.assertEqual(2, len(entries))
            self.assertEqual(2, len({entry['report_sha256'] for entry in entries}))
            self.assertTrue(all(entry['complete'] for entry in entries))
            self.assertEqual(text, self.convert([other, first], fmt)[1])
            self.assertEqual(text, self.convert([first, other], fmt)[1])
            for secret in ('SECRET', 'private.invalid', 'input-0', 'input-1'):
                self.assertNotIn(secret, text)

    def test_empty_incomplete_envelope_preserves_exit_and_per_tool_completion(self):
        first = report(); first['results'] = []
        other = copy.deepcopy(first); other['complete'] = False
        other['tool']['name'] = 'other-check'
        for fmt in ('sarif', 'ndjson'):
            code, text, _ = self.convert([first, other], fmt)
            self.assertEqual(2, code)
            entries = {entry['tool']: entry for entry in self.envelopes(text, fmt)}
            self.assertTrue(entries['synthetic-check']['complete'])
            self.assertFalse(entries['other-check']['complete'])
            if fmt == 'sarif':
                for run in json.loads(text)['runs']:
                    name = run['tool']['driver']['name']
                    self.assertEqual([entries[name]], run['properties']['input_reports'])
                    self.assertEqual(entries[name]['complete'], run['invocations'][0]['executionSuccessful'])

    def test_duplicate_inputs_retain_report_multiplicity(self):
        value = report(); value['results'] = []
        for fmt in ('sarif', 'ndjson'):
            code, text, _ = self.convert([value, value], fmt)
            self.assertEqual(0, code)
            entries = self.envelopes(text, fmt)
            self.assertEqual(2, len(entries))
            self.assertEqual(entries[0], entries[1])
