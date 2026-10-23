"""Synthetic fixtures only; no experimental results are asserted here."""
import csv
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd


class PipelineTests(unittest.TestCase):
    def setUp(self):
        temp_root = Path(__file__).resolve().parents[1] / '.test_tmp'
        temp_root.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=temp_root)
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def config(self, **kwargs):
        from emotcc.config import Config
        return Config(inputs=[], output_dir=str(self.root / 'out'),
                      features=['protocol_type', 'rate', 'iat', 'number'],
                      rule_features=['rate', 'iat', 'number'], min_profile_samples=2, **kwargs)

    def csv(self, name, rows, headers=None):
        path = self.root / name
        headers = headers or ['Protocol Type', 'Rate', 'IAT', 'Number', 'Label']
        with path.open('w', newline='', encoding='utf-8') as stream:
            writer = csv.writer(stream)
            writer.writerow(headers)
            writer.writerows(rows)
        return path

    def fixture(self):
        rows = [[6, i, i / 10, 10, 'BENIGN'] for i in range(1, 31)]
        rows += [[17, i, i / 10, 10, 'BENIGN'] for i in range(101, 131)]
        rows += [[6, 1000 + i, .01, 100, 'MITM-ARPSPOOFING'] for i in range(5)]
        return self.csv('data.csv', rows)

    def test_normalization_preserves_fractional_indicators_and_canonical_labels(self):
        from emotcc.preprocessing import normalize
        df, quality = normalize(pd.DataFrame({'Protocol Type': [6], 'Rate': ['2.5'],
                                              'TCP': [.7], 'Label': [' benign ']}),
                                ['protocol_type', 'rate', 'tcp'])
        self.assertEqual(df.iloc[0]['tcp'], .7)
        self.assertEqual(df.iloc[0]['label'], 'BENIGN')
        self.assertEqual(quality['invalid_rows'], 0)

    def test_invalid_values_are_quarantined_without_imputation(self):
        from emotcc.preprocessing import normalize
        df, q = normalize(pd.DataFrame({'Protocol Type': [6]*5,
                                        'Rate': ['bad', np.inf, -1, 4, 5],
                                        'TCP': [.3, .3, .3, 1.2, .8],
                                        'Label': ['BENIGN']*5}), ['protocol_type', 'rate', 'tcp'])
        self.assertEqual(len(df), 1)
        self.assertEqual(q['invalid_rows'], 4)

    def test_unlabeled_file_requires_explicit_label(self):
        from emotcc.data_loader import inspect_header
        p = self.csv('unlabeled.csv', [[6, 1, .1, 10]], ['Protocol Type', 'Rate', 'IAT', 'Number'])
        with self.assertRaisesRegex(ValueError, 'Label'):
            inspect_header(p, self.config())
        self.assertEqual(inspect_header(p, self.config(), 'BENIGN')['assigned_label'], 'BENIGN')

    def test_missing_required_feature_fails_clearly(self):
        from emotcc.data_loader import inspect_header
        p = self.csv('missing.csv', [[6, 'BENIGN']], ['Protocol Type', 'Label'])
        with self.assertRaisesRegex(ValueError, 'rate'):
            inspect_header(p, self.config())

    def test_empty_file_is_rejected(self):
        from emotcc.data_loader import inspect_header
        p = self.root / 'empty.csv'
        p.write_text('')
        with self.assertRaisesRegex(ValueError, 'vazio'):
            inspect_header(p, self.config())

    def test_exact_statistics_and_zero_variance_threshold(self):
        from emotcc.profile_builder import describe
        stats = describe(np.array([1., 2., 3., 4., 5.]), .99)
        self.assertEqual(stats['mean'], 3)
        self.assertEqual(stats['median'], 3)
        self.assertAlmostEqual(stats['p95'], 4.8)
        self.assertAlmostEqual(stats['p99'], 4.96)
        self.assertAlmostEqual(stats['std'], 5 ** .5 / 2 ** .5)
        self.assertEqual(describe(np.array([2., 2.]), .99)['upper'], 2)

    def test_metrics_count_events_once_and_undefined_values_are_null(self):
        from emotcc.evaluation import confusion_metrics
        m = confusion_metrics(tp=3, fp=1, tn=4, fn=2)
        self.assertEqual(m['precision'], .75)
        self.assertEqual(m['recall'], .6)
        self.assertAlmostEqual(m['f1'], 2 / 3)
        self.assertEqual(m['fpr'], .2)
        self.assertIsNone(confusion_metrics(0, 0, 3, 0)['recall'])

    def test_duplicate_vectors_with_conflicting_labels_are_excluded(self):
        from emotcc.pipeline import prepare
        p = self.csv('conflict.csv', [[6, 1, .1, 10, 'BENIGN'],
                                      [6, 1, .1, 10, 'ATTACK'],
                                      [6, 2, .2, 10, 'BENIGN'],
                                      [6, 3, .3, 10, 'BENIGN'],
                                      [6, 4, .4, 10, 'BENIGN']])
        cfg = self.config(); cfg.inputs = [{'path': str(p)}]
        db = prepare(cfg)
        self.addCleanup(db.close)
        self.assertEqual(db.execute('SELECT count(*) FROM events WHERE conflict=1').fetchone()[0], 1)
        self.assertEqual(db.execute("SELECT count(*) FROM events WHERE conflict=1 AND split!='excluded'").fetchone()[0], 0)

    def test_split_is_disjoint_benign_only_and_reproducible_across_chunks(self):
        from emotcc.pipeline import prepare
        p = self.fixture()
        original = []
        for chunk in (3, 17):
            cfg = self.config(); cfg.inputs = [{'path': str(p)}, {'path': str(p)}]
            cfg.chunk_size = chunk
            cfg.output_dir = str(self.root / f'out{chunk}')
            db = prepare(cfg)
            self.addCleanup(db.close)
            rows = db.execute('SELECT event_id,split FROM events ORDER BY event_id').fetchall()
            original.append(rows)
            self.assertEqual(db.execute("SELECT count(*) FROM events WHERE split='build' AND label!='BENIGN'").fetchone()[0], 0)
            self.assertEqual(len(rows), 65)
            self.assertEqual(db.execute("SELECT count(*) FROM events WHERE split='build'").fetchone()[0], 42)
        self.assertEqual(*original)

    def test_both_detectors_use_same_rules_but_different_reference(self):
        from emotcc.detectors import detect
        cfg = self.config()
        global_ref = {'profile_id': 'global', 'allowed_indicators': [],
                      'stats': {'rate': {'lower': 0, 'upper': 200},
                                'iat': {'lower': 0, 'upper': 10},
                                'number': {'lower': 10, 'upper': 10}}}
        group_ref = {**global_ref, 'profile_id': 'protocol:6',
                     'stats': {**global_ref['stats'], 'rate': {'lower': 0, 'upper': 20}}}
        event = {'rate': 40, 'iat': 1, 'number': 10, 'label': 'BENIGN'}
        self.assertFalse(detect(event, global_ref, True, cfg)[0])
        alerts, count = detect(event, group_ref, True, cfg)
        self.assertEqual(alerts[0]['feature'], 'rate')
        self.assertEqual(alerts[0]['threshold'], 20)
        self.assertGreater(count, 0)
        event['label'] = 'ATTACK'
        self.assertEqual(detect(event, group_ref, True, cfg)[0], alerts)

    def test_end_to_end_profiles_audit_fallback_and_frozen_reference(self):
        from emotcc.pipeline import run, evaluate
        from emotcc.digital_twin import DigitalTwin
        p = self.fixture()
        cfg = self.config(); cfg.inputs = [{'path': str(p)}]
        run(cfg)
        db = sqlite3.connect(Path(cfg.output_dir) / 'digital_twin.sqlite')
        self.addCleanup(db.close)
        profiles_before = db.execute('SELECT * FROM profiles ORDER BY profile_id').fetchall()
        twin = DigitalTwin(db)
        profile, status = twin.lookup('protocol:6')
        self.assertEqual(status, 'specific')
        self.assertEqual(profile['profile_id'], 'protocol:6')
        profile, status = twin.lookup('protocol:47')
        self.assertEqual(status, 'unseen_global')
        self.assertEqual(profile['profile_id'], 'global')
        self.assertEqual(db.execute("SELECT count(*) FROM decisions WHERE detector='A'").fetchone()[0], 23)
        self.assertEqual(db.execute("SELECT count(*) FROM decisions WHERE detector='B'").fetchone()[0], 23)
        self.assertEqual(db.execute('SELECT count(DISTINCT event_id) FROM decisions').fetchone()[0], 23)
        with self.assertRaises(ValueError):
            evaluate(cfg)
        self.assertEqual(profiles_before, db.execute('SELECT * FROM profiles ORDER BY profile_id').fetchall())
        report = json.loads((Path(cfg.output_dir) / 'metrics.json').read_text())
        self.assertEqual(report['detectors']['A']['tp'], 5)
        self.assertTrue((Path(cfg.output_dir) / 'report.md').exists())

    def test_timestamp_order_and_chronological_benign_split(self):
        from emotcc.pipeline import run
        p = self.csv('timed.csv', [[6, i, .1, 10, 'BENIGN', f'2025-01-{i:02}T00:00:00Z']
                                     for i in range(10, 0, -1)],
                     ['Protocol Type', 'Rate', 'IAT', 'Number', 'Label', 'ts'])
        cfg = self.config(); cfg.inputs = [{'path': str(p)}]; cfg.timestamp_format = 'iso8601'
        run(cfg)
        db = sqlite3.connect(Path(cfg.output_dir) / 'digital_twin.sqlite')
        self.addCleanup(db.close)
        with db:
            self.assertEqual(db.execute("SELECT max(rate) FROM events WHERE split='build'").fetchone()[0], 7)
            self.assertEqual(db.execute("SELECT e.rate FROM decisions d JOIN events e USING(event_id) WHERE detector='A' ORDER BY d.sequence").fetchall(), [(8.,), (9.,), (10.,)])

    def test_insufficient_global_reference_fails(self):
        from emotcc.pipeline import run
        p = self.csv('attack.csv', [[6, 1, .1, 10, 'ATTACK']])
        cfg = self.config(); cfg.inputs = [{'path': str(p)}]
        with self.assertRaisesRegex(ValueError, 'benigno'):
            run(cfg)

    def test_missing_profile_generates_protocol_alert(self):
        from emotcc.detectors import detect
        cfg = self.config()
        alerts, _ = detect({'rate': 1, 'iat': .1, 'number': 10},
                           {'profile_id': 'global', 'stats': {}, 'allowed_indicators': []}, False, cfg)
        self.assertEqual(alerts[0]['rule'], 'unseen_protocol')

    def test_output_refuses_to_overwrite_experiment(self):
        from emotcc.pipeline import run
        cfg = self.config(); cfg.inputs = [{'path': str(self.fixture())}]
        run(cfg)
        with self.assertRaises(FileExistsError):
            run(cfg)

    def test_configuration_rejects_label_as_detection_feature(self):
        from emotcc.config import Config
        with self.assertRaises(ValueError):
            Config(inputs=[], features=['label'])

    def test_sparse_profile_falls_back_without_unseen_protocol_alert(self):
        from emotcc.pipeline import run
        from emotcc.digital_twin import DigitalTwin
        from emotcc.detectors import detect
        p = self.csv('sparse.csv', [[6, i, .1, 10, 'BENIGN', f'2025-01-{i+1:02}T00:00:00Z'] for i in range(1, 20)] +
                                 [[17, 1, .1, 10, 'BENIGN', '2025-01-01T00:00:00Z']],
                     ['Protocol Type', 'Rate', 'IAT', 'Number', 'Label', 'ts'])
        cfg = self.config(); cfg.inputs = [{'path': str(p)}]
        cfg.timestamp_format = 'iso8601'
        run(cfg)
        db = sqlite3.connect(Path(cfg.output_dir)/'digital_twin.sqlite')
        self.addCleanup(db.close)
        twin = DigitalTwin(db)
        profile, status = twin.lookup('protocol:17')
        self.assertEqual(profile['profile_id'], 'global')
        self.assertEqual(status, 'sparse_global')
        alerts, _ = detect({'rate': 1, 'iat': .1, 'number': 10}, profile, True, cfg)
        self.assertNotIn('unseen_protocol', [a['rule'] for a in alerts])
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE profiles SET observations=0")

    def test_stage_commands_and_identical_decisions_are_reproducible(self):
        from emotcc.pipeline import prepare, build, evaluate, run
        p = self.fixture()
        decisions = []
        for name in ('stages', 'one-command'):
            cfg = self.config(); cfg.inputs = [{'path': str(p)}]
            cfg.output_dir = str(self.root/name)
            if name == 'stages':
                prepare(cfg, split=False).close(); build(cfg); evaluate(cfg)
            else:
                run(cfg)
            db = sqlite3.connect(Path(cfg.output_dir)/'digital_twin.sqlite')
            decisions.append(db.execute('SELECT event_id,detector,suspicious,alert_count FROM decisions ORDER BY event_id,detector').fetchall())
            db.close()
        self.assertEqual(*decisions)

    def test_large_finite_statistics_do_not_overflow(self):
        from emotcc.profile_builder import describe
        stats = describe(np.array([1e308, 1e308]), .99)
        self.assertEqual(stats['mean'], 1e308)
        self.assertEqual(stats['median'], 1e308)
        self.assertEqual(stats['std'], 0.)

    def test_multibatch_replay_has_exactly_one_decision_per_detector(self):
        from emotcc.pipeline import run
        cfg = self.config(); cfg.inputs = [{'path': str(self.fixture())}]; cfg.chunk_size = 3
        run(cfg)
        db = sqlite3.connect(Path(cfg.output_dir)/'digital_twin.sqlite')
        self.addCleanup(db.close)
        self.assertEqual(db.execute('SELECT count(*) FROM decisions').fetchone()[0], 46)
        self.assertEqual(db.execute('SELECT sum(processed_events) FROM operational_state').fetchone()[0], 23)

    def test_timestamp_precision_is_consistent_across_csv_chunks(self):
        from emotcc.preprocessing import normalize
        orders = []
        for timestamp in ['2025-01-01T00:00:00.000000001Z', '2025-01-02T00:00:00Z']:
            data, _ = normalize(pd.DataFrame({'Protocol Type': [6], 'Rate': [1],
                                               'Label': ['BENIGN'], 'ts': [timestamp]}),
                                ['protocol_type', 'rate'], timestamp_format='iso8601')
            orders.append(int(data.iloc[0]['time_order']))
        self.assertEqual(orders[1]-orders[0], 86399999999999)

    def test_timestamp_outside_nanosecond_range_is_quarantined(self):
        from emotcc.preprocessing import normalize
        data, q = normalize(pd.DataFrame({'Protocol Type': [6], 'Rate': [1],
                                          'Label': ['BENIGN'], 'ts': ['2500-01-01T00:00:00Z']}),
                            ['protocol_type', 'rate'], timestamp_format='iso8601')
        self.assertEqual(len(data), 0)
        self.assertEqual(q['invalid_by_field']['timestamp'], 1)


if __name__ == '__main__':
    unittest.main()
