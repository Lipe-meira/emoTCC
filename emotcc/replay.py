"""Deterministic offline replay with immutable profiles and separate live counters."""
from collections import Counter
from time import perf_counter
import numpy as np
from .database import put_meta, get_meta
from .digital_twin import DigitalTwin
from .detectors import detect
from .evaluation import evaluate_decisions


def replay(db, cfg):
    if get_meta(db, 'stage') != 'built':
        raise ValueError('A avaliação exige perfis recém-construídos; use uma nova pasta para outra execução.')
    twin = DigitalTwin(db)
    run_id = get_meta(db, 'run_id')
    ordering = 'time_order,source,source_row,event_id' if cfg.timestamp_format else 'source,source_row,event_id'
    columns = ['event_id','group_key','source_timestamp', *cfg.features]
    query = 'SELECT ' + ','.join(f'"{c}"' for c in columns) + f" FROM events WHERE split='test' ORDER BY {ordering}"
    read = db.execute(query)
    decision_rows, alert_rows, states = [], [], {}
    statuses = Counter()
    observed_groups = set()
    sequence = 0
    fetch_seconds = write_seconds = 0.
    start = perf_counter()

    def flush():
        nonlocal write_seconds
        t = perf_counter()
        db.executemany('INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?)', decision_rows)
        db.executemany('INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?)', alert_rows)
        db.executemany('''INSERT INTO operational_state VALUES (?,?,?,?)
            ON CONFLICT(group_key) DO UPDATE SET processed_events=processed_events+excluded.processed_events,
            last_event_id=excluded.last_event_id,last_timestamp=excluded.last_timestamp''',
                       ((key, *value) for key, value in states.items()))
        db.commit()
        decision_rows.clear(); alert_rows.clear(); states.clear()
        write_seconds += perf_counter() - t

    while True:
        t = perf_counter()
        batch = read.fetchmany(cfg.chunk_size)
        fetch_seconds += perf_counter() - t
        if not batch:
            break
        for raw in batch:
            event = dict(zip(columns, raw))  # Deliberately excludes Label.
            sequence += 1
            key = event['group_key']
            observed_groups.add(key)
            known = key in twin.groups
            t = perf_counter()
            alerts_a, rules_a = detect(event, twin.global_profile, known, cfg)
            elapsed_a = perf_counter() - t
            t = perf_counter()
            reference, status = twin.lookup(key)
            alerts_b, rules_b = detect(event, reference, known, cfg)
            elapsed_b = perf_counter() - t
            statuses[status] += 1
            for detector, profile, profile_status, alerts, rules, elapsed in (
                ('A', twin.global_profile, 'global', alerts_a, rules_a, elapsed_a),
                ('B', reference, status, alerts_b, rules_b, elapsed_b)):
                decision_rows.append((run_id, event['event_id'], detector, sequence,
                                      profile['profile_id'], profile_status, int(bool(alerts)),
                                      rules, len(alerts), elapsed))
                alert_rows.extend((run_id, event['event_id'], detector, a['rule'], a['feature'],
                                   a['observed'], a['threshold'], a['profile_id'], a['reason']) for a in alerts)
            previous = states.get(key, (0, None, None))
            states[key] = (previous[0]+1, event['event_id'], event['source_timestamp'])
        flush()
        print(f'Replay: {sequence:,} eventos', flush=True)
    # Index after bulk inserts, preserving efficient bounded writes.
    db.execute('CREATE INDEX alerts_detector ON alerts(detector,event_id)')
    elapsed = perf_counter() - start
    query_times = np.asarray(twin.query_seconds)
    timing = {'replay_seconds': elapsed, 'mean_replay_seconds_per_event': elapsed / sequence if sequence else None,
              'sqlite_event_fetch_seconds': fetch_seconds, 'audit_write_seconds': write_seconds,
              'profile_lookup_calls': len(query_times), 'profile_sql_statements': twin.sql_queries,
              'lookup_seconds': {'mean': float(query_times.mean()) if len(query_times) else None,
                                 'p50': float(np.quantile(query_times,.5)) if len(query_times) else None,
                                 'p95': float(np.quantile(query_times,.95)) if len(query_times) else None,
                                 'p99': float(np.quantile(query_times,.99)) if len(query_times) else None,
                                 'max': float(query_times.max()) if len(query_times) else None}}
    coverage = {'test_events': sequence, 'specific_events': statuses['specific'],
                'sparse_fallback_events': statuses['sparse_global'],
                'unseen_protocol_events': statuses['unseen_global'],
                'specific_profile_coverage': statuses['specific'] / sequence if sequence else None,
                'global_fallback_coverage': 1. if sequence else None,
                'observed_test_groups': len(observed_groups),
                'represented_test_groups': len(observed_groups & twin.groups),
                'active_test_groups': db.execute("SELECT count(*) FROM profiles WHERE active=1 AND profile_id!='global' AND profile_id IN (SELECT DISTINCT group_key FROM events WHERE split='test')").fetchone()[0],
                'group_coverage': len(observed_groups & twin.groups)/len(observed_groups) if observed_groups else None,
                'device_coverage': None}
    put_meta(db, 'timing', timing)
    put_meta(db, 'coverage', coverage)
    put_meta(db, 'stage', 'evaluated')
    db.commit()
    raw_labels = set()
    for info in get_meta(db, 'inspection')['files']:
        raw_labels.update(info['label_counts_raw'])
    tested_labels = {r[0] for r in db.execute("SELECT DISTINCT label FROM events WHERE split='test'")}
    return {'run_id': run_id, 'detectors': evaluate_decisions(db), 'coverage': coverage, 'timing': timing,
            'classes': {'evaluated': sorted(tested_labels),
                        'input_labels_absent_from_test': sorted(raw_labels-tested_labels),
                        'expected_attacks_absent_from_test': sorted(set(cfg.expected_attack_labels)-tested_labels)}}
