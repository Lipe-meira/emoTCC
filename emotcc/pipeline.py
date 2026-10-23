"""Experiment orchestration. Every output directory belongs to one immutable run."""
import csv
import hashlib
import json
import platform
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
import uuid
import numpy as np
import pandas as pd
from .config import Config
from .database import connect, initialize, put_meta, get_meta
from .data_loader import inspect_header, iter_csv
from .preprocessing import normalize
from .dataset_split import split_dataset
from .profile_builder import build_profiles
from .replay import replay
from .reporting import save_json, write_reports


def _sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(4*1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def prepare(cfg, split=True):
    cfg.__post_init__()
    if not cfg.inputs:
        raise ValueError('Nenhum CSV configurado em inputs.')
    out = Path(cfg.output_dir).resolve()
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f'Diretório de saída não está vazio: {out}. Use uma pasta nova.')
    infos = [inspect_header(entry['path'], cfg, entry.get('label')) for entry in cfg.inputs]
    # One comparable input vector across all files; optional missing columns are reported.
    common = set.intersection(*(set(i['canonical_columns']) for i in infos))
    cfg.features = [f for f in cfg.features if f in common]
    cfg.__post_init__()
    out.mkdir(parents=True, exist_ok=True)
    db = connect(out/'digital_twin.sqlite')
    initialize(db, cfg.features)
    run_id = str(uuid.uuid4())
    put_meta(db, 'run_id', run_id)
    put_meta(db, 'config', cfg.to_dict())
    put_meta(db, 'created_at_utc', datetime.now(timezone.utc).isoformat())
    started = perf_counter()
    read_seconds = 0.
    inspection = {'files': [], 'rows_read': 0, 'invalid_rows': 0, 'duplicates': 0,
                  'fingerprint_features': cfg.features,
                  'ordering': 'chronological' if cfg.timestamp_format else 'deterministic_file_row',
                  'units': 'source scale; original extractor not supplied'}
    names = ['event_id','label','group_key','source','source_row','source_timestamp','time_order','split_key',*cfg.features]
    sql = 'INSERT OR IGNORE INTO events (' + ','.join(f'"{c}"' for c in names) + ') VALUES (' + ','.join('?' for _ in names) + ')'
    reader = None
    try:
        with (out/'invalid_records.csv').open('w', encoding='utf-8', newline='') as invalid_stream:
            invalid_writer = csv.writer(invalid_stream)
            invalid_writer.writerow(['source','source_row','raw_selected_fields'])
            for entry, info in zip(cfg.inputs, infos):
                path = str(Path(entry['path']).resolve())
                info.update({'sha256': _sha256(path), 'rows_read': 0, 'invalid_rows': 0,
                             'duplicates': 0, 'label_counts_raw': {}, 'invalid_by_field': {},
                             'source_dtypes': {}, 'normalized_numeric_dtype': 'float64'})
                labels, problems = Counter(), Counter()
                reader = iter(iter_csv(path, cfg))
                offset = 0
                while True:
                    t = perf_counter()
                    try:
                        frame = next(reader)
                    except StopIteration:
                        break
                    read_seconds += perf_counter() - t
                    for column, dtype in frame.dtypes.items():
                        info['source_dtypes'].setdefault(str(column), [])
                        if str(dtype) not in info['source_dtypes'][str(column)]:
                            info['source_dtypes'][str(column)].append(str(dtype))
                    data, quality = normalize(frame, cfg.features, entry.get('label'), cfg.timestamp_format)
                    label_column = next((c for c in frame.columns if str(c).strip().lower() == 'label'), None)
                    if label_column:
                        labels.update(frame[label_column].astype('string').fillna('<missing>').str.strip().str.upper().value_counts().to_dict())
                    else:
                        labels[entry.get('label','<missing>')] += len(frame)
                    for index in frame.index.difference(data.index):
                        invalid_writer.writerow([path, offset+int(frame.index.get_loc(index))+2,
                                                 frame.loc[index].to_json(force_ascii=False)])
                    values = data[cfg.features].to_numpy(dtype='<f8')
                    for index, label, timestamp, time_order, vector in zip(
                            data.index, data['label'], data['source_timestamp'], data['time_order'], values):
                        event_id = hashlib.sha256(vector.tobytes()).hexdigest()
                        split_key = hashlib.sha256(f'{cfg.seed}:{event_id}'.encode()).hexdigest()
                        group = f"protocol:{vector[cfg.features.index('protocol_type')]:.17g}"
                        source_row = offset + int(frame.index.get_loc(index)) + 2
                        timestamp = None if pd.isna(timestamp) else str(timestamp)
                        time_order = None if pd.isna(time_order) else int(time_order)
                        params = (event_id, label, group, path, source_row, timestamp, time_order, split_key,
                                  *vector.tolist())
                        inserted = db.execute(sql, params).rowcount
                        if not inserted:
                            info['duplicates'] += 1
                            db.execute('INSERT INTO duplicates VALUES (?,?,?,?)', (event_id,path,source_row,label))
                            db.execute('UPDATE events SET conflict=1 WHERE event_id=? AND label!=?', (event_id,label))
                    offset += len(frame)
                    info['rows_read'] += len(frame)
                    info['invalid_rows'] += quality['invalid_rows']
                    problems.update(quality['invalid_by_field'])
                    db.commit()
                reader.close()
                if not info['rows_read']:
                    raise ValueError(f'Arquivo vazio (somente cabeçalho): {path}')
                info['label_counts_raw'] = dict(labels)
                info['invalid_by_field'] = dict(problems)
                inspection['files'].append(info)
                for field in ('rows_read','invalid_rows','duplicates'):
                    inspection[field] += info[field]
                print(f"Ingestão: {Path(path).name}: {info['rows_read']:,} linhas; {info['invalid_rows']:,} inválidas; {info['duplicates']:,} duplicatas", flush=True)
        inspection['unique_vectors'] = db.execute('SELECT count(*) FROM events').fetchone()[0]
        inspection['conflicting_vectors'] = db.execute('SELECT count(*) FROM events WHERE conflict=1').fetchone()[0]
        inspection['observed_labels'] = [r[0] for r in db.execute('SELECT DISTINCT label FROM events ORDER BY label')]
        put_meta(db, 'inspection', inspection)
        put_meta(db, 'stage', 'inspected')
        if split:
            split_dataset(db, cfg)
            put_meta(db, 'stage', 'prepared')
        preparation = {'ingestion_and_split_seconds': perf_counter()-started,
                       'csv_read_seconds': read_seconds,
                       'note': 'CSV parsing timed separately; ingestion includes hashing, validation, staging and deduplication.'}
        put_meta(db, 'preparation', preparation)
        db.commit()
        save_json(out/'inspection.json', inspection)
        save_json(out/'manifest.json', {'run_id': run_id, 'config': cfg.to_dict(),
                  'created_at_utc': get_meta(db, 'created_at_utc'),
                  'environment': {'python': sys.version, 'platform': platform.platform(),
                                  'machine': platform.machine(), 'processor': platform.processor(),
                                  'pandas': pd.__version__, 'numpy': np.__version__, 'sqlite': sqlite3.sqlite_version},
                  'preparation': preparation, 'files': [{k:i[k] for k in ('path','bytes','sha256')} for i in infos]})
        return db
    except BaseException:
        if reader is not None:
            reader.close()
        db.close()
        raise


def _resume(cfg):
    path = Path(cfg.output_dir)/'digital_twin.sqlite'
    if not path.is_file():
        raise FileNotFoundError(f'Banco ausente: {path}. Execute inspect, build ou run primeiro.')
    db = connect(path)
    stored = Config(**get_meta(db, 'config'))
    # Inference/evaluation must use the exact feature set and parameters that built the reference.
    for key in ('seed','train_fraction','quantile','min_profile_samples','timestamp_format',
                'rule_features','two_sided','absolute_tolerance','relative_tolerance','check_protocol','check_indicators'):
        if getattr(cfg,key) != getattr(stored,key):
            db.close()
            raise ValueError(f'Configuração mudou desde a ingestão: {key}. Use uma nova execução.')
    return db, stored


def build(cfg):
    if (Path(cfg.output_dir)/'digital_twin.sqlite').is_file():
        db, cfg = _resume(cfg)
        if get_meta(db, 'stage') == 'inspected':
            split_dataset(db, cfg)
    else:
        db = prepare(cfg)
    try:
        build_profiles(db, cfg)
        write_reports(db, cfg)
    finally:
        db.close()


def evaluate(cfg):
    db, cfg = _resume(cfg)
    try:
        metrics = replay(db, cfg)
        _report_and_time(db, cfg, metrics)
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        return metrics
    finally:
        db.close()


def run(cfg):
    started = perf_counter()
    db = prepare(cfg)
    try:
        build_profiles(db, cfg)
        metrics = replay(db, cfg)
        _report_and_time(db, cfg, metrics)
        metrics['timing']['pipeline_total_seconds'] = perf_counter() - started
        put_meta(db, 'timing', metrics['timing'])
        db.commit()
        save_json(Path(cfg.output_dir)/'metrics.json', metrics)
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        return metrics
    finally:
        db.close()


def _report_and_time(db, cfg, metrics):
    started = perf_counter()
    write_reports(db, cfg, metrics)
    metrics['timing']['reporting_seconds'] = perf_counter() - started
    put_meta(db, 'timing', metrics['timing'])
    db.commit()
    save_json(Path(cfg.output_dir)/'metrics.json', metrics)
