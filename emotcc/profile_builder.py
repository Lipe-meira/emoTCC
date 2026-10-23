"""Exact benign-only statistics; at most one feature vector in RAM per query."""
import json
from time import perf_counter
import numpy as np
from .config import INDICATORS
from .database import put_meta


def describe(values, quantile):
    values = np.asarray(values, dtype=float)
    # Scaling prevents overflow in sums and squared deviations for finite extremes.
    scale = float(np.max(np.abs(values))) or 1.
    scaled = values / scale
    return {'count': len(values), 'mean': float(np.mean(scaled) * scale),
            'median': float(np.quantile(values, .5)),
            'std': float(np.std(scaled, ddof=1) * scale) if len(values) > 1 else 0.,
            'min': float(np.min(values)), 'max': float(np.max(values)),
            'p95': float(np.quantile(values, .95)), 'p99': float(np.quantile(values, .99)),
            'lower': float(np.quantile(values, 1 - quantile)),
            'upper': float(np.quantile(values, quantile))}


def build_profiles(db, cfg):
    started = perf_counter()
    if db.execute('SELECT count(*) FROM profiles').fetchone()[0]:
        raise ValueError('Perfis já construídos; utilize uma nova pasta de saída.')
    groups = ['global'] + [r[0] for r in db.execute("SELECT DISTINCT group_key FROM events WHERE split='build' ORDER BY group_key")]
    profiles, stability = [], []
    for group in groups:
        condition = "split='build'" if group == 'global' else "split='build' AND group_key=?"
        args = () if group == 'global' else (group,)
        n = db.execute(f'SELECT count(*) FROM events WHERE {condition}', args).fetchone()[0]
        stats, allowed = {}, []
        active = n >= cfg.min_profile_samples
        if active:
            for feature in cfg.features:
                if feature == 'protocol_type':
                    continue
                # Fetch in stable order: slice stability is NOT a time stability claim.
                values = np.fromiter((r[0] for r in db.execute(
                    f'SELECT "{feature}" FROM events WHERE {condition} ORDER BY event_id', args)), dtype=float, count=n)
                stats[feature] = describe(values, cfg.quantile)
                if feature in INDICATORS and np.any(values > 0):
                    allowed.append(feature)
                left, right = values[::2], values[1::2]
                if len(left) >= cfg.min_profile_samples and len(right) >= cfg.min_profile_samples:
                    q1, q2 = float(np.quantile(left, cfg.quantile)), float(np.quantile(right, cfg.quantile))
                    stability.append({'profile_id': group, 'feature': feature, 'slice_1_n': len(left),
                                      'slice_2_n': len(right), 'slice_1_upper': q1, 'slice_2_upper': q2,
                                      'relative_difference': abs(q1-q2)/max(abs(q1),abs(q2),cfg.absolute_tolerance or 1e-300)})
                del values
        profile = {'profile_id': group, 'observations': n, 'active': active,
                   'allowed_indicators': allowed, 'stats': stats}
        db.execute('INSERT INTO profiles VALUES (?,?,?,?)',
                   (group, n, int(active), json.dumps(profile, allow_nan=False)))
        profiles.append(profile)
    for operation in ('INSERT', 'UPDATE', 'DELETE'):
        db.execute(f"CREATE TRIGGER freeze_profiles_{operation.lower()} BEFORE {operation} ON profiles BEGIN SELECT RAISE(ABORT,'Reference profiles are immutable'); END")
    put_meta(db, 'profile_stability', stability)
    put_meta(db, 'build_seconds', perf_counter() - started)
    put_meta(db, 'stage', 'built')
    db.commit()
    return profiles
