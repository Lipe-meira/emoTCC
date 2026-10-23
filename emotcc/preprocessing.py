"""Conservative validation: invalid observations are excluded and counted."""
import numpy as np
import pandas as pd
from .config import FIELD_MAP, INDICATORS


def canonical_columns(columns):
    return [FIELD_MAP.get(str(c).strip(), str(c).strip().lower()) for c in columns]


def normalize(frame, features, assigned_label=None, timestamp_format=None):
    data = frame.copy()
    data.columns = canonical_columns(data.columns)
    if 'label' not in data:
        if assigned_label is None:
            raise ValueError('Coluna Label ausente: configure explicitamente label para este arquivo.')
        data['label'] = assigned_label
    labels = data['label'].astype('string').str.strip().str.upper()
    bad_label = labels.isna() | labels.isin(['', 'NAN', 'NONE', 'NULL'])
    if assigned_label is not None and (labels[~bad_label] != assigned_label.strip().upper()).any():
        raise ValueError('Label existente é incompatível com o rótulo explicitamente atribuído.')
    data['label'] = labels
    bad = bad_label.to_numpy(dtype=bool, copy=True)
    problems = {'label': int(bad.sum())}
    for name in features:
        values = pd.to_numeric(data[name], errors='coerce').astype('float64')
        invalid = ~np.isfinite(values) | (values < 0)
        if name in INDICATORS:
            invalid |= values > 1
        if name == 'number':
            invalid |= values <= 0
        problems[name] = int(invalid.sum())
        bad |= invalid.to_numpy()
        data[name] = values.mask(values == 0, 0.)  # canonicalize negative zero
    if {'min', 'max', 'avg'} <= set(features):
        tol = np.maximum(1., data['max'].abs()) * 1e-9
        inconsistent = ((data['min'] > data['max'] + tol)
                        | (data['avg'] < data['min'] - tol)
                        | (data['avg'] > data['max'] + tol))
        problems['inconsistent_size_statistics'] = int(inconsistent.sum())
        bad |= inconsistent.to_numpy()
    data['source_timestamp'] = data['ts'].astype('string') if 'ts' in data else None
    data['time_order'] = None
    if timestamp_format:
        if 'ts' not in data:
            raise ValueError('timestamp_format configurado, mas ts está ausente.')
        if timestamp_format == 'iso8601':
            timestamps = pd.to_datetime(data['ts'], format='ISO8601', utc=True, errors='coerce')
        else:
            timestamps = pd.to_datetime(pd.to_numeric(data['ts'], errors='coerce'),
                                        unit=timestamp_format[5:], utc=True, errors='coerce')
        # pandas can infer us in one block and ns in another. Persist a single unit.
        in_range = ((timestamps >= pd.Timestamp.min.tz_localize('UTC'))
                    & (timestamps <= pd.Timestamp.max.tz_localize('UTC')))
        timestamps = timestamps.where(in_range).dt.as_unit('ns')
        problems['timestamp'] = int(timestamps.isna().sum())
        bad |= timestamps.isna().to_numpy()
        data['time_order'] = timestamps.astype('int64')
    return data.loc[~bad].copy(), {'rows': len(frame), 'invalid_rows': int(bad.sum()),
                                  'invalid_by_field': problems}
