"""CSV schema inspection and bounded-memory reading."""
from pathlib import Path
import pandas as pd
from .preprocessing import canonical_columns


def inspect_header(path, cfg, assigned_label=None):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f'Arquivo não encontrado: {path.resolve()}')
    try:
        columns = pd.read_csv(path, nrows=0, encoding='utf-8-sig').columns.tolist()
    except pd.errors.EmptyDataError as exc:
        raise ValueError(f'Arquivo vazio: {path}') from exc
    normalized = canonical_columns(columns)
    if len(set(normalized)) != len(normalized):
        raise ValueError(f'Cabeçalhos duplicados após normalização: {path}')
    if 'label' not in normalized and assigned_label is None:
        raise ValueError(f'Label ausente em {path.name}; atribua label explicitamente na configuração.')
    required = {'protocol_type', *cfg.rule_features}
    if cfg.timestamp_format:
        required.add('ts')
    missing = sorted(required - set(normalized))
    if missing:
        raise ValueError(f'Colunas necessárias ausentes em {path.name}: {missing}')
    return {'path': str(path.resolve()), 'bytes': path.stat().st_size, 'columns': columns,
            'column_count': len(columns),
            'canonical_columns': normalized, 'assigned_label': assigned_label,
            'missing_optional': sorted(set(cfg.features) - set(normalized)),
            'timestamp_present': 'ts' in normalized}


def iter_csv(path, cfg):
    keep = set(cfg.features) | {'label', 'ts'}
    return pd.read_csv(path, chunksize=cfg.chunk_size, nrows=cfg.max_rows_per_file,
                       usecols=lambda name: canonical_columns([name])[0] in keep,
                       encoding='utf-8-sig', low_memory=False)
