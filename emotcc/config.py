"""Validated experiment configuration, with paths relative to its JSON file."""
from dataclasses import asdict, dataclass, field
from pathlib import Path
import json
import math

FIELD_MAP = {
    'Protocol Type': 'protocol_type', 'TCP': 'tcp', 'UDP': 'udp',
    'HTTP': 'http', 'HTTPS': 'https', 'DNS': 'dns', 'ARP': 'arp', 'ICMP': 'icmp',
    'Rate': 'rate', 'Number': 'number', 'Tot size': 'tot_size', 'Tot sum': 'tot_sum',
    'Min': 'min', 'Max': 'max', 'AVG': 'avg', 'Std': 'std', 'IAT': 'iat',
    'Label': 'label', 'ts': 'ts',
}
INDICATORS = ['tcp', 'udp', 'http', 'https', 'dns', 'arp', 'icmp']
NUMERIC = [v for v in FIELD_MAP.values() if v not in ('label', 'ts')]


@dataclass
class Config:
    inputs: list = field(default_factory=list)
    output_dir: str = 'outputs/experiment'
    features: list = field(default_factory=lambda: NUMERIC.copy())
    rule_features: list = field(default_factory=lambda: ['rate', 'tot_size', 'number', 'iat'])
    two_sided: list = field(default_factory=lambda: ['iat'])
    train_fraction: float = .7
    seed: int = 42
    quantile: float = .99
    min_profile_samples: int = 100
    chunk_size: int = 50000
    max_rows_per_file: int | None = None
    timestamp_format: str | None = None
    check_protocol: bool = True
    check_indicators: bool = True
    absolute_tolerance: float = 1e-12
    relative_tolerance: float = 1e-9
    export_events: bool = True
    expected_attack_labels: list = field(default_factory=list)

    def __post_init__(self):
        if (not self.features or len(set(self.features)) != len(self.features)
                or not set(self.features) <= set(NUMERIC) or 'protocol_type' not in self.features):
            raise ValueError('features deve conter protocol_type e apenas atributos numéricos conhecidos; Label é proibido.')
        if not set(self.rule_features) <= set(self.features) - {'protocol_type'}:
            raise ValueError('rule_features deve ser um subconjunto numérico de features, sem Label/protocol_type.')
        if not set(self.two_sided) <= set(self.rule_features):
            raise ValueError('two_sided deve ser um subconjunto de rule_features.')
        if not 0 < self.train_fraction < 1 or not .5 < self.quantile < 1:
            raise ValueError('train_fraction deve estar entre 0 e 1; quantile entre 0.5 e 1.')
        if self.chunk_size < 1 or self.min_profile_samples < 2:
            raise ValueError('chunk_size >= 1 e min_profile_samples >= 2 são necessários.')
        if self.max_rows_per_file is not None and self.max_rows_per_file < 1:
            raise ValueError('max_rows_per_file deve ser positivo ou null.')
        if self.timestamp_format not in (None, 'iso8601', 'unix_s', 'unix_ms', 'unix_us', 'unix_ns'):
            raise ValueError('timestamp_format desconhecido; não inferimos unidades.')
        if any(not math.isfinite(t) or t < 0 for t in (self.absolute_tolerance, self.relative_tolerance)):
            raise ValueError('As tolerâncias devem ser finitas e não negativas.')

    def to_dict(self):
        return asdict(self)

    @classmethod
    def load(cls, path):
        path = Path(path).resolve()
        raw = json.loads(path.read_text(encoding='utf-8-sig'))
        cfg = cls(**raw)
        cfg.inputs = [{**entry, 'path': str((path.parent / entry['path']).resolve())}
                      for entry in cfg.inputs]
        cfg.output_dir = str((path.parent / cfg.output_dir).resolve())
        return cfg
