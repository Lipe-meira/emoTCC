"""Identical rule engine for A (global) and B (contextual). Labels are ignored."""
from .config import INDICATORS


def detect(event, reference, known_protocol, cfg):
    alerts, evaluated = [], 0
    profile_id = reference['profile_id']

    def emit(rule, feature, value, threshold, reason):
        alerts.append({'rule': rule, 'feature': feature, 'observed': value,
                       'threshold': threshold, 'profile_id': profile_id, 'reason': reason})

    if cfg.check_protocol:
        evaluated += 1
        if not known_protocol:
            emit('unseen_protocol', 'protocol_type', event.get('protocol_type'), None,
                 'Categoria de Protocol Type ausente na construção benigna; fallback global aplicado.')
    if cfg.check_indicators:
        for name in INDICATORS:
            if name not in cfg.features:
                continue
            evaluated += 1
            if event[name] > 0 and name not in reference['allowed_indicators']:
                emit('unseen_indicator', name, event[name], 0., 'Indicador não observado neste perfil benigno.')
    for name in cfg.rule_features:
        stat = reference['stats'].get(name)
        if stat is None:
            continue
        value = event[name]
        evaluated += 1
        upper = stat['upper']
        tolerance = cfg.absolute_tolerance + cfg.relative_tolerance * abs(upper)
        if value > upper + tolerance:
            emit('above_quantile', name, value, upper, f'Valor acima do quantil {cfg.quantile:g} benigno.')
        if name in cfg.two_sided:
            evaluated += 1
            lower = stat['lower']
            tolerance = cfg.absolute_tolerance + cfg.relative_tolerance * abs(lower)
            if value < lower - tolerance:
                emit('below_quantile', name, value, lower, f'Valor abaixo do quantil {1-cfg.quantile:g} benigno.')
    return alerts, evaluated
