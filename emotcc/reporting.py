"""Portable JSON/CSV/Markdown/SVG artifacts; no plotting dependency needed."""
import csv
import json
from pathlib import Path
from .database import get_meta


def save_json(path, data):
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8')


def export_query(db, path, query, args=()):
    cursor = db.execute(query, args)
    with Path(path).open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow([c[0] for c in cursor.description])
        while True:
            rows = cursor.fetchmany(10000)
            if not rows:
                break
            writer.writerows(rows)


def write_reports(db, cfg, metrics=None):
    out = Path(cfg.output_dir)
    save_json(out / 'inspection.json', get_meta(db, 'inspection'))
    save_json(out / 'split.json', get_meta(db, 'split'))
    profiles = [json.loads(r[0]) for r in db.execute('SELECT payload FROM profiles ORDER BY profile_id')]
    save_json(out / 'profiles.json', profiles)
    save_json(out / 'profile_stability.json', get_meta(db, 'profile_stability'))
    if metrics is None:
        return
    metrics['preparation'] = get_meta(db, 'preparation')
    metrics['build_seconds'] = get_meta(db, 'build_seconds')
    save_json(out / 'metrics.json', metrics)
    for detector in ('A', 'B'):
        export_query(db, out / f'alerts_{detector}.csv', '''SELECT a.*,e.source,e.source_row,e.source_timestamp
            FROM alerts a JOIN events e USING(event_id) WHERE a.detector=? ORDER BY a.rowid''', (detector,))
        m = metrics['detectors'][detector]
        with (out / f'confusion_{detector}.csv').open('w', encoding='utf-8', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerows([['actual/predicted','BENIGN','MALICIOUS'],
                             ['BENIGN',m['tn'],m['fp']],['MALICIOUS',m['fn'],m['tp']]])
    export_query(db, out / 'decisions.csv', 'SELECT * FROM decisions ORDER BY sequence,detector')
    if cfg.export_events:
        export_query(db, out / 'events.csv', 'SELECT * FROM events ORDER BY source,source_row')
    export_query(db, out / 'duplicates.csv', 'SELECT * FROM duplicates ORDER BY source,source_row')
    export_query(db, out / 'by_attack.csv', '''SELECT d.detector,e.label,count(*) AS events,
        sum(d.suspicious) AS suspicious_events,
        CAST(sum(d.suspicious) AS REAL)/count(*) AS alert_rate
        FROM decisions d JOIN events e USING(event_id) GROUP BY d.detector,e.label ORDER BY d.detector,e.label''')
    export_query(db, out / 'aggregation_by_label.csv', '''SELECT label,split,count(*) AS events,
        min(number) AS min_number,max(number) AS max_number,avg(number) AS mean_number
        FROM events WHERE split!='excluded' GROUP BY label,split ORDER BY label,split''') if 'number' in cfg.features else None
    with (out / 'comparison.csv').open('w', encoding='utf-8', newline='') as stream:
        fields = ['detector', *metrics['detectors']['A']]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({'detector': d, **m} for d, m in metrics['detectors'].items())
    write_chart(out, metrics)
    write_markdown(out, db, cfg, metrics)


def write_chart(out, metrics):
    elements = ['<svg xmlns="http://www.w3.org/2000/svg" width="800" height="370" viewBox="0 0 800 370">',
                '<rect width="800" height="370" fill="white"/>',
                '<g font-family="sans-serif" fill="#172b3a"><text x="28" y="32" font-size="22">Comparação dos detectores (0–1)</text>',
                '<text x="28" y="58" font-size="14">A: global (azul) · B: Digital Twin (laranja) · menor FPR é melhor</text>']
    for i, (name, title) in enumerate([('precision','Precisão'),('recall','Recall'),('f1','F1'),('fpr','FPR')]):
        y = 98 + i*65
        elements.append(f'<text x="28" y="{y+14}" font-size="16">{title}</text>')
        for j, detector in enumerate(('A','B')):
            value = metrics['detectors'][detector][name]
            width = 0 if value is None else value * 470
            color = '#1666aa' if detector == 'A' else '#b65c16'
            text = 'indefinido' if value is None else f'{value:.4f}'
            elements.append(f'<rect x="140" y="{y+j*23}" width="{width}" height="18" fill="{color}"/><text x="{150+width}" y="{y+14+j*23}" font-size="13">{detector}: {text}</text>')
    elements.append('</g></svg>')
    (out/'comparison.svg').write_text('\n'.join(elements), encoding='utf-8')


def write_markdown(out, db, cfg, metrics):
    def fmt(value):
        return 'indefinido' if value is None else f'{value:.6f}'
    inspection, split = get_meta(db, 'inspection'), get_meta(db, 'split')
    rows = ['# Experimento CICIoT2023 — Digital Twin simplificado', '',
            f"Execução: `{metrics['run_id']}`. Dados reais fornecidos pelo usuário; sem resultados sintéticos neste relatório.", '',
            '## Configuração e população', '',
            f"Arquivos: {len(inspection['files'])}; linhas lidas: {inspection['rows_read']:,}; inválidas: {inspection['invalid_rows']:,}; duplicatas: {inspection['duplicates']:,}; vetores conflitantes excluídos: {inspection['conflicting_vectors']:,}.",
            f"Construção: {split['build']:,} observações benignas únicas; benignos de teste: {split['test_benign']:,}. Partição: `{split['method']}`, semente {cfg.seed}, fração {cfg.train_fraction}.",
            f"Limiares: quantil {cfg.quantile}; mínimo de {cfg.min_profile_samples} observações por perfil. Regras: {', '.join(cfg.rule_features)}; limites inferiores: {', '.join(cfg.two_sided)}.",
            f"Amostragem: {'leitura completa dos arquivos configurados' if cfg.max_rows_per_file is None else 'AMOSTRA: primeiras '+str(cfg.max_rows_per_file)+' linhas por arquivo; não representa o dataset completo'}.", '',
            '## Detecção', '',
            'Positivo = rótulo diferente de BENIGN. Um evento é suspeito quando pelo menos uma regra dispara; várias regras contam uma única vez na matriz de confusão. Alerta não confirma ataque.', '',
            '| Detector | TP | FP | TN | FN | Precisão | Recall | F1 | FPR | Alertas de regras |',
            '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for d,m in metrics['detectors'].items():
        rows.append(f"| {d} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['fpr'])} | {m['alerts']} |")
    a,b = (metrics['detectors'][d] for d in ('A','B'))
    if a['f1'] is not None and b['f1'] is not None:
        rows += ['', f"Diferença B − A de F1: {b['f1']-a['f1']:+.6f}; de FPR: {b['fpr']-a['fpr']:+.6f}. Resultado descritivo de uma partição; sem inferência causal ou significância estatística."]
    coverage = metrics['coverage']
    rows += ['', 'Classes presentes na entrada mas ausentes do teste: '+
             (', '.join(metrics.get('classes',{}).get('input_labels_absent_from_test',[])) or 'nenhuma entre os rótulos fornecidos')+'.',
             'Ataques esperados na configuração mas ausentes do teste: '+
             (', '.join(metrics.get('classes',{}).get('expected_attacks_absent_from_test',[])) or 'nenhum entre os ataques explicitamente configurados')+'.',
             '', '## Viabilidade e custo', '',
             f"Cobertura específica de eventos: {fmt(coverage['specific_profile_coverage'])}; grupos representados: {coverage['represented_test_groups']}/{coverage['observed_test_groups']}; eventos de protocolo não observado: {coverage['unseen_protocol_events']}; fallback por escassez: {coverage['sparse_fallback_events']}.",
             f"Construção dos perfis: {metrics['build_seconds']:.3f} s; replay: {metrics['timing']['replay_seconds']:.3f} s; média por evento: {fmt(metrics['timing']['mean_replay_seconds_per_event'])} s.",
             f"Consulta ao perfil (SQL + acesso ao cache): {fmt(metrics['timing']['lookup_seconds']['mean'])} s em média; P95 {fmt(metrics['timing']['lookup_seconds']['p95'])} s; {metrics['timing']['profile_lookup_calls']} chamadas.",
             'O cache armazena payloads imutáveis; cada evento B ainda consulta SQLite para a existência/atividade do perfil. A recebe sua referência global uma vez. A ordem de medição é A e depois B. Tempos incluem overhead de instrumentação e não demonstram desempenho em hardware de borda.',
             'A estabilidade compara quantis em duas fatias intercaladas ordenadas pelo hash do vetor, apenas dentro da construção benigna. Não mede estabilidade temporal; ver profile_stability.json.', '',
             '## Limitações e interpretação', '',
             '* Sem IPs, destinos ou IDs de dispositivos: cobertura de dispositivos, relações permitidas, autenticação e regras por destino não foram medidas.',
             '* Protocol Type é uma categoria numérica observada. Sem o extrator exato destes CSVs, não atribuímos uma semântica de dispositivo ou uma interpretação de código IP garantida. Indicadores fracionários são preservados como proporções.',
             '* Sem timestamps documentados, a ordem é determinística por arquivo/linha; não é cronológica. Ordenação temporal só é ativada quando timestamp_format é explicitamente configurado e ts é validado.',
             '* As unidades e janelas destes CSVs não foram certificadas pelo extrator original. IAT mantém a escala de origem e Tot size não é renomeado como bytes totais. Ver aggregation_by_label.csv: diferenças de Number entre classes podem refletir agregação e facilitar artificialmente a classificação.',
             '* Duplicatas são definidas pelo vetor de atributos selecionados, sem Label, origem ou timestamp. É uma proteção conservadora contra vazamento; pode colapsar eventos legítimos distintos e muda a distribuição. Rótulos conflitantes excluem todo o vetor; não são resolvidos por maioria.',
             '* Uma separação aleatória de vetores não garante independência de sessões/dispositivos ou ausência de janelas correlacionadas. Não há identificadores suficientes para medir isso.',
             '* Quantis empíricos e tolerâncias não foram ajustados nos ataques/teste. Várias regras aumentam a probabilidade conjunta de falsos positivos. Variância nula conserva limiar constante com tolerância numérica.',
             '* Perfis raros usam fallback global. Protocolo novo gera alerta para ambos os detectores; cobertura específica e fallback são reportados separadamente.',
             '* Sem atualização de referência com teste: apenas contadores operacionais mudam. Timestamps absolutos e Label não entram nas regras.',
             '* O relatório by_attack.csv lista apenas classes efetivamente avaliadas; não se generaliza para outros arquivos, cenários ou classes ausentes.', '',
             '## Artefatos', '',
             '`inspection.json`, `split.json`, `profiles.json`, `profile_stability.json`, `digital_twin.sqlite`, `alerts_A.csv`, `alerts_B.csv`, `decisions.csv`, `events.csv` (opcional), `duplicates.csv`, `invalid_records.csv`, `metrics.json`, `confusion_A.csv`, `confusion_B.csv`, `comparison.csv`, `comparison.svg`, `by_attack.csv`, `aggregation_by_label.csv`, `manifest.json`.', '',
             'Configuração efetiva, SHA-256 dos arquivos, ambiente e tempos de preparação estão em manifest.json. O SQLite contém as observações, partições, perfis, decisões, alertas, duplicatas e estado operacional consultáveis.']
    (out/'report.md').write_text('\n'.join(rows)+'\n', encoding='utf-8')
