"""Run with python -m emotcc {inspect,build,evaluate,run} --config ..."""
import argparse
import sys
from pathlib import Path
from .config import Config
from .pipeline import prepare, build, evaluate, run


def main(argv=None):
    parser = argparse.ArgumentParser(description='Digital Twin simplificado — CICIoT2023 offline')
    parser.add_argument('command', choices=['inspect','build','evaluate','run'])
    parser.add_argument('--config', default='config/config.json')
    parser.add_argument('--input-dir', help='Substitui o diretório de todos os arquivos configurados')
    parser.add_argument('--output', help='Nova pasta de saída, ou pasta existente para build/evaluate')
    parser.add_argument('--max-rows-per-file', type=int, help='Amostra explícita para prova de conceito')
    args = parser.parse_args(argv)
    try:
        cfg = Config.load(args.config)
        if args.input_dir:
            cfg.inputs = [{**e, 'path': str((Path(args.input_dir)/Path(e['path']).name).resolve())} for e in cfg.inputs]
        if args.output:
            cfg.output_dir = str(Path(args.output).resolve())
        if args.max_rows_per_file is not None:
            cfg.max_rows_per_file = args.max_rows_per_file
        if args.command == 'inspect':
            prepare(cfg, split=False).close()
        else:
            result = {'build':build, 'evaluate':evaluate, 'run':run}[args.command](cfg)
            if result:
                for name, m in result['detectors'].items():
                    print(f"Detector {name}: TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']} F1={m['f1']} FPR={m['fpr']}")
        print(f'Resultados: {cfg.output_dir}')
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f'Erro: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
