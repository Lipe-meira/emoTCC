# emoTCC — Digital Twin simplificado para CICIoT2023

Prova de conceito em Python e SQLite para avaliar se perfis de tráfego benigno ajudam a identificar desvios em comparação com limiares globais. A avaliação é **offline**, interpretável e reproduzível. Não usa aprendizado de máquina, captura de rede ou resposta automática.

O Detector **A** aplica parâmetros globais benignos. O Detector **B** consulta o Digital Twin para obter parâmetros do grupo de protocolo observado. Os dois usam o mesmo motor de regras, recebem os mesmos eventos e não recebem `Label`. Uma execução pode produzir resultados positivos, neutros ou negativos para B.

## Instalação

Python 3.10 ou superior. No diretório do repositório:

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements.txt
```

Opcional: `python -m pip install -e .` disponibiliza o comando `emotcc`. Os comandos abaixo também funcionam diretamente no repositório sem essa instalação.

## Arquivos de entrada

Coloque em `dataset/` os arquivos de tráfego fornecidos para o experimento:

```text
BenignTraffic.pcap.csv
BenignTraffic1.pcap.csv
BenignTraffic2.pcap.csv
BenignTraffic3.pcap.csv
Merged01.csv
Merged02.csv
Merged03.csv
```

A configuração atribui `BENIGN` explicitamente aos arquivos `BenignTraffic`, para permitir sua leitura quando não contêm rótulo. Essa atribuição é uma hipótese de procedência que precisa ser sustentada pela origem dos dados, não uma inferência do conteúdo ou uma detecção automática pelo nome. Os arquivos `Merged` precisam conter `Label`. Novos arquivos podem ser incluídos em `inputs`.

Os CSVs originais e bancos/resultados volumosos não são versionados. O programa só lê os originais. `config/config.json` resolve caminhos relativos à própria configuração. `--input-dir` permite usar os arquivos diretamente de outro diretório, sem copiá-los.

## Executar

Fluxo completo em um comando:

```bash
python -m emotcc run --config config/config.json --output outputs/execucao-01
```

Usando os arquivos de Downloads no Windows:

```powershell
python -m emotcc run --input-dir "$env:USERPROFILE\Downloads" --output outputs/execucao-01
```

Prova de conceito menor, claramente marcada como amostra nos relatórios:

```bash
python -m emotcc run --max-rows-per-file 2000 --output outputs/amostra-01
```

Etapas separadas, utilizando **a mesma pasta e configuração**:

```bash
python -m emotcc inspect --output outputs/etapas-01
python -m emotcc build --output outputs/etapas-01
python -m emotcc evaluate --output outputs/etapas-01
```

`inspect` varre os arquivos em blocos, valida, deduplica e grava a área de trabalho SQLite e a auditoria. `build` também pode ser executado diretamente, sem `inspect`. `evaluate` exige os perfis já construídos. A pasta de uma execução completa precisa estar vazia; não existe sobrescrita silenciosa ou reavaliação que misture resultados. Use uma pasta nova para outro experimento, inclusive depois de uma execução interrompida.

## Configuração

Os valores padrão e as validações ficam em `emotcc/config.py`; apenas os valores que quiser mudar precisam constar no JSON.

| Campo | Padrão | Efeito |
|---|---|---|
| `inputs` | lista em `config/config.json` | Caminhos e `label` explícito somente quando a procedência permite atribuí-lo |
| `output_dir` | `../outputs/experiment` no JSON | Pasta exclusiva da execução |
| `features` | 17 atributos do script inicial | Vetor validado, armazenado e usado para deduplicação; `Label` é proibido |
| `rule_features` | `rate`, `tot_size`, `number`, `iat` | Atributos comparados com limiares superiores |
| `two_sided` | `iat` | Também compara com o quantil inferior |
| `train_fraction` | `0.7` | Fração exata, arredondada para baixo, dos vetores benignos únicos |
| `seed` | `42` | Ordenação pseudoaleatória determinística para a partição sem timestamps |
| `quantile` | `0.99` | Limite superior; inferior = `1 - quantile` |
| `min_profile_samples` | `100` | Quantidade mínima para ativar um perfil; exige referência global suficiente |
| `chunk_size` | `50000` | Limite de linhas por bloco de leitura e replay |
| `max_rows_per_file` | `null` | Leitura completa; um inteiro positivo limita explicitamente a amostra |
| `timestamp_format` | `null` | Sem inferência temporal; aceita `iso8601`, `unix_s`, `unix_ms`, `unix_us`, `unix_ns` quando documentado |
| `check_protocol` | `true` | Alerta para categoria ausente na construção benigna |
| `check_indicators` | `true` | Alerta se indicador positivo não foi observado na referência utilizada |
| `absolute_tolerance` / `relative_tolerance` | `1e-12` / `1e-9` | Tolerância numérica no limite, inclusive em distribuições constantes |
| `export_events` | `true` | Exporta eventos também em CSV; o banco sempre os conserva |
| `expected_attack_labels` | 33 classes de ataque, no JSON fornecido | Universo esperado para informar ataques ausentes do teste; não participa da detecção |

Colunas necessárias são `protocol_type` e as de `rule_features`. Colunas opcionais ausentes são informadas e removidas do vetor **em todos os arquivos** para manter entradas comparáveis. Ausência de coluna obrigatória, arquivo vazio, rótulo não atribuído ou referência benigna insuficiente encerra a etapa com erro claro. Configurações metodológicas diferentes entre construção e avaliação são rejeitadas.

Os nomes canônicos são `protocol_type`, `tcp`, `udp`, `http`, `https`, `dns`, `arp`, `icmp`, `rate`, `number`, `tot_size`, `tot_sum`, `min`, `max`, `avg`, `std`, `iat`. O mapeamento dos cabeçalhos originais está em `FIELD_MAP`.

## Método experimental

1. Converte os atributos selecionados para números, conserva indicadores fracionários entre 0 e 1 e padroniza os rótulos com espaços removidos e letras maiúsculas. Não padroniza a escala nem imputa valores.
2. Exclui e audita valores ausentes, não numéricos, infinitos, negativos, proporções fora de `[0,1]`, `Number <= 0`, estatísticas de tamanho inconsistentes e timestamps inválidos quando a ordenação temporal foi configurada.
3. Calcula SHA-256 do vetor numérico canônico, sem rótulo, arquivo ou timestamp. Vetores iguais são mantidos uma vez, inclusive entre arquivos. Todas as procedências duplicadas ficam registradas. Conflitos entre rótulos excluem o vetor inteiro.
4. Reserva 70% dos vetores benignos para construção. Sem tempo confiável, ordena por SHA-256 de semente e identificação do vetor, tornando a partição independente do tamanho do bloco. Com `ts` validado e formato explícito, reserva os benignos mais antigos. Ataques entram apenas no teste.
5. Constrói estatísticas exatas de cada atributo não categórico: contagem, média, mediana, desvio padrão amostral, mínimo, máximo, P95, P99 e quantis configurados. Os perfis são globais ou por valor observado de `Protocol Type`.
6. Reproduz o teste em ordem de arquivo/linha ou por timestamp validado, com desempates determinísticos. B consulta a existência/atividade do perfil no SQLite por evento e reutiliza o payload imutável em cache. Grupos escassos ou novos usam a referência global; grupo novo também dispara a mesma regra de protocolo em A e B.
7. Persiste decisões de todos os eventos, inclusive os sem alerta, e todos os motivos de regras disparadas. Mantém contadores observados separados dos perfis congelados. Triggers SQLite impedem mutações posteriores dos perfis.
8. Usa os rótulos somente para avaliar as decisões. A seleção inicial dos benignos usa `Label` para definir a população de construção; o cálculo de estatísticas e as regras não usam o rótulo como variável.

P99 é uma escolha inicial fixa para reduzir a sensibilidade a caudas pesadas e a falsos positivos quando várias regras são combinadas; não promete FPR de 1%. P95 e P99 ficam disponíveis para inspeção. Os extremos não são cortados nem ajustados para favorecer os resultados. Duas fatias intercaladas da construção, ordenadas pelo hash, permitem comparar a estabilidade dos quantis; isso não demonstra estabilidade temporal.

## Métricas e artefatos

`report.md` contém a comparação e as limitações. A pasta também contém:

| Artefato | Conteúdo |
|---|---|
| `inspection.json`, `invalid_records.csv` | Dimensões, esquemas, rótulos, qualidade e registros excluídos |
| `manifest.json` | Configuração efetiva, SHA-256 de cada arquivo, ambiente e preparação |
| `split.json`, `duplicates.csv` | Contagens por partição/classe e duplicatas rastreáveis |
| `profiles.json`, `profile_stability.json` | Estatísticas, quantis e comparação de fatias benignas |
| `digital_twin.sqlite` | Eventos, perfis, decisões, alertas, estado operacional e metadados |
| `alerts_A.csv`, `alerts_B.csv` | Uma linha por regra disparada, com evento, origem, valor, limite e perfil |
| `decisions.csv`, `events.csv` | Uma decisão por detector/evento e vetor de entrada auditável |
| `metrics.json`, `comparison.csv` | Métricas de detecção, cobertura e custo |
| `confusion_A.csv`, `confusion_B.csv` | Matrizes: linhas = classe real; colunas = decisão |
| `by_attack.csv` | Eventos e taxa de alerta por classe e detector |
| `aggregation_by_label.csv` | Diagnóstico de `Number` por rótulo e partição |
| `comparison.svg` | Gráfico vetorial de precisão, recall, F1 e FPR |

Um evento com uma ou várias regras disparadas é **uma** previsão positiva. TP = ataque alertado; FP = benigno alertado; TN = benigno sem alerta; FN = ataque sem alerta. Precisão = TP/(TP+FP), recall = TP/(TP+FN), F1 = 2TP/(2TP+FP+FN), FPR = FP/(FP+TN). Denominadores zero geram `null`/“indefinido”. Quantidade de alertas de regras é reportada separadamente da quantidade de eventos suspeitos.

A cobertura informa grupos observados/representados, eventos com perfil específico, fallback por escassez e protocolos novos. Cobertura de dispositivos é indisponível. Os tempos usam `perf_counter`; leitura inicial de CSV, preparação, construção, replay, consulta a perfis, escrita de auditoria e execução dos detectores são diferenciados. A medição de consulta inclui SQL e acesso ao cache; A recebe sua referência global uma vez. Tempos são específicos do computador da execução.

## Arquitetura e consulta

| Módulo | Responsabilidade |
|---|---|
| `config` | Parâmetros, mapeamento e validação |
| `data_loader`, `preprocessing` | Leitura por blocos, normalização e qualidade |
| `pipeline`, `dataset_split` | Ingestão, deduplicação, partição e etapas |
| `profile_builder`, `database` | Estatísticas e persistência SQLite |
| `digital_twin` | API de consulta com fallback e medição de custo |
| `detectors`, `replay` | Motor de regras idêntico e processamento pareado |
| `evaluation`, `reporting` | Métricas e exportações |

```python
from emotcc.database import connect
from emotcc.digital_twin import DigitalTwin

db = connect('outputs/execucao-01/digital_twin.sqlite')
try:
    twin = DigitalTwin(db)
    profile, status = twin.lookup('protocol:6')
    print(status, profile['stats']['rate']['p99'])
finally:
    db.close()
```

O detector só depende do payload da API, sem consultas diretas ao esquema interno. `events.split` documenta a partição; `decisions` conserva resultado, perfil e contagem de regras por evento; `alerts` conserva os motivos; `operational_state` conserva apenas contadores e último evento observados. `metadata` identifica a execução e suas condições.

## Testes

```bash
python -m unittest discover -s tests -v
```

As fixtures são sintéticas, criadas em diretórios temporários e separadas dos resultados reais. Os testes cobrem esquema, ausência de colunas, normalização, dados inválidos, classes, deduplicação/conflitos, construção exclusivamente benigna, partição sem sobreposição, percentis conhecidos, consulta/fallback, perfis congelados, regras, ausência de influência do rótulo, métricas conhecidas, ordenação temporal, reprodutibilidade entre blocos e etapas e proteção contra sobrescrita. GitHub Actions executa a suíte em Python 3.10 e 3.13.

## Limitações científicas

Este Digital Twin representa **grupos de tráfego**, não dispositivos, topologia ou uma réplica física. Quando os CSVs não contêm `ts`, IPs, portas ou IDs de dispositivos, não há base para executar regras de destinos, autenticação, horário ou correlação por dispositivo. A sincronização com uma rede física permanece fora do escopo.

A [documentação oficial do CICIoT2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html) descreve o dataset e seu processo geral de extração. É necessário verificar a correspondência entre os arquivos utilizados e o extrator que os produziu antes de certificar unidades ou equivalência com a distribuição original. `Protocol Type` é tratado como categoria observada; indicadores fracionários de protocolo são preservados como proporções. `Tot size` conserva seu nome e escala: não é apresentado automaticamente como volume total em bytes.

Diferenças de agregação entre classes podem facilitar a detecção de forma dependente da preparação do dataset. Confira `aggregation_by_label.csv` para examinar `Number` e evite atribuir resultados altos apenas à qualidade do modelo. Para uma análise de sensibilidade, crie **outra configuração e outra saída** com `rule_features` sem `number`; não ajuste regras usando os resultados finais para escolher o melhor teste.

A deduplicação pelo vetor selecionado é conservadora: colapsa observações indistinguíveis para os detectores, mesmo que sejam eventos físicos diferentes. A partição aleatória protege contra vetores idênticos, mas não garante independência entre janelas/sessões, pois faltam identificadores. Um único holdout não fornece intervalos de confiança ou evidência causal. O estudo não comprova desempenho em redes 5G/6G, dispositivos IoT físicos ou hardware real de borda.

As decisões metodológicas estão em [docs/methodology.md](docs/methodology.md). A cobertura dos testes sintéticos está em [docs/validation.md](docs/validation.md). Dados de entrada, resultados experimentais e metadados locais são gerados na pasta de saída e não acompanham o código publicado.
