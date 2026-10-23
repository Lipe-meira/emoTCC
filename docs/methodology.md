# Decisões metodológicas

## Escopo

O sistema implementa uma prova de conceito offline de Digital Twin simplificado: perfis consultáveis de comportamento benigno, comparação de parâmetros globais e contextuais e avaliação pareada dos detectores. Não modela uma rede física completa, captura de tráfego, aprendizado de máquina ou resposta ativa.

O script exploratório que acompanha a solicitação serve como ponto de partida para os atributos. O pipeline não mantém um limite implícito de linhas nem filtra automaticamente uma única classe de ataque.

## Ingestão e representação

* Os arquivos são configurados explicitamente e lidos em blocos. Arquivo sem `Label` exige uma atribuição explícita de rótulo sustentada pela procedência.
* Os atributos selecionados são convertidos para números. Indicadores entre zero e um podem representar proporções; valores fracionários não são arredondados.
* Valores ausentes, inválidos, infinitos, negativos, proporções fora de faixa e estatísticas inconsistentes são excluídos e auditados, sem imputação silenciosa.
* Ausência de coluna opcional reduz o vetor de todos os arquivos ao mesmo conjunto disponível. Ausência de coluna obrigatória interrompe a ingestão.
* Sem o extrator correspondente, as unidades permanecem na escala de origem. `Protocol Type` é tratado como categoria numérica observável, sem inferir dispositivo ou garantir interpretação de código IP.

## Separação sem vetores idênticos entre construção e teste

O SHA-256 é calculado sobre doubles normalizados em ordem fixa e formato little-endian. Rótulo, origem e timestamp ficam fora da identidade do vetor. Zero negativo é normalizado.

Vetores iguais são conservados uma vez, inclusive entre arquivos; suas procedências adicionais são registradas. Rótulos divergentes excluem o vetor inteiro, sem resolução por maioria. Essa política é conservadora e pode colapsar eventos físicos distintos que sejam indistinguíveis para os detectores.

A divisão 70/30 é aplicada apenas aos benignos válidos únicos sem conflito. Ataques entram somente no teste. Sem tempo confiável, a partição usa uma ordenação de hashes derivados da semente, independente dos blocos de leitura. Com timestamps explicitamente documentados e validados, reserva os benignos mais antigos para construção e reproduz o teste em ordem temporal com desempates estáveis.

Uma partição por vetor não garante independência de sessões ou dispositivos. Essa limitação precisa ser registrada quando faltam identificadores para uma separação por grupo físico.

## Perfis e detectores

SQLite contém a área de preparação, a referência e a trilha de auditoria. Percentis exatos carregam uma coluna de construção de cada vez; o consumo de memória ainda cresce com o número de benignos. A distribuição dos tempos de consulta usa oito bytes por evento, portanto a memória não é estritamente constante.

Perfis globais e por categoria têm o mesmo conjunto de estatísticas. Perfis com amostras insuficientes ficam inativos; B aplica fallback global e registra a ocorrência. Protocolo novo gera uma regra idêntica em A/B. A referência global também exige uma amostra mínima.

As regras padrão verificam quantis superiores de Rate, Tot size, Number e IAT, o quantil inferior de IAT e o uso de categorias/indicadores não observados na referência. O motor é compartilhado: A recebe parâmetros globais; B consulta os específicos quando disponíveis. Nenhum deles recebe o rótulo no replay.

P99 é uma escolha inicial fixa, com P95/P99 disponíveis para inspeção; não promete FPR conjunta de 1%. Extremos válidos não são eliminados para favorecer métricas. Limiares constantes conservam tolerância numérica. Média e desvio padrão usam escala intermediária para evitar overflow com números finitos extremos.

Perfis são congelados por triggers SQLite. Somente o estado operacional de contagem e último evento é atualizado durante o teste. A referência de A é carregada uma vez. B consulta existência/atividade no SQLite por evento e mantém os payloads imutáveis em cache.

## Avaliação e rastreabilidade

Um evento com várias regras disparadas conta uma vez como suspeito na matriz de confusão. Os alertas individuais são preservados separadamente. Os rótulos servem à definição da população benigna e à avaliação, sem serem uma variável das regras ou da escolha de perfil.

Cobertura específica, fallback, categorias ausentes, TP/FP/TN/FN, precisão, recall, F1, FPR e custo são registrados com configuração e hashes de entrada. Métricas indefinidas têm valor `null`. Estabilidade compara fatias intercaladas da construção ordenada por hash; não é evidência de estabilidade temporal.

Diferenças de agregação podem funcionar como atalhos de classificação. O diagnóstico de `Number` por classe/partição auxilia essa análise. Um holdout não fornece, por si só, significância estatística ou evidência causal. Os custos são do ambiente de execução e não comprovam desempenho em equipamento de borda.

Dados de entrada e resultados experimentais permanecem na pasta de saída da execução. O repositório publicado contém a implementação, configuração e testes sintéticos, sem artefatos derivados de entradas locais.

Referência pública de contexto: [UNB/CIC — IoT Dataset 2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html).
