# Validação do código

Comando, na raiz do repositório:

```bash
python -m unittest discover -s tests -v
```

A suíte possui **22 testes**, executados com sucesso antes da publicação. Todas as suas fixtures são sintéticas e criadas em diretórios temporários, sem uso dos arquivos reais de entrada.

A cobertura inclui:

* Cabeçalhos, colunas obrigatórias ausentes, arquivos vazios e atribuição explícita de rótulos.
* Normalização e preservação de indicadores fracionários; exclusão de números inválidos.
* Partição benigna, duplicatas entre arquivos, rótulos conflitantes e ausência de vetores idênticos entre partições.
* Estatísticas e percentis conhecidos; proteção contra overflow em números finitos extremos.
* Consulta específica, fallback global, congelamento dos perfis e alertas para categorias novas.
* Motor compartilhado com parâmetros globais/contextuais e ausência de influência do rótulo nas regras.
* Métricas com resultados conhecidos e denominadores indefinidos.
* Reprodução temporal configurada, vários lotes e igualdade de decisões entre etapas e execução única.
* Precisão temporal consistente entre blocos de CSV e exclusão de datas fora do intervalo representável em nanosegundos.
* Proteção contra sobrescrita e reprodutibilidade com diferentes tamanhos de bloco.

A análise sintática dos módulos e `git diff --cached --check` também foram executados. O workflow `.github/workflows/tests.yml` configura a suíte para Python 3.10 e 3.13 em GitHub Actions.

Para validar com dados reais, configure os arquivos em `config/config.json` e execute `python -m emotcc run --output outputs/nova-execucao`. O programa produz relatórios com a população efetivamente avaliada, exclusões, limitações e configuração. Os resultados experimentais não acompanham o código publicado.
