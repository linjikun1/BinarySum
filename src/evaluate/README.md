# Evaluation Framework for Binary Code Summarization

This repository contains the evaluation metrics for the Binary Code Summarization project.

## Structure

- `n_gram_metrics/`: Traditional N-gram based metrics (BLEU, ROUGE-L, METEOR).
- `semantic_metrics/`: Embedding-based metrics (CodeBERTScore, SIDE).
- `llm_eval/`: LLM-based evaluation using a vendored version of `deepeval`.

## Installation
```bash
pip install -r requirements.txt
```

```bash
pip install -U deepeval==3.7.2
```

## Usage

See `run_evaluation.py` (you need to create this entry point based on your needs) or import individual calculators:

```python
from evaluate.n_gram_metrics.metric_calculator import NGramMetricsCalculator
from evaluate.semantic_metrics.code_bert_score import CodeBERTScoreCalculator
from evaluate.semantic_metrics.side import SideCalculator

# ... load your data ...

# 1. N-Gram
ngram_calc = NGramMetricsCalculator()
print(ngram_calc.compute(references, hypotheses))

# 2. Semantic
cbs_calc = CodeBERTScoreCalculator()
print(cbs_calc.compute(hypotheses, references))

side_calc = SideCalculator()
print(side_calc.compute(hypotheses, source_codes))
```
