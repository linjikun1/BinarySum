# Evaluation

Computes multiple evaluation metrics for generated binary function summaries.

## Metrics

| Category | Metric | Notes |
|----------|--------|-------|
| TexSim | BLEU-4, METEOR, ROUGE-L | Token-level similarity vs. reference |
| SemSim | CodeBERTScore, SIDE | Semantic similarity (requires local models) |
| LLMJudge | Accuracy, Coverage, Effectiveness | LLM-as-a-Judge with 3-step pipeline |

## Commands

```bash
# Single mode
python main.py evaluate --arch x64_O2 --mode M4 --texsim --semsim --llmjudge

# Multiple modes in one run (shared Step-1 LLM baseline, 3 API calls total)
python main.py evaluate --arch x64_O2 --mode M2 M3 M4 --llmjudge

# Custom input/output
python main.py evaluate \
  --arch x64_O2 \
  --mode M4 \
  --input-file /path/to/summary.json \
  --output-file /path/to/metrics.json \
  --texsim --semsim --llmjudge \
  --profile gpt

# Use token logprobs for finer-grained LLMJudge scoring (requires model support)
python main.py evaluate --arch x64_O2 --mode M4 --llmjudge --logprobs
```

## Output

Results are saved to `data/results/<arch>/<modes>_metrics.json`.

Each item in the output file has a `metrics` field:
```json
{
  "generated_summary": "...",
  "reference": "...",
  "source_code": "...",
  "metrics": {
    "generated_summary": {
      "BLEU-4": 0.12,
      "METEOR": 0.21,
      "ROUGE-L": 0.18,
      "CodeBERTScore": 0.83,
      "SIDE": 0.71,
      "accuracy": 0.67,
      "coverage": 0.44,
      "effectiveness": 0.56
    }
  }
}
```

## LLMJudge Pipeline

LLMJudge uses a unified 3-step pipeline per sample, regardless of how many modes are evaluated:

1. **Step 1** — Extract core source semantics from `source_code` (runs once, shared across all modes)
2. **Step 2** — Extract and tag atomic claims for all summaries (one API call for all modes)
3. **Step 3** — Score all summaries on accuracy / coverage / effectiveness (one API call for all modes)

This guarantees a consistent reference baseline across modes and keeps cost at exactly **3 API calls per sample**.

Claim tags used in Step 2:
- `[ACCURATE/GOLD]` — specific, high-information, verifiable claim
- `[ACCURATE/SAFE]` — correct but generic / low-information
- `[INACCURATE/FATAL]` — contradicts source semantics
- `[INACCURATE/NOISE]` — no corresponding behavior in source

## Module Layout

```
src/evaluate/
├── run_evaluation.py        # entry point
├── texsim/                  # BLEU, METEOR, ROUGE
├── semsim/                  # CodeBERTScore, SIDE
│   └── models/              # local model checkpoints (set paths in config.ini)
└── llmjudge/
    ├── unified_evaluator.py # UnifiedLLMJudgeEvaluator (3-step pipeline)
    └── evaluator.py         # legacy single-metric evaluator
```

## SemSim Model Paths

Set model paths in `config.ini` under `[semsim]`:

```ini
[semsim]
codebert_model_path = /path/to/models/codebert-base
unixcoder_model_path = /path/to/models/unixcoder-base
```

Leave empty to download from HuggingFace Hub automatically.
