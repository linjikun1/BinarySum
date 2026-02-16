# BinarySum: Binary Code Summary Generation Framework

This repository implements **HPSS-CAPD**, a framework for generating summaries for stripped binary code.

## Project Structure

```
BinarySum/
├── dataset/           # Raw data files
├── src/
│   ├── process/       # Data preprocessing (IDA Pro extraction, dataset matching)
│   ├── generate/      # Summary generation modules
│   │   ├── hpss/      # Hierarchical Path-Sensitive Summarization
│   │   ├── capd/      # Context-Aware Program Denoising (CCR + SDN)
│   │   └── synthesizer/ # Final summary synthesis
│   └── evaluate/      # Evaluation metrics
│       ├── n_gram_metrics/   # BLEU, ROUGE-L, METEOR
│       ├── semantic_metrics/ # CodeBERTScore, SIDE
│       └── llm_eval/         # LLM-based evaluation
└── main.py            # Unified entry point
```

## Requirements

- Python 3.8+
- IDA Pro 9.1 (with Hex-Rays Decompiler, for preprocessing)
- OpenAI API Key (for generation)

## Installation

```bash
pip install -r requirements.txt

# Optional: LLM-based evaluation
pip install -U deepeval==3.7.2
```

## Usage

The framework provides three main commands: `preprocess`, `generate`, and `evaluate`.

### 1. Data Preprocessing

Process binary files and align them with source code.

```bash
# Process a single architecture
python main.py preprocess \
  --bin-dir /path/to/binary/dir \
  --src-dir /path/to/source/dir \
  --arch-opt x64_O3 \
  --output-dir /path/to/output \
  --ida-path /path/to/idat

# Process all architectures (auto-detect)
python main.py preprocess \
  --bin-dir /path/to/binary/dir \
  --src-dir /path/to/source/dir \
  --arch-opt all \
  --output-dir /path/to/output
```

**Outputs:**
- `baseline.pkl.gz`: Comprehensive dataset for BinT5, HexT5, CP-BCS, MiSum, ProRec
- `dataset.pkl.gz`: CFG and Call Graph data with enriched callers/callees

### 2. Summary Generation (Ablation Modes)

The framework supports 4 ablation modes:

| Mode | Description | Components |
|------|-------------|------------|
| M1 | Baseline | Decompiled Code only |
| M2 | + HPSS | Decompiled + CFG Description |
| M3 | + HPSS + CCR | M2 + Raw Source Candidates |
| M4 | Full | M3 + SDN Filtering |

```bash
# M1: Baseline (Decompiled Code only)
python main.py generate \
  --input /path/to/dataset.json \
  --output /path/to/results.json \
  --mode M1

# M2: + HPSS (CFG Description)
python main.py generate \
  --input /path/to/dataset.json \
  --output /path/to/results.json \
  --mode M2

# M3: + HPSS + CCR (Raw Source Candidates)
python main.py generate \
  --input /path/to/dataset.json \
  --output /path/to/results.json \
  --mode M3

# M4: Full (HPSS + CCR + SDN Filtering)
python main.py generate \
  --input /path/to/dataset.json \
  --output /path/to/results.json \
  --mode M4
```

### 3. Evaluation

Evaluate the generated summaries against reference summaries.

```bash
python main.py evaluate \
  --input-file /path/to/results.json \
  --output-file /path/to/metrics.json \
  --systems generated_summary \
  --ngram \
  --semantic \
  --llmeval
```