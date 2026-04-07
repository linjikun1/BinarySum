# BinarySum

A framework for generating natural-language summaries of stripped binary functions using a hierarchical path-sensitive summarization and context-aware program denoising pipeline (HPSS-CAPD).

## Requirements

- Python 3.8+
- IDA Pro 9.1 with Hex-Rays Decompiler (for data processing)
- OpenAI-compatible API key (for generation and evaluation)

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

```bash
cp config.ini.example config.ini
# Edit config.ini: fill in API keys and model paths
```

## Quick Start

```bash
# 1. Process raw binaries
python main.py process --arch x64_O2

# 2. Generate LLM reference summaries (one-time, all archs)
python main.py augref

# 3. Generate summaries (M1-M4)
python main.py generate --arch x64_O2 --mode M1
python main.py generate --arch x64_O2 --mode M2
python main.py generate --arch x64_O2 --mode M3
python main.py generate --arch x64_O2 --mode M4

# 4. Evaluate
python main.py evaluate --arch x64_O2 --mode M4 --texsim --semsim --llmjudge

# Evaluate multiple modes together (joint LLMJudge baseline)
python main.py evaluate --arch x64_O2 --mode M2 M3 M4 --llmjudge
```

## Modes

| Mode | Components | Description |
|------|-----------|-------------|
| M1 | Decompiled code | Baseline |
| M2 | M1 + HPSS | + CFG-based behavioral description |
| M3 | M2 + CCR | + raw retrieved source snippets (unfiltered) |
| M4 | M3 + SDN | + filtered and confidence-tagged snippets |

## Directory Structure

```
BinarySum/
├── config.ini.example        # Configuration template
├── main.py                   # Unified CLI entry point
├── requirements.txt
├── data/
│   ├── raw/                  # Raw binaries and source code
│   ├── processed/<arch>/     # Processed datasets (dataset.pkl.gz)
│   ├── generated/<arch>/     # Generated summaries
│   │   ├── shared/           # Shared intermediate results (hpss/, ccr/, sdn/)
│   │   └── <mode>/summary.json
│   └── results/<arch>/       # Evaluation metrics (*_metrics.json)
└── src/
    ├── process/              # Data processing pipeline
    ├── generate/             # Summary generation pipeline
    └── evaluate/             # Evaluation metrics
```

For detailed documentation, see:
- [src/process/README.md](src/process/README.md) — data processing and augref
- [src/generate/README.md](src/generate/README.md) — generation pipeline and CCR training
- [src/evaluate/README.md](src/evaluate/README.md) — evaluation metrics
