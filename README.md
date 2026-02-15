# BinarySum: Binary Code Summary Generation Framework

This repository implements a framework for generating summaries for stripped binary code, supporting research into hierarchical path-based semantic summarization (HPSS) and cross-architecture alignment.

## Project Structure

- `dataset/`: Contains raw data files.
- `src/process/`: Data preprocessing scripts (IDA Pro extraction, dataset matching).
- `src/generate/`: Summary generation modules (HPSS, Synthesis).
- `src/evaluate/`: Evaluation metrics (N-gram, Semantic, LLM-based).
- `main.py`: Unified entry point for the framework.

## Usage

The framework provides three main commands: `preprocess`, `generate`, and `evaluate`.

### 1. Data Preprocessing

Process binary files and align them with source code.

```bash
python main.py preprocess \
  --bin-dir /path/to/binary/dir \
  --src-dir /path/to/source/dir \
  --arch-opt x64_O3 \
  --output-dir /path/to/output \
  --ida-path /path/to/idat
```

### 2. Summary Generation

Generate summaries using the processed dataset. Supports ablation studies.

**Basic Generation (Decompiled Code only):**
```bash
python main.py generate \
  --input /path/to/dataset.json \
  --output /path/to/results.json
```

**Generation with HPSS (Hierarchical Path-Sensitive Summarization):**
```bash
python main.py generate \
  --input /path/to/dataset.json \
  --output /path/to/results.json \
  --enable-hpss \
  --use-cfg
```

**Generation with HPSS + SDN Snippets (Ablation):**
```bash
python main.py generate \
  --input /path/to/dataset.json \
  --output /path/to/results.json \
  --enable-hpss \
  --use-cfg \
  --snippet-mode sdn
```

Arguments:
- `--enable-hpss`: Run the HPSS pipeline to generate CFG descriptions first.
- `--use-cfg`: Include the CFG description in the synthesis prompt.
- `--snippet-mode`: `none` (default), `raw`, or `sdn` (Filtered snippets).

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

Arguments:
- `--systems`: Comma-separated list of JSON keys containing summaries to evaluate.
- `--ngram`: Run BLEU, METEOR, ROUGE.
- `--semantic`: Run CodeBERTScore, SIDE.
- `--llmeval`: Run LLM-based evaluation.

## Requirements

- Python 3.8+
- IDA Pro (for preprocessing)
- OpenAI API Key (for generation)
