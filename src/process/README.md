# Data Processing

Processes raw stripped binaries and source code into structured datasets for summary generation.

## Pipeline Overview

```
data/raw/binary/<arch>/<project>/   +   data/raw/source/<project>-src/
        |
        v
  IDA Pro (ida_extract.py)  +  src_extract.py
        |
        v
  run_process.py  (align, build CFG/CG, dedup)
        |
        v
  data/processed/<arch>/dataset.pkl.gz
        |
        v  (optional)
  gen_augref.py  (LLM generates reference field)
        |
        v
  data/processed/<arch>/dataset.pkl.gz  (with reference field)
```

## Commands

```bash
# Process a single architecture
python main.py process --arch x64_O2

# Process all architectures
python main.py process --arch all

# Custom paths
python main.py process \
  --arch x64_O2 \
  --bin-dir /path/to/binaries \
  --src-dir /path/to/source \
  --output-dir /path/to/output \
  --ida-path /path/to/idat64
```

## Augmented Reference Generation

Generates high-quality reference summaries from source code via LLM, written back to the `reference` field.
Supports resume on interruption.

```bash
# Full pipeline (collect → generate → apply)
python main.py augref

# Individual steps
python main.py augref --step collect   # aggregate and dedup across all archs
python main.py augref --step generate  # call LLM (resumable)
python main.py augref --step apply     # write reference back to dataset.pkl.gz

# Custom paths / profile
python main.py augref \
  --processed-dir /path/to/processed \
  --work-dir /path/to/work \
  --profile gpt
```

| Step | Input | Output |
|------|-------|--------|
| collect | `processed/<arch>/dataset.pkl.gz` (all archs) | `data/need_to_gen_augref.pkl.gz` |
| generate | `need_to_gen_augref.pkl.gz` | `data/final_ref.pkl.gz` |
| apply | `final_ref.pkl.gz` | `processed/<arch>/dataset.pkl.gz` (updated) |

## Outputs

| File | Description |
|------|-------------|
| `data/processed/<arch>/dataset.pkl.gz` | Main dataset with CFG, CG, and reference fields |
| `data/processed/<arch>/baseline.pkl.gz` | Full-field dataset (includes source and binary metadata) |
| `data/generated/<arch>/shared/train.pkl.gz` | CCR training split |
| `data/generated/<arch>/shared/valid.pkl.gz` | CCR validation split |
| `data/generated/<arch>/shared/test_filtered.json` | Test set (200 samples) |

## Scripts

- `run_process.py` — main entry point; orchestrates IDA extraction, source alignment, and dataset building
- `gen_augref.py` — LLM-based augmented reference generation
- `scripts/ida_extract.py` — IDA Pro script for decompilation and CFG/CG extraction
- `scripts/src_extract.py` — extracts C functions from source directories
- `lib/` — analysis utilities (CFG construction, function matching, etc.)
