# Summary Generation

Generates function summaries from processed binary datasets. Four ablation modes are supported.

## Modes

| Mode | Input | Description |
|------|-------|-------------|
| M1 | Decompiled code | Baseline — decompiled code only |
| M2 | M1 + HPSS | + hierarchical path-sensitive CFG description |
| M3 | M2 + CCR | + raw retrieved source snippets (unfiltered) |
| M4 | M3 + SDN | + SDN-filtered and confidence-tagged snippets |

## Data Flow

```
M1:  dataset.pkl.gz --> Synthesizer --> summary.json

M2:  dataset.pkl.gz --> HPSS --> shared/hpss/hpss_summary.json
                                         |
                                    Synthesizer --> summary.json

M3:  shared/hpss/hpss_summary.json  ---|
     shared/ccr/ccr_candidates.json  ---|---> Synthesizer --> summary.json

M4:  shared/hpss/hpss_summary.json  ---|
     shared/ccr/ccr_candidates.json --> SDN --> shared/sdn/sdn_filtered.json
                                                      |
                                               Synthesizer --> summary.json
```

Intermediate results in `shared/` are reused across modes to avoid redundant computation.

## Commands

```bash
python main.py generate --arch x64_O2 --mode M1
python main.py generate --arch x64_O2 --mode M2
python main.py generate --arch x64_O2 --mode M3  # requires CCR training first
python main.py generate --arch x64_O2 --mode M4  # requires CCR training first

# Custom input/output
python main.py generate \
  --arch x64_O2 \
  --mode M4 \
  --input /path/to/dataset.pkl.gz \
  --output /path/to/summary.json \
  --profile gpt
```

## Outputs

```
data/generated/<arch>/
├── shared/
│   ├── test_filtered.json      # filtered test set (200 samples)
│   ├── hpss/
│   │   ├── hpss_paths.json     # extracted execution paths
│   │   └── hpss_summary.json   # CFG behavioral descriptions (M2/M3/M4)
│   ├── ccr/
│   │   └── ccr_candidates.json # retrieved source snippets (M3/M4)
│   └── sdn/
│       └── sdn_filtered.json   # filtered + tagged snippets (M4)
├── M1/summary.json
├── M2/summary.json
├── M3/summary.json
└── M4/summary.json
```

## Module Layout

```
src/generate/
├── run_generate.py          # entry point
├── intermediate/            # intermediate result management layer
│   ├── hpss_manager.py      #   HPSS result loading and caching
│   ├── ccr_loader.py        #   CCR candidate loading and token cleanup
│   └── sdn_manager.py       #   SDN filtering and tag assignment
├── hpss/                    # Hierarchical Path-Sensitive Summarization
│   └── run_hpss.py
├── capd/
│   ├── ccr/                 # Cross-modal Code Retrieval (requires training)
│   │   └── src/             # training scripts and model code
│   └── sdn/                 # Semantic Denoising Network
└── synthesizer/
    ├── run_synthesis.py
    └── core/generator.py    # prompt builders for M1–M4
```

## CCR Training (required for M3/M4)

CCR training takes approximately 10 hours on 4× A100-80G GPUs.

**Before training**, update model paths in the yaml configs under
`src/generate/capd/ccr/src/scripts/configs/` — replace `/path/to/...` placeholders
with your actual model directories. The same paths should be set in `config.ini` under `[ccr]`.

```bash
cd src/generate/capd/ccr/src

# Step 1: Train CASP (dual-encoder)
bash scripts/train_casp_moco.sh

# Step 2: Train prober (source code generator)
bash scripts/train_prober.sh

# Step 3: Run inference on test set
python big_model_quantized_probing_continue.py \
  --config scripts/configs/probe_continue.yaml

# Step 4: Build CCR candidate index
python update_index.py
```

Required external models (download separately):
- `LongCodeArt` — assembly tokenizer / encoder
- `CodeLlama-13b-hf` — source code prober base model
- `Salesforce/codet5p-110m-embedding` — dual-encoder source branch
