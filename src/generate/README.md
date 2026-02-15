# Binary Code Summarization Framework

This repository integrates two novel approaches for binary code summarization: **HPSS (CFG Analysis)** and **CAPD (Source Denoising)**.

## Structure

### 1. HPSS (Hierarchical Path-Sensitive Summarization)
Located in `hpss/`.
- Extracts execution paths from CFG.
- Generates semantic descriptions of the control flow (`cfg_summary`).
- **Run**: `python hpss/run_hpss.py`

### 2. CAPD (Context-Aware Program Denoising)
Located in `capd/`.
- **SDN Module (`capd/sdn/`)**: Filters raw source code candidates retrieved by search.
- Classifies snippets into Strong Match, Backup Match, or Uncertain.
- **Run**: `python capd/sdn/run_sdn.py`

### 3. Synthesizer (Final Generation)
Located in `synthesizer/`.
- Combines Decompiled Code + CFG Summary (Optional) + Source Snippets (Optional) to generate the final summary.
- Supports ablation studies via CLI arguments.
- **Run**: `python synthesizer/run_synthesis.py`

## Usage Workflow

1. **Pre-processing**: Ensure your input JSON contains `cfg` (for HPSS) and `probed_sources` (for CAPD).
2. **Step 1: Run HPSS** to add `cfg_summary`.
   ```bash
   python hpss/run_hpss.py --input data.json --output_dir data/ --step 0
   ```
3. **Step 2: Run SDN** to add filtered snippets (`filter_strong`, etc.).
   ```bash
   python capd/sdn/run_sdn.py --input data/hpss_step2_summary.json --output data/full_context.json
   ```
4. **Step 3: Run Synthesis** (Ablation Examples).
   ```bash
   # Full Model (Code + CFG + SDN)
   python synthesizer/run_synthesis.py --input data/full_context.json --output results/final.json --use_cfg --snippet_mode sdn

   # Ablation: No CFG, Raw Snippets
   python synthesizer/run_synthesis.py --input data/full_context.json --output results/ablation1.json --snippet_mode raw

   # Baseline: Decompiled Code Only
   python synthesizer/run_synthesis.py --input data/full_context.json --output results/baseline.json --snippet_mode none
   ```
