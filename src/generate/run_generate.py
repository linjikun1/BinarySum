#!/usr/bin/env python3
"""
Binary Code Summary Generation Pipeline (Refactored)

使用分层架构管理中间产物：
- Intermediate Layer: cfg_manager, ccr_loader, sdn_manager
- Innovation Layer: HPSS (M2), CAPD-CCR/SDN (M3/M4)
- Synthesis Layer: Final summary generation

Usage:
    python run_generate.py --input dataset.pkl.gz --output summary.json --mode M4

Modes:
    M1: Baseline (Decompiled Code only)
    M2: + HPSS (CFG Description) - Innovation Point 1
    M3: + HPSS + CCR (Raw Source Candidates) - Innovation Point 2 (Stage 1)
    M4: Full (HPSS + CCR + SDN) - Innovation Point 2 (Stage 2)

Directory Structure:
    data/generated/<arch>/
    ├── shared/
    │   ├── test_filtered.json      # Test data (all modes)
    │   ├── hpss/hpss_summary.json  # CFG summaries (M2/M3/M4)
    │   ├── ccr/ccr_candidates.json # Source candidates (M3/M4, manual training)
    │   └── sdn/sdn_filtered.json   # Filtered candidates (M4)
    ├── M1/summary.json
    ├── M2/summary.json
    ├── M3/summary.json
    └── M4/summary.json

Data Flow:
    M1: test_filtered → Synthesizer → summary.json
    M2: test_filtered → [HPSS] → cfg_summary → Synthesizer → summary.json
    M3: test_filtered → [HPSS] → cfg_summary ─┐
                                             ├→ Synthesizer → summary.json
              ccr_candidates → [CCRLoader] ──┘
    M4: test_filtered → [HPSS] → cfg_summary ───────────────────────┐
                                                                    ├→ Synthesizer → summary.json
              ccr_candidates → [CCRLoader] → [SDN] → filtered ──────┘
"""

import os
import sys
import argparse
import json
import pickle
import gzip
from pathlib import Path

# Add src directory to path for config import
src_dir = Path(__file__).parent.parent.resolve()
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Add generate directory to path for intermediate imports
generate_dir = Path(__file__).parent.resolve()
if str(generate_dir) not in sys.path:
    sys.path.insert(0, str(generate_dir))

from config import get_openai_config, get_generation_config
from intermediate import HPSSManager, CCRLoader, SDNManager

# Get directory paths
CURRENT_DIR = Path(__file__).parent.resolve()
SYNTH_SCRIPT = CURRENT_DIR / "synthesizer" / "run_synthesis.py"

# ========================================
# Data Split Configuration
# ========================================
TRAIN_RATIO = 0.8   # 80% for CCR training
VALID_RATIO = 0.1   # 10% for CCR validation
TEST_RATIO = 0.1    # 10% for final test (all modes)

# Test filter: code length in words
MIN_CODE_WORDS = 200
MAX_CODE_WORDS = 250
MAX_TEST_ITEMS = 200  # Maximum test items to use


def load_data(input_file):
    """Load data from pkl.gz or JSON file."""
    print(f"Loading data from {input_file}...")
    try:
        with gzip.open(input_file, 'rb') as f:
            data = pickle.load(f)
    except (gzip.BadGzipFile, pickle.UnpicklingError, OSError):
        # Fallback to JSON if not a gzipped pickle file
        with open(input_file, 'r') as f:
            data = json.load(f)
    print(f"Loaded {len(data)} samples.")
    return data


def filter_test_data(data):
    """Filter test data by code length (200-250 words) and take first 200 items."""
    filtered = []
    for item in data:
        code = item.get('strip_decompiled_code', '')
        word_count = len(code.strip().split())
        if MIN_CODE_WORDS < word_count < MAX_CODE_WORDS:
            filtered.append(item)
    # Take first MAX_TEST_ITEMS
    filtered = filtered[:MAX_TEST_ITEMS]
    print(f"Filtered test data: {len(filtered)} items (code length {MIN_CODE_WORDS}-{MAX_CODE_WORDS} words)")
    return filtered


def split_dataset(data, splits_dir, force_split=False):
    """
    Split dataset into train/valid/test.
    
    - train/valid: saved as pkl.gz (for CCR training)
    - test_filtered: saved as JSON (for all modes evaluation)
    
    Returns:
        dict with keys: train, valid, test_filtered, train_file, valid_file, test_filtered_file
    """
    n = len(data)
    train_end = int(n * TRAIN_RATIO)
    valid_end = int(n * (TRAIN_RATIO + VALID_RATIO))
    
    # File paths
    train_file = splits_dir / "train.pkl.gz"
    valid_file = splits_dir / "valid.pkl.gz"
    test_filtered_file = splits_dir / "test_filtered.json"
    
    if not force_split and train_file.exists() and test_filtered_file.exists():
        print("Loading existing data splits...")
        with gzip.open(train_file, 'rb') as f:
            train = pickle.load(f)
        with gzip.open(valid_file, 'rb') as f:
            valid = pickle.load(f)
        with open(test_filtered_file, 'r') as f:
            test_filtered = json.load(f)
        return {
            'train': train,
            'valid': valid,
            'test_filtered': test_filtered,
            'train_file': str(train_file),
            'valid_file': str(valid_file),
            'test_filtered_file': str(test_filtered_file)
        }
    
    print(f"Splitting dataset: train={TRAIN_RATIO*100:.0f}%, valid={VALID_RATIO*100:.0f}%, test={TEST_RATIO*100:.0f}%")
    
    # Split data
    train = data[:train_end]
    valid = data[train_end:valid_end]
    test = data[valid_end:]
    test_filtered = filter_test_data(test)
    
    # Save splits
    splits_dir.mkdir(parents=True, exist_ok=True)
    
    # Save train/valid as pkl.gz
    with gzip.open(train_file, 'wb', compresslevel=5) as f:
        pickle.dump(train, f)
    with gzip.open(valid_file, 'wb', compresslevel=5) as f:
        pickle.dump(valid, f)
    
    # Save test_filtered as JSON
    with open(test_filtered_file, 'w') as f:
        json.dump(test_filtered, f)
    
    print(f"Saved splits to {splits_dir}")
    print(f"  - train.pkl.gz: {len(train)} items")
    print(f"  - valid.pkl.gz: {len(valid)} items")
    print(f"  - test_filtered.json: {len(test_filtered)} items")
    
    return {
        'train': train,
        'valid': valid,
        'test_filtered': test_filtered,
        'train_file': str(train_file),
        'valid_file': str(valid_file),
        'test_filtered_file': str(test_filtered_file)
    }


def run_synthesis_with_context(test_data, context, output_file, mode):
    """
    Run final summary synthesis with prepared context.
    
    Args:
        test_data: List of test samples with reference fields (reference, source_code)
        context: Dict containing intermediate results
            - cfg_summary: List[Dict] (M2/M3/M4)
            - candidates: List[Dict] (M3, with probed_sources)
            - filtered: List[Dict] (M4, with filter_strong/backup/uncertain)
        output_file: Output JSON path
        mode: M1/M2/M3/M4
    """
    import subprocess
    
    print("\n[Synthesis] Starting Final Summary Generation...")
    
    # Prepare input data with all context
    synthesis_input = []
    for i, item in enumerate(test_data):
        entry = {
            'strip_decompiled_code': item.get('strip_decompiled_code', ''),
            'reference': item.get('reference', ''),
            'source_code': item.get('source_code', '')
        }
        
        # Add CFG summary (M2/M3/M4)
        if 'cfg_summary' in context and i < len(context['cfg_summary']):
            cfg_item = context['cfg_summary'][i]
            entry['cfg_summary'] = cfg_item.get('cfg_summary', '')
        
        # Add candidates (M3)
        if 'candidates' in context and i < len(context['candidates']):
            cand_item = context['candidates'][i]
            entry['probed_sources'] = cand_item.get('probed_sources', [])
        
        # Add filtered candidates (M4)
        if 'filtered' in context and i < len(context['filtered']):
            filt_item = context['filtered'][i]
            entry['filter_strong'] = filt_item.get('filter_strong', [])
            entry['filter_backup'] = filt_item.get('filter_backup', [])
            entry['filter_uncertain'] = filt_item.get('filter_uncertain', [])
        
        synthesis_input.append(entry)
    
    # Save temporary input file for synthesizer
    work_dir = Path(output_file).parent
    work_dir.mkdir(parents=True, exist_ok=True)
    temp_input = work_dir / f"synthesis_input_{mode}.json"
    with open(temp_input, 'w', encoding='utf-8') as f:
        json.dump(synthesis_input, f, indent=2, ensure_ascii=False)
    
    # Call synthesizer
    cmd = [
        sys.executable, str(SYNTH_SCRIPT),
        "--input", str(temp_input),
        "--output", str(output_file),
        "--mode", mode
    ]
    
    print(f"  -> Generating final summaries (Mode: {mode})...")
    subprocess.check_call(cmd)
    
    # Clean up temp file
    temp_input.unlink(missing_ok=True)
    
    print(f"[Synthesis] Output: {output_file}")


def run_generate(input_file, output_file, mode, work_dir=None):
    """
    Main generation pipeline (Refactored with Intermediate Managers).
    
    Architecture:
    - Intermediate Layer: HPSSManager, CCRLoader, SDNManager
    - Innovation Layer: HPSS (M2), CAPD-CCR/SDN (M3/M4)
    - Synthesis Layer: Final summary generation
    
    Data Flow:
    - M1: test_filtered → Synthesizer → summary.json
    - M2: test_filtered → [HPSSManager] → cfg_summary → Synthesizer → summary.json
    - M3: test_filtered → [HPSSManager] → cfg_summary ─┐
                                                      ├→ Synthesizer → summary.json
              [CCRLoader] → ccr_candidates ───────────┘
    - M4: test_filtered → [HPSSManager] → cfg_summary ───────────────────────┐
                                                                            ├→ Synthesizer → summary.json
              [CCRLoader] → ccr_candidates → [SDNManager] → filtered ───────┘
    """
    input_path = Path(input_file)
    if work_dir is None:
        work_dir = input_path.parent / "generate_intermediate"
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*50}")
    print(f"[Generate] Mode: {mode}")
    print(f"{'='*50}")
    print(f"Input: {input_file}")
    print(f"Output: {output_file}")
    
    # ========================================
    # Data Split (shared across all modes)
    # ========================================
    shared_dir = work_dir.parent / "shared"
    shared_dir.mkdir(parents=True, exist_ok=True)
    
    data = load_data(input_file)
    splits = split_dataset(data, shared_dir)
    test_data = splits['test_filtered']
    
    print(f"\n{'='*30}")
    print(f"Using test_filtered: {len(test_data)} items")
    print(f"Shared Dir: {shared_dir}")
    print(f"{'='*30}")
    
    # ========================================
    # Initialize Intermediate Managers
    # ========================================
    hpss_dir = shared_dir / "hpss"
    ccr_dir = shared_dir / "ccr"
    sdn_dir = shared_dir / "sdn"
    
    cfg_manager = HPSSManager(hpss_dir)
    ccr_loader = CCRLoader(ccr_dir)
    sdn_manager = SDNManager(sdn_dir)
    
    # ========================================
    # Pipeline: Build Context for Synthesis
    # ========================================
    context = {}
    
    # Stage 1: HPSS (M2, M3, M4) - Innovation Point 1
    if mode in ['M2', 'M3', 'M4']:
        print("\n[Pipeline] Stage 1: HPSS (CFG Summary)")
        cfg_summary = cfg_manager.get_or_create(test_data)
        context['cfg_summary'] = cfg_summary
    
    # Stage 2: CCR (M3, M4) - Innovation Point 2, Stage 1
    if mode in ['M3', 'M4']:
        print("\n[Pipeline] Stage 2: CCR (Source Candidates)")
        if not ccr_loader.exists():
            print("\n[ERROR] CCR results not found!")
            print("CCR requires manual training. Please run:")
            print("  cd BinarySum/src/generate/capd/ccr")
            print("  bash run.sh <arch>  # e.g., x64_O3")
            print("\nThen retry this command.")
            sys.exit(1)
        candidates = ccr_loader.load()
        context['candidates'] = candidates
    
    # Stage 3: SDN (M4 only) - Innovation Point 2, Stage 2
    if mode == 'M4':
        print("\n[Pipeline] Stage 3: SDN (Candidate Filtering)")
        filtered = sdn_manager.get_or_create(context['candidates'])
        context['filtered'] = filtered
    
    # ========================================
    # Final Stage: Synthesis
    # ========================================
    print("\n[Pipeline] Final Stage: Summary Synthesis")
    run_synthesis_with_context(test_data, context, output_file, mode)
    
    print(f"\n{'='*50}")
    print(f"[Generate] Complete!")
    print(f"Output: {output_file}")
    print(f"{'='*50}")


def main():
    parser = argparse.ArgumentParser(description="Binary Code Summary Generation Pipeline")
    parser.add_argument("--input", required=True, help="Input dataset file (JSON or pkl.gz)")
    parser.add_argument("--output", required=True, help="Output summary file (JSON)")
    parser.add_argument("--mode", choices=['M1', 'M2', 'M3', 'M4'], default='M1',
                        help="Ablation mode: M1(Baseline), M2(+HPSS), M3(+HPSS+CCR), M4(Full)")
    parser.add_argument("--work-dir", help="Working directory for intermediate files")
    parser.add_argument("--profile", default="gpt", help="OpenAI config profile")
    
    args = parser.parse_args()
    
    # Set config profile for subprocess calls
    os.environ["BINARYSUM_CONFIG_PROFILE"] = args.profile
    
    run_generate(args.input, args.output, args.mode, args.work_dir)


if __name__ == "__main__":
    main()
