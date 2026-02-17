#!/usr/bin/env python3
"""
Binary Code Summary Generation Pipeline

This module orchestrates the summary generation process through multiple stages:
- HPSS: Hierarchical Path-Sensitive Summarization (CFG semantic extraction)
- CCR: Cross-modal Code Retrieval (source candidate generation)
- SDN: Semantic Denoising Network (candidate filtering)
- Synthesizer: Final summary synthesis

Usage:
    python run_generate.py --input dataset.pkl.gz --output summary.json --mode M4

Modes:
    M1: Baseline (Decompiled Code only)
    M2: + HPSS (CFG Description)
    M3: + HPSS + CCR (Raw Source Candidates)
    M4: Full (HPSS + CCR + SDN Filtering)
"""

import os
import sys
import argparse
import json
import subprocess
from pathlib import Path

# Get directory paths
CURRENT_DIR = Path(__file__).parent.resolve()
HPSS_SCRIPT = CURRENT_DIR / "hpss" / "run_hpss.py"
CCR_SCRIPT = CURRENT_DIR / "capd" / "ccr" / "run_ccr.py"
SDN_SCRIPT = CURRENT_DIR / "capd" / "sdn" / "run_sdn.py"
SYNTH_SCRIPT = CURRENT_DIR / "synthesizer" / "run_synthesis.py"


def get_config():
    """Get API configuration from environment variables."""
    return {
        "api_key": os.environ.get("OPENAI_API_KEY", "YOUR_API_KEY_HERE"),
        "base_url": os.environ.get("OPENAI_BASE_URL", "https://aizex.top/v1"),
        "model_name": os.environ.get("MODEL_NAME", "gpt-5")
    }


def run_hpss(input_file, work_dir):
    """
    Run HPSS (Hierarchical Path-Sensitive Summarization).
    
    Input: dataset.pkl.gz or JSON with CFG data
    Output: hpss_summary.json with cfg_summary field
    """
    print("\n[HPSS] Starting Hierarchical Path-Sensitive Summarization...")
    
    paths_file = work_dir / "hpss_paths.json"
    hpss_file = work_dir / "hpss_summary.json"
    
    # Step 1: Extract Paths
    if not paths_file.exists():
        cmd = [
            sys.executable, str(HPSS_SCRIPT),
            "--step", "1",
            "--input", str(input_file),
            "--output_dir", str(work_dir)
        ]
        print(f"  -> Extracting execution paths from CFG...")
        subprocess.check_call(cmd)
    else:
        print(f"  -> Using cached paths: {paths_file}")
    
    # Step 2: Generate HPSS Summaries
    if not hpss_file.exists():
        cmd = [
            sys.executable, str(HPSS_SCRIPT),
            "--step", "2",
            "--input", str(paths_file),
            "--output_dir", str(work_dir)
        ]
        print(f"  -> Generating CFG semantic descriptions...")
        subprocess.check_call(cmd)
    else:
        print(f"  -> Using cached HPSS summary: {hpss_file}")
    
    print(f"[HPSS] Output: {hpss_file}")
    return str(hpss_file)


def run_ccr(input_file, work_dir):
    """
    Run CCR (Cross-modal Code Retrieval).
    
    Input: JSON with decompiled code and optional cfg_summary
    Output: JSON with probed_sources field (raw source candidates)
    
    NOTE: CCR module is currently a placeholder.
    """
    print("\n[CCR] Starting Cross-modal Code Retrieval...")
    
    ccr_file = work_dir / "ccr_candidates.json"
    
    # Check if CCR script exists
    if not CCR_SCRIPT.exists():
        print(f"  -> WARNING: CCR module not implemented at {CCR_SCRIPT}")
        print(f"  -> Skipping CCR, using input file directly")
        return str(input_file)
    
    cmd = [
        sys.executable, str(CCR_SCRIPT),
        "--input", str(input_file),
        "--output", str(ccr_file)
    ]
    print(f"  -> Generating source code candidates...")
    subprocess.check_call(cmd)
    
    print(f"[CCR] Output: {ccr_file}")
    return str(ccr_file)


def run_sdn(input_file, work_dir):
    """
    Run SDN (Semantic Denoising Network).
    
    Input: JSON with probed_sources field
    Output: JSON with filter_strong, filter_backup, filter_uncertain fields
    """
    print("\n[SDN] Starting Semantic Denoising Network...")
    
    sdn_file = work_dir / "sdn_filtered.json"
    
    cmd = [
        sys.executable, str(SDN_SCRIPT),
        "--input", str(input_file),
        "--output", str(sdn_file)
    ]
    print(f"  -> Filtering source candidates...")
    subprocess.check_call(cmd)
    
    print(f"[SDN] Output: {sdn_file}")
    return str(sdn_file)


def run_synthesis(input_file, output_file, mode):
    """
    Run final summary synthesis.
    
    Input: JSON with all context (cfg_summary, probed_sources or filtered snippets)
    Output: JSON with generated_summary field
    """
    print("\n[Synthesis] Starting Final Summary Generation...")
    
    cmd = [
        sys.executable, str(SYNTH_SCRIPT),
        "--input", str(input_file),
        "--output", str(output_file),
        "--mode", mode
    ]
    print(f"  -> Generating final summaries (Mode: {mode})...")
    subprocess.check_call(cmd)
    
    print(f"[Synthesis] Output: {output_file}")


def run_generate(input_file, output_file, mode, work_dir=None):
    """
    Main generation pipeline.
    
    Mode -> Pipeline:
    - M1: [Input] -> [Synthesizer] -> [Output]
    - M2: [Input] -> [HPSS] -> [Synthesizer] -> [Output]
    - M3: [Input] -> [HPSS] -> [CCR] -> [Synthesizer] -> [Output]
    - M4: [Input] -> [HPSS] -> [CCR] -> [SDN] -> [Synthesizer] -> [Output]
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
    print(f"Work Dir: {work_dir}")
    print(f"Output: {output_file}")
    
    current_input = input_file
    
    # Stage 1: HPSS (M2, M3, M4)
    if mode in ['M2', 'M3', 'M4']:
        current_input = run_hpss(current_input, work_dir)
    
    # Stage 2: CCR (M3, M4)
    if mode in ['M3', 'M4']:
        current_input = run_ccr(current_input, work_dir)
    
    # Stage 3: SDN (M4 only)
    if mode == 'M4':
        current_input = run_sdn(current_input, work_dir)
    
    # Final Stage: Synthesis (All modes)
    run_synthesis(current_input, output_file, mode)
    
    print(f"\n{'='*50}")
    print(f"[Generate] Complete!")
    print(f"{'='*50}")


def main():
    parser = argparse.ArgumentParser(description="Binary Code Summary Generation Pipeline")
    parser.add_argument("--input", required=True, help="Input dataset file (JSON or pkl.gz)")
    parser.add_argument("--output", required=True, help="Output summary file (JSON)")
    parser.add_argument("--mode", choices=['M1', 'M2', 'M3', 'M4'], default='M1',
                        help="Ablation mode: M1(Baseline), M2(+HPSS), M3(+HPSS+CCR), M4(Full)")
    parser.add_argument("--work-dir", help="Working directory for intermediate files")
    
    args = parser.parse_args()
    run_generate(args.input, args.output, args.mode, args.work_dir)


if __name__ == "__main__":
    main()
