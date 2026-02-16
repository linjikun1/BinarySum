#!/usr/bin/env python3
import subprocess
import argparse
import sys
import os
import json
from pathlib import Path

# Define paths relative to this script
ROOT_DIR = Path(__file__).parent.resolve()
SRC_DIR = ROOT_DIR / "src"

PROCESS_SCRIPT = SRC_DIR / "process" / "pipeline.py"
HPSS_SCRIPT = SRC_DIR / "generate" / "hpss" / "run_hpss.py"
CCR_SCRIPT = SRC_DIR / "generate" / "capd" / "ccr" / "run_ccr.py"
SDN_SCRIPT = SRC_DIR / "generate" / "capd" / "sdn" / "run_sdn.py"
SYNTH_SCRIPT = SRC_DIR / "generate" / "synthesizer" / "run_synthesis.py"
EVAL_SCRIPT = SRC_DIR / "evaluate" / "run_evaluation.py"

def run_preprocess(args):
    """
    Run data preprocessing pipeline.
    """
    cmd = [
        sys.executable, str(PROCESS_SCRIPT),
        "--bin-dir", args.bin_dir,
        "--arch-opt", args.arch_opt,
        "--output-dir", args.output_dir
    ]
    if args.src_dir:
        cmd.extend(["--src-dir", args.src_dir])
    if args.ida_path:
        cmd.extend(["--ida-path", args.ida_path])
        
    print(f"Running Preprocessing: {' '.join(cmd)}")
    subprocess.check_call(cmd)

def run_generate(args):
    """
    Run summary generation pipeline based on mode (M1-M4).
    
    Mode Definitions:
    - M1: Baseline (Decompiled Code only)
    - M2: + HPSS (CFG Description)
    - M3: + HPSS + CCR (Raw Source Candidates)
    - M4: Full (+ HPSS + CCR + SDN Filtering)
    """
    mode = args.mode
    print(f"\n{'='*50}")
    print(f"Running Generation Pipeline - Mode: {mode}")
    print(f"{'='*50}")
    
    input_path = Path(args.input)
    work_dir = Path(args.work_dir) if args.work_dir else input_path.parent / "generate_intermediate"
    work_dir.mkdir(parents=True, exist_ok=True)
    
    current_input = args.input
    
    # ========================================
    # Step 1: HPSS (Mode M2, M3, M4)
    # ========================================
    if mode in ['M2', 'M3', 'M4']:
        print(f"\n[Step 1] Running HPSS Pipeline...")
        
        # Step 1.1: Extract Paths
        paths_file = work_dir / "hpss_paths.json"
        cmd_hpss1 = [
            sys.executable, str(HPSS_SCRIPT),
            "--step", "1",
            "--input", str(current_input),
            "--output_dir", str(work_dir)
        ]
        print(f"  -> Extracting paths from CFG...")
        subprocess.check_call(cmd_hpss1)
        
        # Step 1.2: Generate HPSS Summaries
        hpss_file = work_dir / "hpss_summary.json"
        cmd_hpss2 = [
            sys.executable, str(HPSS_SCRIPT),
            "--step", "2",
            "--input", str(paths_file),
            "--output_dir", str(work_dir)
        ]
        print(f"  -> Generating CFG descriptions...")
        subprocess.check_call(cmd_hpss2)
        
        current_input = str(hpss_file)
        print(f"  -> HPSS output: {current_input}")
    
    # ========================================
    # Step 2: CCR (Mode M3, M4)
    # ========================================
    if mode in ['M3', 'M4']:
        print(f"\n[Step 2] Running CCR Pipeline...")
        
        ccr_file = work_dir / "ccr_candidates.json"
        cmd_ccr = [
            sys.executable, str(CCR_SCRIPT),
            "--input", str(current_input),
            "--output", str(ccr_file)
        ]
        print(f"  -> Generating source code candidates...")
        subprocess.check_call(cmd_ccr)
        
        current_input = str(ccr_file)
        print(f"  -> CCR output: {current_input}")
    
    # ========================================
    # Step 3: SDN (Mode M4 only)
    # ========================================
    if mode == 'M4':
        print(f"\n[Step 3] Running SDN Pipeline...")
        
        sdn_file = work_dir / "sdn_filtered.json"
        cmd_sdn = [
            sys.executable, str(SDN_SCRIPT),
            "--input", str(current_input),
            "--output", str(sdn_file)
        ]
        print(f"  -> Filtering source candidates...")
        subprocess.check_call(cmd_sdn)
        
        current_input = str(sdn_file)
        print(f"  -> SDN output: {current_input}")
    
    # ========================================
    # Final Step: Synthesis (All Modes)
    # ========================================
    print(f"\n[Final Step] Running Synthesis...")
    
    cmd_synth = [
        sys.executable, str(SYNTH_SCRIPT),
        "--input", str(current_input),
        "--output", args.output,
        "--mode", mode
    ]
    
    print(f"  -> Generating final summaries (Mode: {mode})...")
    subprocess.check_call(cmd_synth)
    
    print(f"\n{'='*50}")
    print(f"Generation Complete! Output: {args.output}")
    print(f"{'='*50}")

def run_eval(args):
    """
    Run evaluation metrics.
    """
    cmd = [
        sys.executable, str(EVAL_SCRIPT),
        "--input_file", args.input_file,
        "--output_file", args.output_file
    ]
    if args.systems:
        cmd.extend(["--systems", args.systems])
    if args.ngram:
        cmd.append("--ngram")
    if args.semantic:
        cmd.append("--semantic")
    if args.llmeval:
        cmd.append("--llmeval")
        
    print(f"Running Evaluation: {' '.join(cmd)}")
    subprocess.check_call(cmd)

def main():
    parser = argparse.ArgumentParser(prog="binarysum", description="BinarySum: Binary Code Summary Generation Framework")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Preprocess Command
    parser_prep = subparsers.add_parser("preprocess", help="Data Preprocessing")
    parser_prep.add_argument("--bin-dir", required=True, help="Binary directory")
    parser_prep.add_argument("--src-dir", help="Source directory")
    parser_prep.add_argument("--arch-opt", required=True, help="Architecture/Optimization (e.g., x64_O3)")
    parser_prep.add_argument("--output-dir", required=True, help="Output directory")
    parser_prep.add_argument("--ida-path", default="idat", help="Path to IDA Pro")
    parser_prep.set_defaults(func=run_preprocess)
    
    # Generate Command
    parser_gen = subparsers.add_parser("generate", help="Summary Generation")
    parser_gen.add_argument("--input", required=True, help="Input dataset file (JSON)")
    parser_gen.add_argument("--output", required=True, help="Output result file (JSON)")
    parser_gen.add_argument("--mode", choices=['M1', 'M2', 'M3', 'M4'], default='M1',
                            help="Ablation mode: M1(Baseline), M2(+HPSS), M3(+HPSS+CCR), M4(Full)")
    parser_gen.add_argument("--work-dir", help="Working directory for intermediate files")
    parser_gen.set_defaults(func=run_generate)
    
    # Evaluate Command
    parser_eval = subparsers.add_parser("evaluate", help="Summary Evaluation")
    parser_eval.add_argument("--input-file", required=True, help="Input file with generated summaries")
    parser_eval.add_argument("--output-file", required=True, help="Output file for metrics")
    parser_eval.add_argument("--systems", help="Comma-separated list of systems to evaluate")
    parser_eval.add_argument("--ngram", action="store_true", help="Run N-Gram metrics")
    parser_eval.add_argument("--semantic", action="store_true", help="Run Semantic metrics")
    parser_eval.add_argument("--llmeval", action="store_true", help="Run LLM evaluation")
    parser_eval.set_defaults(func=run_eval)
    
    args = parser.parse_args()
    
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
