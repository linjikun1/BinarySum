#!/usr/bin/env python3
import subprocess
import argparse
import sys
import os
from pathlib import Path

# ========================================
# Directory Structure Configuration
# ========================================
ROOT_DIR = Path(__file__).parent.resolve()
SRC_DIR = ROOT_DIR / "src"
DATA_DIR = ROOT_DIR / "data"

# Data directories
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
GENERATED_DIR = DATA_DIR / "generated"
RESULTS_DIR = DATA_DIR / "results"

# Scripts
PROCESS_SCRIPT = SRC_DIR / "process" / "run_process.py"
GENERATE_SCRIPT = SRC_DIR / "generate" / "run_generate.py"
EVAL_SCRIPT = SRC_DIR / "evaluate" / "run_evaluation.py"


def ensure_dirs():
    """Ensure data directories exist."""
    for d in [RAW_DIR, PROCESSED_DIR, GENERATED_DIR, RESULTS_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def run_process(args):
    """
    Run data processing pipeline.
    
    Input:  data/raw/binary/<arch>/  + data/raw/source/
    Output: data/processed/<arch>/dataset.pkl.gz
    """
    ensure_dirs()
    
    # Determine binary directory
    if args.bin_dir:
        bin_dir = args.bin_dir
    else:
        bin_dir = str(RAW_DIR / "binary")
    
    # Determine source directory
    if args.src_dir:
        src_dir = args.src_dir
    else:
        src_dir = str(RAW_DIR / "source")
    
    # Determine output directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        output_dir = str(PROCESSED_DIR)
    
    cmd = [
        sys.executable, str(PROCESS_SCRIPT),
        "--bin-dir", bin_dir,
        "--src-dir", src_dir,
        "--arch-opt", args.arch,
        "--output-dir", output_dir
    ]
    if args.ida_path:
        cmd.extend(["--ida-path", args.ida_path])
        
    print(f"\n{'='*50}")
    print(f"[Process] Architecture: {args.arch}")
    print(f"{'='*50}")
    print(f"Binary Dir: {bin_dir}")
    print(f"Source Dir: {src_dir}")
    print(f"Output Dir: {output_dir}")
    print(f"{'='*50}\n")
    
    subprocess.check_call(cmd)
    
    print(f"\n{'='*50}")
    print(f"Output: {output_dir}/{args.arch}/dataset.pkl.gz")
    print(f"{'='*50}")

def run_generate(args):
    """
    Run summary generation pipeline based on mode (M1-M4).
    
    Input:  data/processed/<arch>/dataset.pkl.gz
    Output: data/generated/<arch>/<mode>/summary.json
    
    Mode Definitions:
    - M1: Baseline (Decompiled Code only)
    - M2: + HPSS (CFG Description)
    - M3: + HPSS + CCR (Raw Source Candidates)
    - M4: Full (+ HPSS + CCR + SDN Filtering)
    """
    ensure_dirs()
    
    mode = args.mode
    arch = args.arch
    
    # Determine input file
    if args.input:
        input_file = args.input
    else:
        input_file = str(PROCESSED_DIR / arch / "dataset.pkl.gz")
    
    # Work directory for intermediate files
    work_dir = GENERATED_DIR / arch / mode
    work_dir.mkdir(parents=True, exist_ok=True)
    
    # Output file
    if args.output:
        output_file = args.output
    else:
        output_file = str(work_dir / "summary.json")
    
    print(f"\n{'='*50}")
    print(f"[Generate] Mode: {mode} | Architecture: {arch}")
    print(f"{'='*50}")
    print(f"Input: {input_file}")
    print(f"Work Dir: {work_dir}")
    print(f"Output: {output_file}")
    print(f"{'='*50}\n")
    
    # Call run_generate.py
    cmd = [
        sys.executable, str(GENERATE_SCRIPT),
        "--input", input_file,
        "--output", output_file,
        "--mode", mode,
        "--work-dir", str(work_dir)
    ]
    
    subprocess.check_call(cmd)
    
    print(f"\n{'='*50}")
    print(f"Generation Complete!")
    print(f"Output: {output_file}")
    print(f"{'='*50}")

def run_eval(args):
    """
    Run evaluation metrics.
    
    Input:  data/generated/<arch>/<mode>/summary.json
    Output: data/results/<arch>/<mode>_metrics.json
    """
    ensure_dirs()
    
    arch = args.arch
    mode = args.mode
    
    # Determine input file
    if args.input_file:
        input_file = args.input_file
    else:
        input_file = str(GENERATED_DIR / arch / mode / "summary.json")
    
    # Determine output file
    if args.output_file:
        output_file = args.output_file
    else:
        output_file = str(RESULTS_DIR / arch / f"{mode}_metrics.json")
    
    # Ensure output directory exists
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*50}")
    print(f"[Evaluate] Mode: {mode} | Architecture: {arch}")
    print(f"{'='*50}")
    print(f"Input: {input_file}")
    print(f"Output: {output_file}")
    print(f"{'='*50}\n")
    
    cmd = [
        sys.executable, str(EVAL_SCRIPT),
        "--input_file", input_file,
        "--output_file", output_file
    ]
    if args.systems:
        cmd.extend(["--systems", args.systems])
    if args.ngram:
        cmd.append("--ngram")
    if args.semantic:
        cmd.append("--semantic")
    if args.llmeval:
        cmd.append("--llmeval")
        
    subprocess.check_call(cmd)
    
    print(f"\n{'='*50}")
    print(f"Evaluation Complete!")
    print(f"Output: {output_file}")
    print(f"{'='*50}")

def main():
    parser = argparse.ArgumentParser(prog="binarysum", description="BinarySum: Binary Code Summary Generation Framework")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # ========================================
    # Process Command
    # ========================================
    parser_prep = subparsers.add_parser("process", help="Data Processing")
    parser_prep.add_argument("--arch", required=True, help="Architecture/Optimization (e.g., x64_O3, arm_O2, all)")
    parser_prep.add_argument("--bin-dir", help="Binary directory (default: data/raw/binary)")
    parser_prep.add_argument("--src-dir", help="Source directory (default: data/raw/source)")
    parser_prep.add_argument("--output-dir", help="Output directory (default: data/processed)")
    parser_prep.add_argument("--ida-path", default="idat", help="Path to IDA Pro")
    parser_prep.set_defaults(func=run_process)
    
    # ========================================
    # Generate Command
    # ========================================
    parser_gen = subparsers.add_parser("generate", help="Summary Generation")
    parser_gen.add_argument("--arch", required=True, help="Architecture/Optimization (e.g., x64_O3)")
    parser_gen.add_argument("--mode", choices=['M1', 'M2', 'M3', 'M4'], default='M1',
                            help="Ablation mode: M1(Baseline), M2(+HPSS), M3(+HPSS+CCR), M4(Full)")
    parser_gen.add_argument("--input", help="Input dataset file (default: data/processed/<arch>/dataset.pkl.gz)")
    parser_gen.add_argument("--output", help="Output result file (default: data/generated/<arch>/<mode>/summary.json)")
    parser_gen.set_defaults(func=run_generate)
    
    # ========================================
    # Evaluate Command
    # ========================================
    parser_eval = subparsers.add_parser("evaluate", help="Summary Evaluation")
    parser_eval.add_argument("--arch", required=True, help="Architecture/Optimization (e.g., x64_O3)")
    parser_eval.add_argument("--mode", choices=['M1', 'M2', 'M3', 'M4'], default='M1',
                            help="Ablation mode to evaluate")
    parser_eval.add_argument("--input-file", help="Input file (default: data/generated/<arch>/<mode>/summary.json)")
    parser_eval.add_argument("--output-file", help="Output file (default: data/results/<arch>/<mode>_metrics.json)")
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
