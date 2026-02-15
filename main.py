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
    Run summary generation pipeline (HPSS + Synthesis).
    """
    current_input = args.input
    
    # 1. HPSS Pipeline (if enabled)
    if args.enable_hpss:
        print("HPSS Enabled. Starting HPSS Pipeline...")
        
        # Determine intermediate output directory
        # If input is a file, use its parent directory for temp files
        input_path = Path(args.input)
        work_dir = input_path.parent / "hpss_intermediate"
        work_dir.mkdir(parents=True, exist_ok=True)
        
        # Step 1: Extract Paths
        # Input: args.input (dataset.pkl.gz or .json)
        # Output: paths.json
        paths_file = work_dir / "hpss_step1_paths.json"
        
        cmd_step1 = [
            sys.executable, str(HPSS_SCRIPT),
            "--step", "1",
            "--input", str(current_input),
            "--output_dir", str(work_dir)
        ]
        print(f"Running HPSS Step 1: {' '.join(cmd_step1)}")
        subprocess.check_call(cmd_step1)
        
        # Step 2: Generate HPSS Summaries
        # Input: paths_file
        # Output: hpss_summary.json
        hpss_summary_file = work_dir / "hpss_step2_summary.json"
        
        cmd_step2 = [
            sys.executable, str(HPSS_SCRIPT),
            "--step", "2",
            "--input", str(paths_file), # Step 2 takes the output of step 1 as input (if step=2 logic is used correctly)
            # Wait, run_hpss.py logic:
            # if step in [0, 2]: input_for_step2 = path_file if step == 0 else args.input
            # So if we run step 2 explicitly, we pass path_file as --input.
            "--output_dir", str(work_dir)
        ]
        
        # run_hpss.py uses fixed names for outputs based on output_dir
        # path_file = os.path.join(args.output_dir, "hpss_step1_paths.json")
        # hpss_file = os.path.join(args.output_dir, "hpss_step2_summary.json")
        
        # So we just need to ensure Step 1 writes to where Step 2 expects it, OR we pass inputs correctly.
        # run_hpss.py implementation:
        # if args.step == 2: input_for_step2 = args.input
        # So yes, we pass paths_file as input to step 2.
        
        # BUT run_hpss.py also hardcodes the output filename inside `main`:
        # hpss_file = os.path.join(args.output_dir, "hpss_step2_summary.json")
        
        print(f"Running HPSS Step 2: {' '.join(cmd_step2)}")
        subprocess.check_call(cmd_step2)
        
        # Update current input for synthesis
        current_input = hpss_summary_file
        
    # 2. Synthesis
    print("Starting Synthesis...")
    cmd_synth = [
        sys.executable, str(SYNTH_SCRIPT),
        "--input", str(current_input),
        "--output", args.output,
        "--snippet_mode", args.snippet_mode
    ]
    if args.use_cfg:
        cmd_synth.append("--use_cfg")
        
    print(f"Running Synthesis: {' '.join(cmd_synth)}")
    subprocess.check_call(cmd_synth)

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
    parser_gen.add_argument("--enable-hpss", action="store_true", help="Run HPSS (CFG Description) pipeline first")
    parser_gen.add_argument("--use-cfg", action="store_true", help="Use CFG description in synthesis")
    parser_gen.add_argument("--snippet-mode", choices=['none', 'raw', 'sdn'], default='none', help="Snippet usage mode")
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
