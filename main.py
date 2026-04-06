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
PROCESS_SCRIPT  = SRC_DIR / "process" / "run_process.py"
AUGREF_SCRIPT   = SRC_DIR / "process" / "gen_augref.py"
GENERATE_SCRIPT = SRC_DIR / "generate" / "run_generate.py"
EVAL_SCRIPT     = SRC_DIR / "evaluate" / "run_evaluation.py"

# Default config profile
DEFAULT_PROFILE = "gpt"


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


def run_augref(args):
    """
    Generate augmented reference summaries for all processed architectures.

    Steps:
      1. collect  – aggregate dataset.pkl.gz from all arch dirs, dedup by key
      2. generate – call LLM for each source_code, write final_ref.pkl.gz
      3. apply    – write "reference" field back into every dataset.pkl.gz
                    and baseline.pkl.gz under data/processed/

    Intermediate files land in --work-dir (default: data/).
    """
    ensure_dirs()

    processed_dir = args.processed_dir or str(PROCESSED_DIR)
    work_dir      = args.work_dir      or str(DATA_DIR)
    step          = args.step
    profile       = getattr(args, 'profile', DEFAULT_PROFILE)

    cmd = [
        sys.executable, str(AUGREF_SCRIPT),
        "--processed-dir", processed_dir,
        "--work-dir",      work_dir,
        "--step",          step,
        "--profile",       profile,
    ]

    print(f"\n{'='*50}")
    print(f"[AugRef] Step: {step}")
    print(f"Config Profile: {profile}")
    print(f"{'='*50}")
    print(f"Processed Dir : {processed_dir}")
    print(f"Work Dir      : {work_dir}")
    print(f"{'='*50}\n")

    subprocess.check_call(cmd)

    print(f"\n{'='*50}")
    print(f"AugRef Complete! 'reference' field written to dataset.pkl.gz / baseline.pkl.gz")
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
    profile = getattr(args, 'profile', DEFAULT_PROFILE)
    
    # Set config profile for subprocess calls
    os.environ["BINARYSUM_CONFIG_PROFILE"] = profile
    
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
    print(f"Config Profile: {profile}")
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
        "--work-dir", str(work_dir),
        "--profile", profile
    ]
    
    subprocess.check_call(cmd)
    
    print(f"\n{'='*50}")
    print(f"Generation Complete!")
    print(f"Output: {output_file}")
    print(f"{'='*50}")


def run_eval(args):
    """
    Run evaluation metrics.
    
    Supports one or multiple modes:
      --mode M1          -> evaluates M1 only
      --mode M1 M2       -> merges M1+M2 into a tempfile and evaluates both in a single run
    
    Input:  data/generated/<arch>/<mode>/summary.json  (one per mode)
    Output: data/results/<arch>/<modes>_metrics.json
    """
    import json as _json
    import tempfile
    ensure_dirs()

    arch = args.arch
    modes = args.mode  # list of one or more modes
    profile = getattr(args, 'profile', DEFAULT_PROFILE)

    # Set config profile for subprocess calls (used by llm_eval)
    os.environ["BINARYSUM_CONFIG_PROFILE"] = profile

    # ---- Build merged input file ----
    _tmpfile = None  # keep reference to prevent GC-triggered deletion

    if args.input_file:
        # User supplied a ready-made file; use as-is (single mode assumed)
        input_file = args.input_file
        modes_label = "_".join(modes)
    else:
        if len(modes) == 1:
            # Single mode: use summary.json directly, no merging needed
            mode = modes[0]
            input_file = str(GENERATED_DIR / arch / mode / "summary.json")
            modes_label = mode
        else:
            # Multiple modes: merge into a temporary file (no permanent artefact)
            # Each item gets a key "generated_summary_<MODE>" for its summary.
            # source_code / reference come from the first mode's file.
            modes_label = "_".join(modes)

            base_data = _json.load(open(GENERATED_DIR / arch / modes[0] / "summary.json"))
            # Start with base items (source_code, reference, etc.)
            merged = [item.copy() for item in base_data]
            # Add each mode's generated_summary under its own key
            for mode in modes:
                mode_data = _json.load(open(GENERATED_DIR / arch / mode / "summary.json"))
                for i, item in enumerate(mode_data):
                    merged[i][f"generated_summary_{mode}"] = item.get("generated_summary", "")
            # Remove the original generic key to avoid confusion
            for item in merged:
                item.pop("generated_summary", None)

            # Write to a named temp file (delete=False so subprocess can read it;
            # we delete it manually after subprocess finishes)
            _tmpfile = tempfile.NamedTemporaryFile(
                mode='w', suffix='.json', delete=False, encoding='utf-8'
            )
            _json.dump(merged, _tmpfile, indent=2, ensure_ascii=False)
            _tmpfile.flush()
            _tmpfile.close()
            input_file = _tmpfile.name
            print(f"[Evaluate] Merged {modes} into temp file (will be removed after evaluation)")

    # ---- Determine systems to pass ----
    if args.systems:
        systems_arg = args.systems
    elif len(modes) > 1:
        systems_arg = ",".join(f"generated_summary_{m}" for m in modes)
    else:
        systems_arg = None  # run_evaluation.py uses DEFAULT_SYSTEMS ('generated_summary')

    # ---- Determine output file ----
    if args.output_file:
        output_file = args.output_file
    else:
        output_file = str(RESULTS_DIR / arch / f"{modes_label}_metrics.json")

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*50}")
    print(f"[Evaluate] Mode(s): {modes} | Architecture: {arch}")
    print(f"Config Profile: {profile}")
    print(f"{'='*50}")
    print(f"Input:  {input_file}")
    print(f"Output: {output_file}")
    if systems_arg:
        print(f"Systems: {systems_arg}")
    print(f"{'='*50}\n")

    cmd = [
        sys.executable, str(EVAL_SCRIPT),
        "--input_file", input_file,
        "--output_file", output_file,
    ]
    if systems_arg:
        cmd.extend(["--systems", systems_arg])
    if args.texsim:
        cmd.append("--texsim")
    if args.semsim:
        cmd.append("--semsim")
    if args.llmjudge:
        cmd.append("--llmjudge")
        cmd.extend(["--profile", profile])
        if getattr(args, 'logprobs', False):
            cmd.append("--logprobs")

    subprocess.check_call(cmd)

    # Clean up temp file (only exists for multi-mode merges)
    if _tmpfile is not None:
        try:
            os.unlink(_tmpfile.name)
        except OSError:
            pass

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
    # AugRef Command
    # ========================================
    parser_augref = subparsers.add_parser(
        "augref",
        help="Generate augmented reference summaries via LLM and write back to processed datasets"
    )
    parser_augref.add_argument(
        "--processed-dir",
        default=None,
        help="Path to data/processed/ (default: data/processed)"
    )
    parser_augref.add_argument(
        "--work-dir",
        default=None,
        help="Directory for intermediate files (default: data/)"
    )
    parser_augref.add_argument(
        "--step",
        choices=["all", "collect", "generate", "apply"],
        default="all",
        help="Which step to run: collect | generate | apply | all (default: all)"
    )
    parser_augref.add_argument(
        "--profile",
        default=DEFAULT_PROFILE,
        help="OpenAI config profile (default: gpt)"
    )
    parser_augref.set_defaults(func=run_augref)

    # ========================================
    # Generate Command
    # ========================================
    parser_gen = subparsers.add_parser("generate", help="Summary Generation")
    parser_gen.add_argument("--arch", required=True, help="Architecture/Optimization (e.g., x64_O3)")
    parser_gen.add_argument("--mode", choices=['M1', 'M2', 'M3', 'M4'], default='M1',
                            help="Ablation mode: M1(Baseline), M2(+HPSS), M3(+HPSS+CCR), M4(Full)")
    parser_gen.add_argument("--input", help="Input dataset file (default: data/processed/<arch>/dataset.pkl.gz)")
    parser_gen.add_argument("--output", help="Output result file (default: data/generated/<arch>/<mode>/summary.json)")
    parser_gen.add_argument("--profile", default=DEFAULT_PROFILE, help="OpenAI config profile")
    parser_gen.set_defaults(func=run_generate)
    
    # ========================================
    # Evaluate Command
    # ========================================
    parser_eval = subparsers.add_parser("evaluate", help="Summary Evaluation")
    parser_eval.add_argument("--arch", required=True, help="Architecture/Optimization (e.g., x64_O3)")
    parser_eval.add_argument("--mode", choices=['M1', 'M2', 'M3', 'M4'], default=['M1'],
                            nargs='+', help="Ablation mode(s) to evaluate (e.g. M1 or M1 M2)")
    parser_eval.add_argument("--input-file", help="Input file (default: data/generated/<arch>/<mode>/summary.json)")
    parser_eval.add_argument("--output-file", help="Output file (default: data/results/<arch>/<mode>_metrics.json)")
    parser_eval.add_argument("--systems", help="Comma-separated list of systems to evaluate")
    parser_eval.add_argument("--texsim", action="store_true", help="Run Textual Similarity metrics (BLEU, METEOR, ROUGE)")
    parser_eval.add_argument("--semsim", action="store_true", help="Run Semantic Similarity metrics (CodeBERTScore, SIDE)")
    parser_eval.add_argument("--llmjudge", action="store_true", help="Run LLM-as-a-Judge evaluation")
    parser_eval.add_argument("--logprobs", action="store_true", help="Use token logprobs for probability-weighted LLMJudge scoring.")
    parser_eval.add_argument("--profile", default=DEFAULT_PROFILE, help="OpenAI config profile")
    parser_eval.set_defaults(func=run_eval)
    
    args = parser.parse_args()
    
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
