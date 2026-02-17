import json
import argparse
import sys
import os
import numpy as np
from tqdm import tqdm

# Add the project root to path to ensure imports work
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.append(project_root)

# Import calculators
from evaluate.n_gram_metrics.metric_calculator import NGramMetricsCalculator
from evaluate.semantic_metrics.code_bert_score import CodeBERTScoreCalculator
from evaluate.semantic_metrics.side import SideCalculator
from evaluate.llm_eval.run_llm_eval import LLMEvalRunner

# ==========================================
#  CONFIGURATION: SYSTEMS TO EVALUATE
# ==========================================
# Default list of system keys in the JSON to evaluate
# For BinarySum, the generated summary is stored under 'generated_summary'
DEFAULT_SYSTEMS = ['generated_summary']
DEFAULT_REFERENCE_KEY = 'comment'          # Reference summary (ground truth)
DEFAULT_CODE_KEY = 'strip_decompiled_code' # Binary code for context
# ==========================================

def load_data(file_path):
    data = []
    with open(file_path, 'r', encoding='utf-8') as f:
        if file_path.endswith('.jsonl'):
            for line in f:
                if line.strip():
                    data.append(json.loads(line))
        else:
            data = json.load(f)
    return data

def run_evaluation(args):
    # Determine which systems to evaluate
    if args.systems:
        systems = [s.strip() for s in args.systems.split(',')]
    else:
        systems = DEFAULT_SYSTEMS
    
    print(f"Systems to evaluate: {systems}")

    # Load data
    print(f"Loading data from {args.input_file}...")
    data = load_data(args.input_file)
    print(f"Loaded {len(data)} samples.")

    # Prepare common data
    refs = [item.get(args.reference_key, "") for item in data]
    codes = [item.get(args.code_key, "") for item in data]

    # Initialize results structure
    # sample_metrics is a list of dicts, one for each data sample
    # sample_metrics[i] = { "system_A": {metrics...}, "system_B": {metrics...} }
    sample_metrics = [{} for _ in range(len(data))]
    
    # Initialize metric calculators (lazy loading)
    ngram_calc = NGramMetricsCalculator() if args.ngram else None
    
    cbs_calc = None
    side_calc = None
    if args.semantic:
        cbs_calc = CodeBERTScoreCalculator()
        side_calc = SideCalculator()
        
    llm_runner = None
    if args.llmeval:
        print("Initializing LLM Evaluator...")
        llm_runner = LLMEvalRunner()

    # Loop through each system
    for sys_name in systems:
        print(f"\n{'='*40}")
        print(f"Evaluating System: {sys_name}")
        print(f"{'='*40}")

        # Extract summaries for this system
        gens = [item.get(sys_name, "") for item in data]
        
        # Check if system exists in data (if all summaries are empty, maybe key is wrong)
        # But some could be empty validly, so we check if key exists in at least one item
        if not any(sys_name in item for item in data):
            print(f"Warning: Key '{sys_name}' not found in any data item. Skipping.")
            continue
            
        # Initialize storage for this system in all samples
        for i in range(len(data)):
            if sys_name not in sample_metrics[i]:
                sample_metrics[i][sys_name] = {}

        # 1. N-Gram Metrics
        if args.ngram:
            print(f"[{sys_name}] Running N-Gram Metrics...")
            # compute returns (avg_scores, individual_scores_dict)
            avg_scores, ind_scores = ngram_calc.compute(refs, gens)
            
            # Store individual scores
            for metric_name, scores_list in ind_scores.items():
                for i, score in enumerate(scores_list):
                    sample_metrics[i][sys_name][metric_name] = score
            
            print(f"[{sys_name}] N-Gram Averages:", json.dumps(avg_scores, indent=2))

        # 2. Semantic Metrics
        if args.semantic:
            print(f"[{sys_name}] Running Semantic Metrics...")
            
            # CodeBERTScore
            print(f"[{sys_name}] Calculating CodeBERTScore...")
            cbs_scores = cbs_calc.compute(gens, refs)
            for i, score in enumerate(cbs_scores):
                sample_metrics[i][sys_name]["CodeBERTScore"] = score
            print(f"[{sys_name}] Avg CodeBERTScore: {np.mean(cbs_scores):.4f}")

            # SIDE
            print(f"[{sys_name}] Calculating SIDE...")
            side_scores = side_calc.compute(gens, codes)
            for i, score in enumerate(side_scores):
                sample_metrics[i][sys_name]["SIDE"] = score
            print(f"[{sys_name}] Avg SIDE: {np.mean(side_scores):.4f}")

        # 3. LLM Eval
        if args.llmeval:
            print(f"[{sys_name}] Running LLM Evaluation...")
            # We process LLM eval sequentially
            # We can skip if gen is empty
            for i in tqdm(range(len(data)), desc=f"[{sys_name}] LLM Eval"):
                gen_text = gens[i]
                code_text = codes[i]
                
                if not code_text or not gen_text:
                    continue
                    
                try:
                    res = llm_runner.evaluate_single(gen_text, code_text)
                    sample_metrics[i][sys_name].update(res)
                except Exception as e:
                    print(f"Error evaluating sample {i}: {e}")

    # Save results
    print(f"\nSaving detailed results to {args.output_file}...")
    with open(args.output_file, 'w', encoding='utf-8') as f:
        for i, item in enumerate(data):
            # Create output item
            output_item = item.copy()
            
            # Ensure "metrics" key exists
            if "metrics" not in output_item:
                output_item["metrics"] = {}
            
            # Merge our calculated metrics
            # Structure: metrics -> { system_name -> { metric -> score } }
            # We only update keys for systems we evaluated to avoid overwriting existing metrics for other systems
            for sys_name, metrics_dict in sample_metrics[i].items():
                if metrics_dict: # Only add if we calculated something
                    output_item["metrics"][sys_name] = metrics_dict
            
            f.write(json.dumps(output_item) + "\n")

    print("Done.")

def main():
    parser = argparse.ArgumentParser(description="Run evaluation metrics for multiple systems.")
    parser.add_argument("--input_file", type=str, required=True, help="Input JSON/JSONL file.")
    parser.add_argument("--output_file", type=str, required=True, help="Output JSONL file.")
    parser.add_argument("--reference_key", type=str, default=DEFAULT_REFERENCE_KEY, help="Key for reference summary.")
    parser.add_argument("--code_key", type=str, default=DEFAULT_CODE_KEY, help="Key for source/binary code.")
    
    # Systems can also be passed via command line, comma-separated
    parser.add_argument("--systems", type=str, default=None, help="Comma-separated list of system keys (overrides default).")
    
    # Selection flags
    parser.add_argument("--ngram", action="store_true", help="Run N-Gram metrics (BLEU, METEOR, ROUGE).")
    parser.add_argument("--semantic", action="store_true", help="Run Semantic metrics (CodeBERTScore, SIDE).")
    parser.add_argument("--llmeval", action="store_true", help="Run LLM-based evaluation.")
    
    args = parser.parse_args()
    run_evaluation(args)

if __name__ == "__main__":
    main()
