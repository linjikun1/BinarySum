import json
import argparse
import sys
import os
import numpy as np
import configparser

# Add the project root to path to ensure imports work
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.append(project_root)

# Import evaluators (lazy loading)
# Only import what's needed to avoid loading heavy dependencies

# ==========================================
#  CONFIGURATION: SYSTEMS TO EVALUATE
# ==========================================
# Default list of system keys in the JSON to evaluate
# For BinarySum, the generated summary is stored under 'generated_summary'
DEFAULT_SYSTEMS = ['LLM-Zero']
# For evaluating multiple baselines, use:
# DEFAULT_SYSTEMS = ['HexT5', 'BinT5', 'CP-BCS', 'MiSum', 'ProRec']
DEFAULT_REFERENCE_KEY = 'reference'          # Reference summary (ground truth) - LLM-generated from source_code
DEFAULT_CODE_KEY = 'source_code' # Source code for context
# ==========================================

def get_semsim_config():
    """Read semantic similarity model paths from config.ini."""
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(project_root), 'config.ini')
    
    if os.path.exists(config_path):
        config.read(config_path)
        if 'semsim' in config:
            codebert_path = config['semsim'].get('codebert_model_path', '')
            unixcoder_path = config['semsim'].get('unixcoder_model_path', '')
            
            # Convert to absolute path if relative
            if codebert_path and not os.path.isabs(codebert_path):
                codebert_path = os.path.join(os.path.dirname(project_root), codebert_path)
            if unixcoder_path and not os.path.isabs(unixcoder_path):
                unixcoder_path = os.path.join(os.path.dirname(project_root), unixcoder_path)
            
            return {
                'codebert_model_path': codebert_path if codebert_path else None,
                'unixcoder_model_path': unixcoder_path if unixcoder_path else None
            }
    
    return {'codebert_model_path': None, 'unixcoder_model_path': None}

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
    
    # Load data
    data = load_data(args.input_file)
    
    # Validate that reference fields exist in input data
    for i, item in enumerate(data):
        if args.reference_key not in item or not item.get(args.reference_key):
            raise ValueError(
                f"Sample {i}: Missing or empty '{args.reference_key}' field. "
                f"Ensure input file contains reference fields (reference, source_code)."
            )
        if args.code_key not in item or not item.get(args.code_key):
            raise ValueError(
                f"Sample {i}: Missing or empty '{args.code_key}' field. "
                f"Ensure input file contains source code field."
            )

    # Prepare common data
    refs = [item.get(args.reference_key, "") for item in data]
    codes = [item.get(args.code_key, "") for item in data]

    # Initialize results structure
    # sample_metrics is a list of dicts, one for each data sample
    # sample_metrics[i] = { "system_A": {metrics...}, "system_B": {metrics...} }
    sample_metrics = [{} for _ in range(len(data))]
    
    # Initialize metric calculators (lazy loading)
    texsim_eval = None
    if args.texsim:
        from evaluate.texsim import TexSimEvaluator
        texsim_eval = TexSimEvaluator()
    
    semsim_eval = None
    if args.semsim:
        from evaluate.semsim import SemSimEvaluator
        semsim_config = get_semsim_config()
        semsim_eval = SemSimEvaluator(
            codebert_model_path=semsim_config['codebert_model_path'],
            unixcoder_model_path=semsim_config['unixcoder_model_path']
        )
        
    llmjudge_eval = None
    if args.llmjudge:
        from evaluate.llmjudge import LLMJudgeEvaluator
        profile = getattr(args, 'profile', None)
        llmjudge_eval = LLMJudgeEvaluator(profile=profile)

    # Loop through each system
    for sys_name in systems:
        print(f"\n[{sys_name}]")

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

        # 1. Textual Similarity Metrics
        if args.texsim:
            # compute returns (avg_scores, individual_scores_dict)
            avg_scores, ind_scores = texsim_eval.compute(refs, gens)
            
            # Store individual scores (convert numpy types to Python float)
            for metric_name, scores_list in ind_scores.items():
                for i, score in enumerate(scores_list):
                    sample_metrics[i][sys_name][metric_name] = float(score)
            
            # Simplified output
            print(f"  TexSim: BLEU-4={avg_scores['BLEU-4']:.2f}, METEOR={avg_scores['METEOR']:.2f}, ROUGE-L={float(avg_scores['ROUGE-L']):.2f}")

        # 2. Semantic Similarity Metrics
        if args.semsim:
            # CodeBERTScore
            cbs_scores = semsim_eval.compute_code_bert_score(gens, refs)
            for i, score in enumerate(cbs_scores):
                sample_metrics[i][sys_name]["CodeBERTScore"] = float(score)

            # SIDE
            side_scores = semsim_eval.compute_side(gens, codes)
            for i, score in enumerate(side_scores):
                sample_metrics[i][sys_name]["SIDE"] = float(score)
            
            print(f"  SemSim: CodeBERTScore={np.mean(cbs_scores):.4f}, SIDE={np.mean(side_scores):.4f}")

        # 3. LLM-as-a-Judge
        if args.llmjudge:
            # We process LLM eval sequentially
            llm_scores = {'accuracy': [], 'coverage': [], 'effectiveness': []}
            for i in range(len(data)):
            # for i in range(20):
                gen_text = gens[i]
                code_text = codes[i]
                
                if not code_text or not gen_text:
                    continue
                    
                try:
                    res = llmjudge_eval.evaluate_single(gen_text, code_text)
                    sample_metrics[i][sys_name].update(res)
                    print(f"  LLMJudge [{i}]: accuracy={res['accuracy']:.2f}, coverage={res['coverage']:.2f}, effectiveness={res['effectiveness']:.2f}")
                    for k in llm_scores:
                        if k in res:
                            llm_scores[k].append(res[k])
                except Exception as e:
                    print(f"Error evaluating sample {i}: {e}")
            
            # Print average scores
            if any(llm_scores.values()):
                avg_acc = np.mean(llm_scores['accuracy']) if llm_scores['accuracy'] else float('nan')
                avg_cov = np.mean(llm_scores['coverage']) if llm_scores['coverage'] else float('nan')
                avg_eff = np.mean(llm_scores['effectiveness']) if llm_scores['effectiveness'] else float('nan')
                print(f"  LLMJudge Avg: accuracy={avg_acc:.2f}, coverage={avg_cov:.2f}, effectiveness={avg_eff:.2f}")

    # Save results
    with open(args.output_file, 'w', encoding='utf-8') as f:
        result = []
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
            result.append(output_item)
        json.dump(result, f, indent=4)

    print(f"\nResults saved to: {args.output_file}")

def main():
    parser = argparse.ArgumentParser(description="Run evaluation metrics for multiple systems.")
    parser.add_argument("--input_file", type=str, required=True, help="Input JSON/JSONL file with generated_summary, reference, source_code fields.")
    parser.add_argument("--output_file", type=str, required=True, help="Output JSONL file.")
    parser.add_argument("--reference_key", type=str, default=DEFAULT_REFERENCE_KEY, help="Key for reference summary (default: reference).")
    parser.add_argument("--code_key", type=str, default=DEFAULT_CODE_KEY, help="Key for source code (default: source_code).")
    
    # Systems can also be passed via command line, comma-separated
    parser.add_argument("--systems", type=str, default=None, help="Comma-separated list of system keys (overrides default).")
    
    # Selection flags
    parser.add_argument("--texsim", action="store_true", help="Run Textual Similarity metrics (BLEU, METEOR, ROUGE).")
    parser.add_argument("--semsim", action="store_true", help="Run Semantic Similarity metrics (CodeBERTScore, SIDE).")
    parser.add_argument("--llmjudge", action="store_true", help="Run LLM-as-a-Judge evaluation.")
    parser.add_argument("--profile", type=str, default=None, help="OpenAI config profile for LLM eval (default, gpt, etc.).")
    
    args = parser.parse_args()
    run_evaluation(args)

if __name__ == "__main__":
    main()
