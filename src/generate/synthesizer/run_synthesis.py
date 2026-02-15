import json
import os
import sys
import argparse
from tqdm import tqdm

# Add current directory (synthesizer) to sys.path to ensure local 'core' module can be imported
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from core.generator import OpenAIFinalSummarizer

def get_config():
    return {
        "api_key": os.environ.get("OPENAI_API_KEY", "YOUR_API_KEY_HERE"),
        "base_url": os.environ.get("OPENAI_BASE_URL", "https://aizex.top/v1"),
        "model_name": "gpt-5"
    }

def extract_snippets(item, mode):
    """
    Extract snippets based on mode: 'none', 'raw', 'sdn'
    """
    snippets = []
    
    if mode == 'none':
        return []
        
    elif mode == 'raw':
        # Use raw probed sources (Top 5)
        raw = item.get('probed_sources', [])
        # Simple cleaning logic (if needed)
        cleaned = []
        for s in raw:
            if '<asm_token>' in s:
                cleaned.append(s.split('<asm_token>\n')[-1])
            else:
                cleaned.append(s)
        # Tag them as UNCERTAIN
        for s in cleaned[:5]:
            snippets.append(f"// [UNCERTAIN SOURCE]\n{s}")
            
    elif mode == 'sdn':
        # Use filtered results
        strong = item.get('filter_strong', [])
        backup = item.get('filter_backup', [])
        uncertain = item.get('filter_uncertain', [])
        
        for s in strong:
            snippets.append(f"// [HIGH CONFIDENCE SOURCE]\n{s}")
        for s in backup:
            snippets.append(f"// [CONTEXT REFERENCE]\n{s}")
        for s in uncertain:
            snippets.append(f"// [UNCERTAIN SOURCE]\n{s}")
            
    return snippets

def run_synthesis(input_file, output_file, use_cfg, snippet_mode):
    print(f"Loading data from {input_file}...")
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Input file {input_file} not found.")
        return

    config = get_config()
    summarizer = OpenAIFinalSummarizer(config['api_key'], config['model_name'], config['base_url'])

    print(f"Running Synthesis with: CFG={use_cfg}, Snippets={snippet_mode}")
    
    for item in tqdm(data, total=len(data), desc="Generating Summaries"):
        # 1. Get Decompiled Code
        decom_code = item.get('strip_decompiled_code') or item.get('codeinfo', {}).get('decompiled_code', "")
        
        if not decom_code:
            item['final_summary'] = ""
            continue

        # 2. Get CFG Summary (if enabled)
        cfg_desc = item.get('cfg_summary', "") if use_cfg else None

        # 3. Get Snippets (if enabled)
        snippets = extract_snippets(item, snippet_mode)

        # 4. Generate
        summary = summarizer.generate_summary(decom_code, cfg_desc, snippets)
        
        # Save result
        key_suffix = f"_cfg{int(use_cfg)}_{snippet_mode}"
        item[f'summary{key_suffix}'] = summary
        item['generated_summary'] = summary 

    print(f"Saving results to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print("Done.")

def main():
    parser = argparse.ArgumentParser(description="Run Final Summary Synthesis (Ablation Supported)")
    parser.add_argument("--input", type=str, required=True, help="Input JSON file")
    parser.add_argument("--output", type=str, required=True, help="Output JSON file")
    parser.add_argument("--use_cfg", action="store_true", help="Include CFG semantic description")
    parser.add_argument("--snippet_mode", choices=['none', 'raw', 'sdn'], default='none', 
                        help="Snippet context mode: none (Baseline), raw (No Filter), sdn (With Filter)")
    
    args = parser.parse_args()
    
    run_synthesis(args.input, args.output, args.use_cfg, args.snippet_mode)

if __name__ == "__main__":
    main()
