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
    Extract snippets based on mode (M1-M4).
    
    M1: No snippets (Baseline)
    M2: No snippets (only CFG)
    M3: Raw probed sources (CCR output, no filtering)
    M4: Filtered snippets (SDN output: strong/backup/uncertain)
    """
    snippets = []
    
    if mode in ['M1', 'M2']:
        return []
        
    elif mode == 'M3':
        # Use raw probed sources from CCR (Top 5)
        raw = item.get('probed_sources', [])
        cleaned = []
        for s in raw:
            if '<asm_token>' in s:
                cleaned.append(s.split('<asm_token>\n')[-1])
            else:
                cleaned.append(s)
        # Tag them as UNCERTAIN (since no SDN filtering)
        for s in cleaned[:5]:
            snippets.append(f"// [UNCERTAIN SOURCE]\n{s}")
            
    elif mode == 'M4':
        # Use filtered results from SDN
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

def run_synthesis(input_file, output_file, mode):
    """
    Run final summary synthesis based on mode.
    
    Mode -> Context Mapping:
    - M1: Decompiled code only
    - M2: Decompiled code + CFG description
    - M3: Decompiled code + CFG description + Raw snippets
    - M4: Decompiled code + CFG description + Filtered snippets
    """
    print(f"Loading data from {input_file}...")
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Input file {input_file} not found.")
        return

    config = get_config()
    summarizer = OpenAIFinalSummarizer(config['api_key'], config['model_name'], config['base_url'])

    # Determine if CFG should be used (M2, M3, M4)
    use_cfg = mode in ['M2', 'M3', 'M4']
    
    print(f"\nRunning Synthesis - Mode: {mode}")
    print(f"  - Use CFG: {use_cfg}")
    print(f"  - Use Snippets: {mode in ['M3', 'M4']}")
    print(f"  - Snippet Filter: {'SDN' if mode == 'M4' else 'None'}")
    
    for item in tqdm(data, total=len(data), desc="Generating Summaries"):
        # 1. Get Decompiled Code
        decom_code = item.get('strip_decompiled_code') or item.get('codeinfo', {}).get('decompiled_code', "")
        
        if not decom_code:
            item['generated_summary'] = ""
            continue

        # 2. Get CFG Summary (if mode requires)
        cfg_desc = item.get('cfg_summary', "") if use_cfg else None

        # 3. Get Snippets (if mode requires)
        snippets = extract_snippets(item, mode)

        # 4. Generate
        summary = summarizer.generate_summary(decom_code, cfg_desc, snippets)
        
        # Save result with mode tag
        item['generation_mode'] = mode
        item['generated_summary'] = summary

    print(f"\nSaving results to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print("Done.")

def main():
    parser = argparse.ArgumentParser(description="Run Final Summary Synthesis")
    parser.add_argument("--input", type=str, required=True, help="Input JSON file")
    parser.add_argument("--output", type=str, required=True, help="Output JSON file")
    parser.add_argument("--mode", choices=['M1', 'M2', 'M3', 'M4'], default='M1',
                        help="Ablation mode: M1(Baseline), M2(+HPSS), M3(+HPSS+CCR), M4(Full)")
    
    args = parser.parse_args()
    
    run_synthesis(args.input, args.output, args.mode)

if __name__ == "__main__":
    main()
