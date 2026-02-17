import os
import sys
import argparse

# Add current directory (hpss) to sys.path to ensure local 'src' module can be imported
# This allows 'from src.step1...' to work regardless of where the script is run from
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from src.step1_extract_paths import run_step1
from src.step2_hpss_summary import run_step2

def get_config():
    return {
        "api_key": os.environ.get("OPENAI_API_KEY", "YOUR_API_KEY_HERE"),
        "base_url": os.environ.get("OPENAI_BASE_URL", "https://aizex.top/v1"),
        "model_name": "gpt-5", # Or gpt-4o
        "temperature_hpss": 0.5
    }

def main():
    parser = argparse.ArgumentParser(description="Run HPSS (Hierarchical Path-Sensitive Summarization)")
    parser.add_argument("--step", type=int, choices=[1, 2, 0], default=0, help="Run specific step (1=Extract, 2=HPSS, 0=All)")
    parser.add_argument("--input", type=str, required=True, help="Input file path (raw CFG data)")
    parser.add_argument("--output_dir", type=str, default="output", help="Output directory")
    
    args = parser.parse_args()
    
    config = get_config()
    os.makedirs(args.output_dir, exist_ok=True)
    
    path_file = os.path.join(args.output_dir, "hpss_paths.json")
    hpss_file = os.path.join(args.output_dir, "hpss_summary.json")

    # Step 1: Extract Paths
    if args.step in [0, 1]:
        run_step1(args.input, path_file)
    
    # Step 2: Generate HPSS Summaries (CFG Description)
    if args.step in [0, 2]:
        input_for_step2 = path_file if args.step == 0 else args.input
        if args.step == 0 and not os.path.exists(path_file):
            print("Error: Step 1 output missing, cannot run Step 2.")
            return
            
        cfg = config.copy()
        cfg['temperature'] = config['temperature_hpss']
        run_step2(input_for_step2, hpss_file, cfg)

if __name__ == "__main__":
    main()
