import os
import sys
import argparse

# Add src directory to path for config import
src_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from config import get_module_config

# Add current directory (hpss) to sys.path to ensure local 'src' module can be imported
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from src.extract_paths import extract_cfg_paths
from src.hpss_summary import generate_cfg_summaries


def main():
    parser = argparse.ArgumentParser(description="Run HPSS (Hierarchical Path-Sensitive Summarization)")
    parser.add_argument("--step", type=int, choices=[1, 2, 0], default=0, help="Run specific step (1=Extract, 2=HPSS, 0=All)")
    parser.add_argument("--input", type=str, required=True, help="Input file path (original data with CFG)")
    parser.add_argument("--output_dir", type=str, default="output", help="Output directory")
    parser.add_argument("--original-data", type=str, help="Original data file (required for Step 2, contains CFG)")
    
    args = parser.parse_args()
    
    # Use unified module config
    config = get_module_config("hpss")
    os.makedirs(args.output_dir, exist_ok=True)
    
    path_file = os.path.join(args.output_dir, "hpss_paths.json")
    hpss_file = os.path.join(args.output_dir, "hpss_summary.json")

    # Step 1: Extract Paths
    if args.step in [0, 1]:
        extract_cfg_paths(args.input, path_file)
    
    # Step 2: Generate HPSS Summaries (CFG Description)
    if args.step in [0, 2]:
        # For Step 2, need original data file to get CFG
        if args.step == 2:
            if not args.original_data:
                print("Error: --original-data is required for Step 2")
                return
            original_data = args.original_data
            paths_input = args.input
        else:
            # Running all steps: use original input for both
            original_data = args.input
            paths_input = path_file
        
        if not os.path.exists(paths_input):
            print("Error: Paths file missing, cannot run Step 2.")
            return
            
        generate_cfg_summaries(original_data, paths_input, hpss_file, config)


if __name__ == "__main__":
    main()
