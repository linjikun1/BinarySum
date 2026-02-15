import os
import sys
import argparse

# Add current directory (sdn) to sys.path to ensure local 'src' module can be imported
# This allows 'from src.pipeline...' to work regardless of where the script is run from
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from src.pipeline.run_filtering import run_filtering_pipeline

def get_config():
    return {
        "api_key": os.environ.get("OPENAI_API_KEY", "YOUR_API_KEY_HERE"),
        "base_url": os.environ.get("OPENAI_BASE_URL", "https://aizex.top/v1"),
        "model_name": "gpt-5" # Or gpt-4o
    }

def main():
    parser = argparse.ArgumentParser(description="Run SDN (Semantic Denoising Network) Filter")
    parser.add_argument("--input", type=str, required=True, help="Input JSON file with probed candidates")
    parser.add_argument("--output", type=str, required=True, help="Output JSON file path (filtered results)")
    
    args = parser.parse_args()
    
    config = get_config()
    
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # This runs the filtering logic only, tagging candidates as Strong/Backup/Junk
    run_filtering_pipeline(args.input, args.output, config)

if __name__ == "__main__":
    main()
