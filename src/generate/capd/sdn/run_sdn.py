import os
import sys
import argparse
import json
from typing import List, Dict

# Add src directory to path for config import
src_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from config import get_module_config

# Add current directory (sdn) to sys.path to ensure local 'src' module can be imported
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from src.pipeline.run_filtering import run_filtering_pipeline


def run_filtering(ccr_candidates: List[Dict], config: dict = None) -> List[Dict]:
    """
    Run SDN filtering on CCR candidates.
    
    Args:
        ccr_candidates: List of CCR output items with 'probed_sources' field
        config: Optional config dict (will load from get_module_config if not provided)
    
    Returns:
        List of filtered items with 'filter_strong', 'filter_backup', 'filter_uncertain' fields
    """
    if config is None:
        config = get_module_config("sdn")
    
    # Save candidates to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(ccr_candidates, f)
        temp_input = f.name
    
    # Create temp output file
    temp_output = temp_input.replace('.json', '_filtered.json')
    
    try:
        # Run filtering pipeline
        run_filtering_pipeline(temp_input, temp_output, config)
        
        # Load results
        with open(temp_output, 'r') as f:
            filtered = json.load(f)
        
        return filtered
    finally:
        # Clean up temp files
        if os.path.exists(temp_input):
            os.unlink(temp_input)
        if os.path.exists(temp_output):
            os.unlink(temp_output)


def main():
    parser = argparse.ArgumentParser(description="Run SDN (Semantic Denoising Network) Filter")
    parser.add_argument("--input", type=str, required=True, help="Input JSON file with probed candidates")
    parser.add_argument("--output", type=str, required=True, help="Output JSON file path (filtered results)")
    
    args = parser.parse_args()
    
    # Use unified module config
    config = get_module_config("sdn")
    
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # This runs the filtering logic only, tagging candidates as Strong/Backup/Junk
    run_filtering_pipeline(args.input, args.output, config)


if __name__ == "__main__":
    main()
