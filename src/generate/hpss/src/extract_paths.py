import json
import pickle
import gzip
from tqdm import tqdm
from src.analyzer.cfg_analyzer import BinaryCFGAnalyzer

def extract_cfg_paths(input_path, output_path):
    """
    Extract CFG paths from binary data.
    
    Parses CFG data and extracts execution paths for HPSS generation.
    
    NOTE: Data splitting (train/valid/test) is handled by run_generate.py.
    This function expects pre-filtered data.
    """
    print(f"[extract_cfg_paths] Loading data from {input_path}...")
    try:
        with gzip.open(input_path, 'rb') as f:
            data = pickle.load(f)
    except FileNotFoundError:
        print(f"Error: Input file {input_path} not found.")
        return
    except (gzip.BadGzipFile, pickle.UnpicklingError) as e:
        # Fallback to json if pickle fails (or if file is not gzipped)
        try:
            with open(input_path, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e2:
            print(f"Error loading file {input_path}: {e} / {e2}")
            return

    # Data splitting is now handled by run_generate.py
    # No longer filtering here - expect pre-filtered input
    print(f"[Step 1] Processing {len(data)} items...")

    results = []
    
    for item in tqdm(data, total=len(data), desc="Extracting Paths"):
        func_cfg = item.get("cfg", {})
        
        result = {"path": []}
        if func_cfg:
            cfg_analyzer = BinaryCFGAnalyzer()
            cfg_analyzer.build_cfg_from_json(func_cfg)
            paths, _ = cfg_analyzer.extract_paths()
            result["path"] = paths
        
        results.append(result)

    print(f"[Step 1] Saving paths to {output_path}...")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)
    print("[Step 1] Done.")
