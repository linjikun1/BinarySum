import json
import pickle
import gzip
from tqdm import tqdm
from src.analyzer.cfg_analyzer import BinaryCFGAnalyzer

def run_step1(input_path, output_path):
    """
    Step 1: Parse CFG data and extract paths.
    """
    print(f"[Step 1] Loading data from {input_path}...")
    try:
        with gzip.open(input_path, 'rb') as f:
            data = pickle.load(f)
    except FileNotFoundError:
        print(f"Error: Input file {input_path} not found.")
        return
    except Exception as e:
        # Fallback to json if pickle fails (or if file is not gzipped)
        try:
            with open(input_path, 'r') as f:
                data = json.load(f)
        except:
            print(f"Error loading file {input_path}: {e}")
            return

    # Optional: Filter logic removed for general usage
    # data = data[int(len(data) * 0.9):]
    # tmp = []
    # for item in data:
    #     if 200 < len(item['strip_decompiled_code'].strip().split()) < 250:
    #         tmp.append(item)
    # data = tmp

    for item in tqdm(data, total=len(data), desc="Extracting Paths"):
        func_cfg = item.get("cfg", {})
        if not func_cfg:
            item["path"] = []
            continue
            
        cfg_analyzer = BinaryCFGAnalyzer()
        cfg_analyzer.build_cfg_from_json(func_cfg)
        paths, _ = cfg_analyzer.extract_paths()
        
        item["path"] = paths

    print(f"[Step 1] Saving paths to {output_path}...")
    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
    print("[Step 1] Done.")
