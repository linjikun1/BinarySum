#!/usr/bin/env python3
"""
Prepare probing data for continue probing (body generation).

Usage:
    python probed_continue_data_cg.py --input cg_data_codeart.pkl.gz --output-dir ./data
    python probed_continue_data_cg.py  # Use default paths for BinarySum
"""
import argparse
import pickle
import gzip
import json
import os
from pathlib import Path
from tqdm import tqdm
from datasets import Dataset, DatasetDict

# Default paths for BinarySum integration
SCRIPT_DIR = Path(__file__).parent.resolve()
CCR_DIR = SCRIPT_DIR.parent
BINARYSUM_ROOT = CCR_DIR.parent.parent.parent.parent
DEFAULT_DATA_DIR = BINARYSUM_ROOT / "data" / "processed"


def main():
    parser = argparse.ArgumentParser(description="Prepare probing data for body generation")
    parser.add_argument("--input", help="Input dataset.pkl.gz file")
    parser.add_argument("--output-dir", default=str(SCRIPT_DIR / ".." / "data"),
                        help="Output directory for processed data")
    parser.add_argument("--scored-signatures", help="Scored signatures JSON file")
    parser.add_argument("--arch", default="x64_O2", help="Architecture (e.g., x64_O2)")
    parser.add_argument("--test-ratio", type=float, default=0.1, help="Test data ratio")
    args = parser.parse_args()
    
    # Determine input file
    if args.input:
        input_file = args.input
    else:
        input_file = str(DEFAULT_DATA_DIR / args.arch / "dataset.pkl.gz")
    
    if not os.path.exists(input_file):
        print(f"ERROR: Input file not found: {input_file}")
        print(f"Please run BinarySum data processing first:")
        print(f"  python main.py process --arch {args.arch}")
        return
    
    # Output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Determine scored signatures file
    if args.scored_signatures:
        scored_file = args.scored_signatures
    else:
        scored_file = str(CCR_DIR / "save" / args.arch / "scored_signatures.json")
    
    if not os.path.exists(scored_file):
        print(f"ERROR: Scored signatures file not found: {scored_file}")
        print(f"Please run signature probing first:")
        print(f"  cd {CCR_DIR}/src && accelerate launch big_model_quantized_probing.py scripts/configs/probe_quantized_codellama-34b-4bit-unfreeze.yaml")
        return
    
    print(f"Loading data from {input_file}")
    with gzip.open(input_file, "rb") as f:
        data = pickle.load(f)

    print(f"Loading scored signatures from {scored_file}")
    with open(scored_file, 'r') as f:
        scored_signatures = json.load(f)

    total = len(data)
    test_start = int(total * (1 - args.test_ratio))
    test_data = data[test_start:]
    print(f"Test data: {len(test_data)} samples")

    # Process test data
    test_info_list = []
    test_codeart_list = []
    test_callers_list = []
    test_callees_list = []

    for item in tqdm(test_data, total=len(test_data), desc="Processing test data"):
        test_info_list.append(repr({
            'decompiled_code': item['codeart']['strip_decompiled_code'],
            'comment': item['comment']
        }))

        test_codeart_list.append(repr({
            'code': item['codeart']['code'],
            'data_dep': item['codeart']['data_dep']
        }))
        
        callers_list = [repr({
            'code': caller['code'],
            'data_dep': caller['data_dep']
        }) for caller in item.get('callers', {}).values()]
        test_callers_list.append(callers_list)
        
        callees_list = [repr({
            'code': callee['code'],
            'data_dep': callee['data_dep']
        }) for callee in item.get('callees', {}).values()]
        test_callees_list.append(callees_list)

    test_dataset = Dataset.from_dict({
        'codeinfo': test_info_list,
        'codeart': test_codeart_list,
        'candidate_signatures': scored_signatures,
        'callers': test_callers_list,
        'callees': test_callees_list
    })

    test_dataset = DatasetDict({'test': test_dataset})
    test_output = str(output_dir / "probed_continue_data_cg" / "test")
    test_dataset.save_to_disk(test_output)
    print(f"Saved test dataset to {test_output}")
    print("Data preparation complete!")


if __name__ == "__main__":
    main()
