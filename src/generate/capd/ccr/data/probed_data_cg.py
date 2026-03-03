#!/usr/bin/env python3
"""
Prepare probing data from processed binary code for signature probing.

Usage:
    python probed_data_cg.py --input cg_data_codeart.pkl.gz --output-dir ./data
    python probed_data_cg.py  # Use default paths for BinarySum
"""
import argparse
import pickle
import gzip
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
    parser = argparse.ArgumentParser(description="Prepare probing data for signature probing")
    parser.add_argument("--input", help="Input dataset.pkl.gz file")
    parser.add_argument("--output-dir", default=str(SCRIPT_DIR / ".." / "data"),
                        help="Output directory for processed data")
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
    
    print(f"Loading data from {input_file}")
    with gzip.open(input_file, "rb") as f:
        data = pickle.load(f)

    total = len(data)
    test_start = int(total * (1 - args.test_ratio))
    test_data = data[test_start:]
    print(f"Test data: {len(test_data)} samples")

    # Process test data
    test_src_list = []
    test_codeart_list = []
    test_callers_list = []
    test_callees_list = []

    for item in tqdm(test_data, total=len(test_data), desc="Processing test data"):
        test_src_list.append(item['source_code'])
        
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
        'src': test_src_list,
        'codeart': test_codeart_list,
        'callers': test_callers_list,
        'callees': test_callees_list
    })

    test_dataset = DatasetDict({'test': test_dataset})
    test_output = str(output_dir / "probed_data_cg" / "test")
    test_dataset.save_to_disk(test_output)
    print(f"Saved test dataset to {test_output}")
    print("Data preparation complete!")


if __name__ == "__main__":
    main()
