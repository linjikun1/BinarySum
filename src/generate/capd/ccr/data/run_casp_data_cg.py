#!/usr/bin/env python3
"""
Prepare CASP training data from processed binary code.

Usage:
    python run_casp_data_cg.py --input cg_data_codeart.pkl.gz --output-dir ./data
    python run_casp_data_cg.py  # Use default paths for BinarySum
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
    parser = argparse.ArgumentParser(description="Prepare CASP training data")
    parser.add_argument("--input", help="Input dataset.pkl.gz file")
    parser.add_argument("--output-dir", default=str(SCRIPT_DIR / ".." / "data"),
                        help="Output directory for processed data")
    parser.add_argument("--arch", default="x64_O2", help="Architecture (e.g., x64_O2)")
    parser.add_argument("--train-ratio", type=float, default=0.8, help="Training data ratio")
    parser.add_argument("--valid-ratio", type=float, default=0.1, help="Validation data ratio")
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
    train_end = int(total * args.train_ratio)
    valid_end = int(total * (args.train_ratio + args.valid_ratio))
    train_data = data[:train_end]
    valid_data = data[train_end:valid_end]
    print(f"Data split: train={len(train_data)}, valid={len(valid_data)}")

    # Process train data
    train_src_list = []
    train_codeart_list = []
    train_callers_list = []
    train_callees_list = []

    for item in tqdm(train_data, total=len(train_data), desc="Processing train data"):
        train_src_list.append(item['source_code'])
        
        train_codeart_list.append(repr({
            'code': item['codeart']['code'],
            'data_dep': item['codeart']['data_dep']
        }))
        
        callers_list = [repr({
            'code': caller['code'],
            'data_dep': caller['data_dep']
        }) for caller in item.get('callers', {}).values()]
        train_callers_list.append(callers_list)
        
        callees_list = [repr({
            'code': callee['code'],
            'data_dep': callee['data_dep']
        }) for callee in item.get('callees', {}).values()]
        train_callees_list.append(callees_list)

    train_dataset = Dataset.from_dict({
        'src': train_src_list,
        'codeart': train_codeart_list, 
        'callers': train_callers_list, 
        'callees': train_callees_list  
    })
    train_dataset = DatasetDict({'train': train_dataset})
    train_output = str(output_dir / "bimodal-lmpa-shuffled-cg" / "train")
    train_dataset.save_to_disk(train_output)
    print(f"Saved train dataset to {train_output}")

    # Process validation data
    valid_src_list = []
    valid_codeart_list = []
    valid_callers_list = []
    valid_callees_list = []

    for item in tqdm(valid_data, total=len(valid_data), desc="Processing valid data"):
        valid_src_list.append(repr(item['source_code']))
        
        valid_codeart_list.append(repr({
            'code': item['codeart']['code'],
            'data_dep': item['codeart']['data_dep']
        }))
        
        callers_list = [repr({
            'code': caller['code'],
            'data_dep': caller['data_dep']
        }) for caller in item.get('callers', {}).values()]
        valid_callers_list.append(callers_list)
        
        callees_list = [repr({
            'code': callee['code'],
            'data_dep': callee['data_dep']
        }) for callee in item.get('callees', {}).values()]
        valid_callees_list.append(callees_list)

    valid_dataset = Dataset.from_dict({
        'src': valid_src_list,
        'codeart': valid_codeart_list,
        'callers': valid_callers_list,
        'callees': valid_callees_list
    })
    valid_dataset = DatasetDict({'valid': valid_dataset})
    valid_output = str(output_dir / "bimodal-lmpa-shuffled-cg" / "valid")
    valid_dataset.save_to_disk(valid_output)
    print(f"Saved valid dataset to {valid_output}")
    print("Data preparation complete!")


if __name__ == "__main__":
    main()
