import pickle
import os
import gzip
import argparse
from analysis.expr_lang_analyzer import ExprLangAnalyzer
from tqdm import tqdm

bin_dir = os.environ.get("bin_dir")
arch_opt = os.environ.get("arch_opt")

list_file_dir = f"{bin_dir}/{arch_opt}"

def load_pickle(path):
    return pickle.load(gzip.open(path, "rb"))

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data_in', type=str, default=f"{list_file_dir}/test.pkl.gz") 
    parser.add_argument('--data_in_for_cg', type=str, default=f"{list_file_dir}/test_for_cg.pkl.gz")    
    parser.add_argument('--fout', type=str, default=f"{list_file_dir}/test_bin_info.pkl.gz")        
    parser.add_argument('--fout_for_cg', type=str, default=f"{list_file_dir}/test_bin_info_for_cg.pkl.gz")    
    args = parser.parse_args()
    return args


def handle_item(function, fout):
    meta = {
        'binary_name': function['binary_name'],
        'project_path': function['project_path'],
        'function_addr': function['function_addr'],
        'strip_function_name': function['strip_function_name'],
        'strip_decompiled_code': function['strip_decompiled_code'],
        'function_name': function['function_name'],
        'decompiled_code': function['decompiled_code']
    }
    meta_for_ProRec = {
        'strip_function_name': function['strip_function_name'],
        'strip_decompiled_code': function['strip_decompiled_code']
    }
    expr_lang_analyzer = ExprLangAnalyzer(function['cfg'])
    expr_lang_analyzer.print_func_to_jsonl(fout, metadata=meta, metadata_for_ProRec=meta_for_ProRec)


def handle_cg_item(function, fout):
    meta = {
        'binary_name': function['binary_name'],
        'project_path': function['project_path'],
        'function_addr': function['function_addr'],
        'strip_function_name': function['strip_function_name'],
        'strip_decompiled_code': function['strip_decompiled_code']
    }
    expr_lang_analyzer = ExprLangAnalyzer(function['cfg'])
    expr_lang_analyzer.print_func_to_jsonl_for_ProRec(fout=fout, metadata=meta)


def process_dataset(data, fout, handler, flag):
    for function in tqdm(data, desc=f"[{arch_opt}][{'for_cg' if flag else ''}] Processing: "):
        try:
            handler(function, fout)
        except Exception as e:
            if str(e) != "timeout":
                print(e)
                print("Error in function: ")
            else:
                print(e)


def main():
    args = parse_args()

    data_in = load_pickle(args.data_in)
    data_in_for_cg = load_pickle(args.data_in_for_cg)

    with gzip.open(args.fout, 'wb', compresslevel=5) as fout, gzip.open(args.fout_for_cg, 'wb', compresslevel=5) as fout_for_cg:
        process_dataset(data_in, fout, handle_item, False)
        process_dataset(data_in_for_cg, fout_for_cg, handle_cg_item, True)

    print(args)


if __name__ == '__main__':
    main()
