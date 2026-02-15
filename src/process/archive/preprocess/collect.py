import pickle
import os
from tqdm import tqdm
import gzip
import argparse

bin_dir = os.environ.get("bin_dir")
arch_opt = os.environ.get("arch_opt")

list_file_dir = f"{bin_dir}/{arch_opt}"

def get_args():
    parser = argparse.ArgumentParser(description="Collect the preprocess results")
    parser.add_argument(
        "--binary_list_file",
        type=str,
        default=f"{list_file_dir}/test.txt",
        help="This file contains the file names to be loaded",
    )
    parser.add_argument(
        "--binary_list_file_for_cg",
        type=str,
        default=f"{list_file_dir}/test_for_cg.txt",
        help="This file contains the file names to be loaded for data_cg",
    )
    parser.add_argument(
        "--fout",
        type=str,
        default=f"{list_file_dir}/test.pkl.gz",
        help="The output pickle file for data",
    )
    parser.add_argument(
        "--fout_for_cg",
        type=str,
        default=f"{list_file_dir}/test_for_cg.pkl.gz",
        help="The output pickle file for data_cg",
    )
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    assert os.path.exists(list_file_dir), "list_file_dir does not exist"
    MAX_LEN = 512
    args = get_args()
    print(args)

    def load_entries(list_file):
        fin = open(list_file, "r")
        binary_list = fin.readlines()
        fin.close()
        entries = []
        print(f"Loading binaries from {list_file} ...")
        for b in tqdm(binary_list):
            project_path = os.path.dirname(os.path.dirname(b))
            bin_fin = gzip.open(b.strip(), "rb")
            binary = pickle.load(bin_fin)
            bin_fin.close()

            for function_addr, entry in binary.items():
                cfg = entry['cfg']
                cfg.nodes[function_addr]["num"] = -1
                entries.append(
                    {
                        'binary_name': os.path.basename(b.strip()),
                        'project_path': project_path,
                        'function_addr': function_addr,
                        'strip_function_name': entry['strip_function_name'],
                        'strip_decompiled_code': entry['strip_decompiled_code'],
                        'function_name': entry['function_name'],
                        'decompiled_code': entry['decompiled_code'],
                        'cfg': cfg
                    }
                )
        return entries
    
    def load_entries_for_cg(list_file):
        fin = open(list_file, "r")
        binary_list = fin.readlines()
        fin.close()
        entries = []
        print(f"Loading binaries from {list_file} ...")
        for b in tqdm(binary_list):
            project_path = os.path.dirname(os.path.dirname(b))
            bin_fin = gzip.open(b.strip(), "rb")
            binary = pickle.load(bin_fin)
            bin_fin.close()

            for function_addr, entry in binary.items():
                cfg = entry['cfg']
                cfg.nodes[function_addr]["num"] = -1
                entries.append(
                    {
                        'binary_name': os.path.basename(b.strip()),
                        'project_path': project_path,
                        'function_addr': function_addr,
                        'strip_function_name': entry['strip_function_name'],
                        'strip_decompiled_code': entry['strip_decompiled_code'],
                        'cfg': cfg
                    }
                )
        return entries

    binfolder_binary_entries = load_entries(args.binary_list_file)
    binfolder_binary_entries_cg = load_entries_for_cg(args.binary_list_file_for_cg)

    with gzip.open(args.fout, 'wb', compresslevel=5) as fout:
        pickle.dump(binfolder_binary_entries, fout)

    with gzip.open(args.fout_for_cg, 'wb', compresslevel=5) as fout_for_cg:
        pickle.dump(binfolder_binary_entries_cg, fout_for_cg)
