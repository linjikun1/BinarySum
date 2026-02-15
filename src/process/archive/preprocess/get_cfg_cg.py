import json
import os
import gzip
import pickle
from tqdm import tqdm

bin_dir = os.environ.get("bin_dir")
arch_opt = os.environ.get("arch_opt")

seen_cfg = set()
seen_cg = set()
result1 = []
result2 = []

data_dir = f"{bin_dir}/{arch_opt}"

projects = [p for p in os.listdir(data_dir) if os.path.isdir(os.path.join(data_dir, p))]

for proj in tqdm(projects, desc=f"[{arch_opt}] Projects", unit="proj"):
    proj_dir = os.path.join(data_dir, proj)

    files = [fn for fn in os.listdir(proj_dir) if fn.endswith(("cfgdata.json", "cgdata.json"))]
    for file in tqdm(files, desc=f"{proj}", unit="file", leave=False):
        file_path = os.path.join(proj_dir, file)

        if file.endswith("cfgdata.json"):
            with open(file_path, "r") as f:
                data = json.load(f)
            for key, value in data.items():
                first_block = next(iter(value['cfg'])) if value.get('cfg') else None
                base_key = f"{proj}::{first_block}::{key}::{value['decompiled_code'][:50]}"
                if base_key in seen_cfg:
                    continue
                seen_cfg.add(base_key)
                result1.append({
                    'project_name': proj,
                    'function_addr': first_block,
                    'strip_function_name': key,
                    'strip_decompiled_code': value['decompiled_code'],
                    'cfg': value['cfg'],
                })

        elif file.endswith("cgdata.json"):
            with open(file_path, "r") as f:
                data = json.load(f)
            for item in data:
                base_key = (
                    f"{item['project_name']}::{item['function_addr']}::"
                    f"{item['strip_function_name']}::{item['strip_decompiled_code'][:50]}"
                )
                if base_key in seen_cg:
                    continue
                seen_cg.add(base_key)
                result2.append(item)

print(len(result1), len(result2))

with gzip.open(f"{bin_dir}/{arch_opt}/raw_cfg_data.pkl.gz", "wb", compresslevel=5) as f:
    pickle.dump(result1, f)

with gzip.open(f"{bin_dir}/{arch_opt}/raw_cg_data.pkl.gz", "wb", compresslevel=5) as f:
    pickle.dump(result2, f)
