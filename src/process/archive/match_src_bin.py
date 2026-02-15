import json
import sys
import re
from tqdm import tqdm
import random
import gzip
import pickle
import os

bin_dir = os.environ.get("bin_dir")
arch_opt = os.environ.get("arch_opt")

# bin_dir = "/data/linjk/data/binary"
# arch_opt = "x64_O3"

# 加载二进制信息
def load_bin_data_stream(filepath):
    buffer = ""
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            buffer += line
            if line.endswith('}'):
                try:
                    yield json.loads(buffer)
                    buffer = ""
                except json.JSONDecodeError:
                    pass

def load_jsonl_gz(path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)

# 计算代码的单词数量
def word_count(code):
    tokens = re.findall(r'\w+|[^\s\w]', code)
    return len(tokens)

with open(f"data/test_src_info.json", 'r') as f:
    src_data = json.load(f)
    print(f"源代码加载完成，数量: {len(src_data)}")

bin_dict = {}
for item in load_jsonl_gz(f"{bin_dir}/{arch_opt}/test_bin_info.pkl.gz"):
    project_name = item.get("project_name")
    function_name = item.get("function_name")
    if project_name not in bin_dict:
        bin_dict[project_name] = {}
    # 重复函数的存在是因为同一个逻辑很短、常被调用的函数在反编译过程中，于不同位置被重复生成
    # 重复函数的内容完全相同，去重无需担心
    bin_dict[project_name][function_name] = item
print(f"二进制信息 bin_dict 加载完成")
cnt = 0
for k, v in bin_dict.items():
    print(f"[{k}]: {len(v)}")
    cnt += len(v)
print(cnt)
tmp_items = []
i, j, k = 0, 0, 0
for item in tqdm(src_data, total=len(src_data), desc="Matching info: "):
    comment = str(item['comment']).strip()
    project_name = item['project_name'].split('-')[0]
    function_name = item['function_name']

    bin_proj = bin_dict.get(project_name, {})
    bin_fn   = bin_proj.get(function_name)
    if not bin_fn:
        i += 1
        continue
    cfg = bin_fn['cfg']
    if not cfg['nodes'] or not cfg['edge_index'][0] or not cfg['edge_index'][1]:
        j += 1
        continue
    de_code = bin_fn['strip_decompiled_code']
    source_code = item['source_code']
    if not (30 < word_count(de_code) < 9192) or not (30 < word_count(source_code) < 9192):
        k += 1
        continue

    tmp_items.append({
        'project_name'         : project_name,
        'function_name'        : function_name,
        'strip_function_name'  : bin_fn['strip_function_name'],
        'function_addr'        : bin_fn['function_addr'],
        'strip_decompiled_code': de_code,
        'decompiled_code'      : bin_fn['decompiled_code'],
        'asm_code'             : bin_fn['asm_code'],
        'cfg'                  : cfg,
        'source_code'          : source_code,
        'comment'              : comment,
        'meta'                 : bin_fn['data_for_ProRec'],
    })
print(f"源代码与二进制信息初始匹配完成，数量: {len(tmp_items)}")

# print(i, j, k)
# import sys
# sys.exit(0)

src_seen = set()
key_seen = set()
dedup_items = []
for rec in tmp_items:
    src = rec["source_code"]
    base_key = f"{rec['project_name']}::{rec['function_addr']}::{rec['strip_function_name']}::{rec['strip_decompiled_code'][:50]}"
    if src not in src_seen and base_key not in key_seen:
        src_seen.add(src)
        key_seen.add(base_key)
        dedup_items.append(rec)
tmp_items = dedup_items
print(f"以 source_code 和 base_key 为基准去重完成，数量: {len(tmp_items)}")

tmp_dict = {f"{item['project_name']}::{item['function_addr']}::{item['strip_function_name']}::{item['strip_decompiled_code'][:50]}": item 
                  for item in tmp_items}

with gzip.open(f"{bin_dir}/{arch_opt}/raw_cfg_data.pkl.gz", 'rb') as f:
    cfg_data = pickle.load(f)
    print(f"len(cfg_data): {len(cfg_data)}")
    cfg_dict = {f"{item['project_name']}::{item['function_addr']}::{item['strip_function_name']}::{item['strip_decompiled_code'][:50]}": item 
                  for item in cfg_data} 
with gzip.open(f"{bin_dir}/{arch_opt}/raw_cg_data.pkl.gz", 'rb') as f:
    cg_data = pickle.load(f)
    print(f"len(cg_data): {len(cg_data)}")
    cg_dict = {f"{item['project_name']}::{item['function_addr']}::{item['strip_function_name']}::{item['strip_decompiled_code'][:50]}": item 
                  for item in cg_data}
random.seed(42)
common_keys = list(set(tmp_dict.keys()) & set(cfg_dict.keys()) & set(cg_dict.keys()))
random.shuffle(common_keys)

tmp_dict = {key : tmp_dict[key] for key in common_keys}
cfg_dict = {key : cfg_dict[key] for key in common_keys}
cg_dict = {key : cg_dict[key] for key in common_keys}
print(f"CFG、CG 交集匹配完成，数量: {len(tmp_dict)}")


for key, item in tqdm(tmp_dict.items(), total=len(tmp_dict), desc="Matching info: "):
    cfg_dict[key]['source_code'] = item['source_code']
    cfg_dict[key]['comment'] = item['comment']
    cg_dict[key]['source_code'] = item['source_code']
    cg_dict[key]['comment'] = item['comment']

os.makedirs(f"result/{arch_opt}", exist_ok=True)

tmp_items = list(tmp_dict.values())
print(f"暂存: {len(tmp_items)}")
# 暂存
with gzip.open(f"result/{arch_opt}/tmp_items.pkl.gz", 'wb', compresslevel=5) as f:
    pickle.dump(tmp_items, f)

cfg_data = list(cfg_dict.values())
with gzip.open(f"result/{arch_opt}/cfg_data.pkl.gz", 'wb', compresslevel=5) as f:
    pickle.dump(cfg_data, f)

cg_data = list(cg_dict.values())
# bin_dict = {}
# for item in tqdm(load_bin_data_stream("/home/linjk/study/data/result/test_bin_info_cg.jsonl"), 
#                  desc="Making dict: "):
#     project_name = item.get("project_name")
#     strip_function_name = item.get("strip_function_name")
#     code = item.get("strip_decompiled_code")[:50]
#     bin_dict[f"{project_name}::{strip_function_name}::{code}"] = item

# for item in tqdm(cg_data, desc="Matching: "):
#     project_name = item.get("project_name")
#     strip_function_name = item.get("strip_function_name")
#     code = item.get("strip_decompiled_code")[:50]
#     base_key = f"{project_name}::{strip_function_name}::{code}"
#     item['codeart'] = bin_dict[base_key]['data_for_ProRec']

#     callers = item.get("callers")
#     new_callers = {}
#     if callers: # 确保 callers 不是 None
#         for key, value in callers.items():
#             base_key = f"{project_name}::{key}::{value[:50]}"
#             if base_key not in bin_dict:
#                 i += 1
#                 continue
#             new_callers[key] = {
#                 'code': bin_dict[base_key]['data_for_ProRec']['code'],
#                 'data_dep': bin_dict[base_key]['data_for_ProRec']['data_dep']
#             }
#     item['callers'] = new_callers

#     callees = item.get("callees")
#     new_callees = {}
#     if callees: # 确保 callees 不是 None
#         for key, value in callees.items():
#             base_key = f"{project_name}::{key}::{value[:50]}"
#             if base_key not in bin_dict:
#                 j += 1
#                 continue
#             new_callees[key] = {
#                 'code': bin_dict[base_key]['data_for_ProRec']['code'],
#                 'data_dep': bin_dict[base_key]['data_for_ProRec']['data_dep']
#             }
#     item['callees'] = new_callees

# with open(f"result/{arch_opt}/tmp_cg_data_codeart.json", 'w') as f:
#     json.dump(cg_data[:100], f, indent=4)
with gzip.open(f"result/{arch_opt}/cg_data.pkl.gz", 'wb', compresslevel=5) as f:
    pickle.dump(cg_data, f) 

### 5. 写入各个目录
result_for_HexT5, result_for_BinT5, result_for_CP_BCS, result_for_ProRec = [], [], [], []

for rec in tmp_items:
    proj = rec['project_name']
    strip_name = rec['strip_function_name']
    # HexT5
    result_for_HexT5.append({
        'project_name'        : proj,
        'function_addr'       : rec['function_addr'],
        'strip_function_name' : strip_name,
        'strip_decompiled_code': rec['strip_decompiled_code'],
        'function_name'       : rec['function_name'],
        'decompiled_code'     : rec['decompiled_code'],
        'source_code'         : rec['source_code'],
        'comment'             : rec['comment'],
    })

    # BinT5
    result_for_BinT5.append({
        'project_name'        : proj,
        'function_addr'       : rec['function_addr'],
        'strip_decompiled_code': rec['strip_decompiled_code'],
        'comment'             : rec['comment'],
    })

    # CP-BCS / MiSum
    result_for_CP_BCS.append({
        'function_name'          : rec['function_name'],
        'function_name_in_strip' : strip_name,
        'comment'                : rec['comment'],
        'function_body'          : rec['asm_code'],
        'pseudo_code'            : rec['strip_decompiled_code'],
        'cfg'                    : rec['cfg'],
        'pseudo_code_non_strip'  : rec['decompiled_code'],
        'pseudo_code_refined'    : rec['strip_decompiled_code'],
    })

    # ProRec
    result_for_ProRec.append({
        'project_name'  : proj,
        'function_addr' : rec['function_addr'],
        'comment'       : rec['comment'],
        'source_code'   : rec['source_code'],
        'meta'          : rec['meta'],
    })

assert result_for_HexT5[0]['comment'] == result_for_CP_BCS[0]['comment'] == result_for_ProRec[0]['comment'], "the comment should be the same"
assert len(result_for_HexT5) == len(result_for_BinT5) == len(result_for_CP_BCS) == len(result_for_ProRec), "the length of the data should be the same"

# 写入文件
os.makedirs(f"result/{arch_opt}/HexT5", exist_ok=True)
os.makedirs(f"result/{arch_opt}/BinT5", exist_ok=True)
os.makedirs(f"result/{arch_opt}/CPBCS", exist_ok=True)
os.makedirs(f"result/{arch_opt}/ProRec", exist_ok=True)
with open(f"result/{arch_opt}/HexT5/test_for_HexT5.json", 'w') as f:
    json.dump(result_for_HexT5, f, indent=4)
with open(f"result/{arch_opt}/BinT5/test_for_BinT5.json", 'w') as f:
    json.dump(result_for_BinT5, f, indent=4)
with open(f"result/{arch_opt}/CPBCS/test_for_CP_BCS.json", 'w') as f:
    json.dump(result_for_CP_BCS, f, indent=4)
with open(f"result/{arch_opt}/ProRec/test_for_ProRec.json", 'w') as f:
    json.dump(result_for_ProRec, f, indent=4)