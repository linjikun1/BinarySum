import gzip
import os
import json

bin_dir = "/data/linjk/data/binary"
arch_opt = "x64_O3"
path = f"{bin_dir}/{arch_opt}/test_bin_info.pkl.gz"
with gzip.open(path, "rb") as fp:
    head = fp.read(8000)
print(head[:8000])

# from collections import Counter
# import itertools

# def load_jsonl_gz(path):
#     with gzip.open(path, "rt", encoding="utf-8") as f:
#         for line in f:
#             line = line.strip()
#             if line:
#                 yield json.loads(line)

# path = f"{bin_dir}/{arch_opt}/test_bin_info.pkl.gz"

# cnt_proj = Counter()
# cnt_fn = Counter()
# samples = []

# for item in itertools.islice(load_jsonl_gz(path), 5000):  # 先抽 5000 条
#     cnt_proj[item.get("project_name")] += 1
#     cnt_fn[item.get("function_name")] += 1
#     if len(samples) < 5:
#         samples.append((item.get("project_name"), item.get("function_name"), item.get("strip_function_name")))

# print("Top projects:", cnt_proj.most_common(10))
# print("Top function_name:", cnt_fn.most_common(10))
# print("Samples:", samples)
