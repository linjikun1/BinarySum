import json
import sys
from tqdm import tqdm

data = []
buffer = ""
with open("result/test_for_filter3_uncertain_4o.jsonl", 'r') as f:
    for line in f:
        line = line.strip()
        if not line:  # 跳过空行
            continue
        
        buffer += line  # 拼接当前行
        if line.endswith('}'):  # JSON 对象结束的标识
            try:
                data.append(json.loads(buffer))  # 尝试解析完整 JSON 对象
                buffer = ""  # 清空缓冲区
            except json.JSONDecodeError:
                pass 
# works = ['decom', 'cfg']
# works = ['hext5', 'bint5', 'cpbcs', 'misum']
works = ['prorec', 'filter_prorec']
# works = ['filter2_prorec', 'filter2_prorec_aug', 'filter2_prorec_aug2']
Q_Acc = {work: 0 for work in works}
Q_Cov = {work: 0 for work in works}
Q_Eff = {work: 0 for work in works}
data = data
i = 0
for item in tqdm(data, total=len(data), desc="Processing: "):
    for work in works:
        Q_Acc[work] += item['work_score'][work]['score'][0]
        Q_Cov[work] += item['work_score'][work]['score'][1]
        Q_Eff[work] += item['work_score'][work]['score'][2]

num_items = len(data)
print(num_items)
print("Average Scores:")
for work in works:
    print(f"\n{work}:")
    print(f"  Accuracy: {Q_Acc[work] / num_items:.4f}")
    print(f"  Coverage: {Q_Cov[work] / num_items:.4f}")
    print(f"  Effectiveness: {Q_Eff[work] / num_items:.4f}")
