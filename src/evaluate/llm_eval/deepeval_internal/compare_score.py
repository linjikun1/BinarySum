import json
import sys
from tqdm import tqdm

data1 = []
buffer = ""
with open("./filter_prorec_aug2_1.jsonl", 'r') as f:
    for line in f:
        line = line.strip()
        if not line:  # 跳过空行
            continue
        
        buffer += line  # 拼接当前行
        if line.endswith('}'):  # JSON 对象结束的标识
            try:
                data1.append(json.loads(buffer))  # 尝试解析完整 JSON 对象
                buffer = ""  # 清空缓冲区
            except json.JSONDecodeError:
                pass 

data2 = []
buffer = ""
with open("./filter_prorec_aug2_2.jsonl", 'r') as f:
    for line in f:
        line = line.strip()
        if not line:  # 跳过空行
            continue
        
        buffer += line  # 拼接当前行
        if line.endswith('}'):  # JSON 对象结束的标识
            try:
                data2.append(json.loads(buffer))  # 尝试解析完整 JSON 对象
                buffer = ""  # 清空缓冲区
            except json.JSONDecodeError:
                pass 

data3 = []
buffer = ""
with open("./prorec_aug2_1.jsonl", 'r') as f:
    for line in f:
        line = line.strip()
        if not line:  # 跳过空行
            continue
        
        buffer += line  # 拼接当前行
        if line.endswith('}'):  # JSON 对象结束的标识
            try:
                data3.append(json.loads(buffer))  # 尝试解析完整 JSON 对象
                buffer = ""  # 清空缓冲区
            except json.JSONDecodeError:
                pass 

data4 = []
buffer = ""
with open("./filter2_prorec_1.jsonl", 'r') as f:
    for line in f:
        line = line.strip()
        if not line:  # 跳过空行
            continue
        
        buffer += line  # 拼接当前行
        if line.endswith('}'):  # JSON 对象结束的标识
            try:
                data4.append(json.loads(buffer))  # 尝试解析完整 JSON 对象
                buffer = ""  # 清空缓冲区
            except json.JSONDecodeError:
                pass 

data = []
buffer = ""
with open("./llmgen_small_result.jsonl", 'r') as f:
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

works = ['prorec']

# for idx, item in tqdm(enumerate(data1), total=len(data1), desc="Processing: "):
#     for work in works:
#         if item['work_score'][work]['flag'] == False:
#             print(f"\n[{idx}] ")
#             print(f"      decom:        {data[idx]['work_score']['decom']['score']}")
#             hal, cov, eff = [
#                 (data1[idx]['work_score'][work]['score'][i] 
#                  + data2[idx]['work_score'][work]['score'][i] 
#                  + data3[idx]['work_score'][work]['score'][i]) / 3.0
#                 for i in range(3)
#             ]
#             print(f"      current:      {[hal, cov, eff]}")
#             # print(f"      data1:      {data1[idx]['work_score'][work]['score']}")
#             # print(f"      data2:      {data2[idx]['work_score'][work]['score']}")
#             # print(f"      data3:      {data3[idx]['work_score'][work]['score']}")
#             # i += 1
#             # hal1, cov1, eff1 = data2[idx]['work_score']['decom']['score']
#             # hal2, cov2, eff2 = item['work_score'][work]['score']
#             # if hal1 < hal2 and cov1 < cov2 and eff1 < eff2:
#             #     j += 1
#             # else:
#             #     pass
#         else:
#             pass

for idx, item in tqdm(enumerate(data1), total=len(data1), desc="Processing: "):

    for work in works:
        if item['work_score'][work]['flag'] == False:
            print(f"\n[{idx}] ")
            print(f"      decom:      {data[idx]['work_score']['decom']['score']}")
            print(f"      data4:      {data4[idx]['work_score'][work]['score']}")
            # hal1, cov1, eff1 = data2[idx]['work_score']['decom']['score']
            # hal2, cov2, eff2 = item['work_score'][work]['score']
            # if hal1 < hal2 and cov1 < cov2 and eff1 < eff2:
            #     j += 1
            # else:
            #     pass
        else:
            pass