from deepeval.test_case import LLMTestCase, LLMTestCaseParams
from deepeval.metrics import GEval
from deepeval.models.llms.openai_model import GPTModel
import json
import time
from tqdm import tqdm

model = GPTModel(
    model="gpt-4o-mini",
    _openai_api_key="sk-qCfNA7gNQKDjCKpFuBJOHGdDAwAyIQ8yaewCbMxlrs6cq49x",
    base_url="https://aizex.top/v1"
)

Effectiveness_metric = GEval(
    name="Effectiveness",
    criteria=(
        "Effectiveness: Evaluate how clearly, precisely, and usefully the summary expresses the logic that is actually present in the source code. Focus only on content that corresponds to real code behavior — ignore any fabricated or hallucinated content. Do not penalize for missing information (Coverage); only judge how well the *included and real* code semantics are conveyed."
    ),
    evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
    evaluation_steps=[
        "Step 1: Identify which statements in the summary correspond to behaviors, conditions, or logic that are actually implemented in the source code.",
        "Step 2: For each such real, grounded statement, evaluate whether it expresses the original logic in a clear, precise, and informative way — does it help the reader understand what the code actually does?",
        "Step 3: Ignore any parts of the summary that describe hallucinated content (not present in the code), and ignore any missing logic (Coverage); only assess the effectiveness of conveying code-true semantics."
    ],
    model=model
)

# 要处理的工作列表
works = ['hext5', 'bint5', 'cpbcs', 'misum', 'prorec', 'decomc']

# 读取原始结果
data = []
buffer = ""
with open("score.jsonl", 'r') as f:
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


with open("score_updated.jsonl", 'a') as f:
    i = 0
    for idx, item in tqdm(enumerate(data), total=len(data), desc="Updating Effectiveness"):
        i += 1
        context = [item['source_code'], item['comment'], item['decompiled_code']]

        for work in works:
            summary = item['work'][work]['summary']

            test_case = LLMTestCase(
                input=None,
                context=context,
                actual_output=summary
            )
            Effectiveness_metric.measure(test_case)
            eff_score = Effectiveness_metric.score
            print(f"[{i}] {work}: {eff_score}")
            item['work'][work]['score'][0] = eff_score  # 替换 Effectiveness 部分
            time.sleep(0.5)  # 防止请求过快触发限速

        f.write(json.dumps(item, indent=4, ensure_ascii=False) + "\n")

# 你可以视情况替换原文件
# import shutil
# shutil.move("score_updated.jsonl", "score.jsonl")
