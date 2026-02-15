from deepeval.test_case import LLMTestCase, LLMTestCaseParams
from deepeval.metrics import GEval, HallucinationMetric
from deepeval.models.llms.openai_model import GPTModel

import time
import json
import random
from tqdm import tqdm

model = GPTModel(
    model="gpt-4o",
    _openai_api_key="sk-ozBLfwlgIwNJprcJMSZSFm0HqNUoA4CyEskNbCNvDbBXsVMV",
    base_url="https://aizex.top/v1",
    temperature=0.1
)

# 是否添加了不存在的内容 
Hallucination_metric = GEval(
    name="Accuracy Fidelity",
    criteria=(
        "Accuracy Fidelity: Evaluate the trustworthiness of the summary based on the ratio of accurate details to total details. "
        "Higher scores indicate a summary that is free from hallucinations."
    ),
    evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
    evaluation_steps=[
        # 统一的 Step 1
        "Extract all semantic details from the SUMMARY (including specific claims about libraries, drivers, logic steps, data types) and verify their truthfulness against the SOURCE_CODE. Mark each detail as **'Accurate'** ONLY if there is explicit evidence (strings, function names, logic structure) in the source code; otherwise, mark it as **'Inaccurate'** (Hallucination), even if it seems plausible based on context.",
        
        # 差异化 Step 2 & 3
        "Calculate the **Ratio of Accurate Details**: (Count of Accurate Details) / (Total Number of Details).",
        
        "Assign Score based on the Ratio:\
            - **Score 9-10**: >90% of details are Accurate. (Almost no hallucinations).\
            - **Score 5-8**: Mixed accuracy. Some details are correct, but others are unverified assumptions.\
            - **Score 0-4**: <50% of details are Accurate. The summary is dominated by hallucinations."
    ],
    model=model
)

# 是否遗漏了关键内容 
Coverage_metric = GEval(
    name="Valid Semantic Coverage",
    criteria=(
        "Valid Semantic Coverage: Evaluate how well the *Accurate Details Only* cover the full semantic meaning of the Source Code. "
        "Logic: Filter out lies first, then measure the completeness of the truth."
    ),
    evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
    evaluation_steps=[
        # 统一的 Step 1
        "Extract all semantic details from the SUMMARY (including specific claims about libraries, drivers, logic steps, data types) and verify their truthfulness against the SOURCE_CODE. Mark each detail as **'Accurate'** ONLY if there is explicit evidence (strings, function names, logic structure) in the source code; otherwise, mark it as **'Inaccurate'** (Hallucination), even if it seems plausible based on context.",
        
        # 差异化 Step 2 & 3
        "**FILTERING & MAPPING**: Discard all 'Inaccurate' details. Map the remaining 'Accurate' details to the Source Code's critical semantic units (e.g., control flow, error handling, specific data manipulations).",
        
        "Assign Score based on Completeness of the Valid Content:\
            - **Score 8-10**: The accurate details form a complete picture of the code's logic (including edge cases).\
            - **Score 4-7**: The accurate details cover the main action, but significant logic is missing.\
            - **Score 0-3**: After discarding hallucinations, the remaining content is empty or misses the core logic entirely."
    ],
    model=model
)

# 判断描述的质量和价值 
Effectiveness_metric = GEval(
    name="Utility with Kill Switch",
    criteria=(
        "Utility with Kill Switch: Evaluate the helpfulness of the summary for a reverse engineer, strictly penalizing misleading information. "
        "Logic: If unreliable, Score 0. If reliable, reward Specificity."
    ),
    evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
    evaluation_steps=[
        # 统一的 Step 1
        "Extract all semantic details from the SUMMARY (including specific claims about libraries, drivers, logic steps, data types) and verify their truthfulness against the SOURCE_CODE. Mark each detail as **'Accurate'** ONLY if there is explicit evidence (strings, function names, logic structure) in the source code; otherwise, mark it as **'Inaccurate'** (Hallucination), even if it seems plausible based on context.",
        
        # 差异化 Step 2 & 3
        "**THE KILL SWITCH**: Check the proportion of 'Inaccurate' details.\
            - If Inaccurate Details > 50% of the total: **STOP. Score 0.** (The summary is misleading/poisonous).\
            - If Inaccurate Details <= 50%: Proceed to Step 3.",
            
        "Evaluate the **Value of the Accurate Details**:\
            - **Score 8-10**: The accurate details provide specific, domain-rich insights.\
            - **Score 4-7**: The accurate details are generic/vague.\
            - **Score 1-3**: The accurate details are trivial or barely helpful."
    ],
    model=model
)

# Contextual_Relevance_metric = GEval(
#     name="Contextual Relevance",
#     criteria="Contextual Relevance: Determine whether the summary captures how the function fits into the broader program context, including its purpose, dependencies, or interactions with other components.",
#     evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
#     evaluation_steps=[
#         "Step 1: Evaluate whether the summary conveys how the function contributes to or interacts with other parts of the application.",
#         "Step 2: Identify whether the summary explains the purpose of the function beyond its internal logic — for example, its intended effect or outcome in the full system.",
#         "Step 3: Do not evaluate the factual correctness of internal logic — focus only on how well the summary contextualizes the function."
#     ],
#     model=model
# )

# Conciseness_metric = GEval(
#     name="Conciseness",
#     criteria="Conciseness: Evaluate whether the summary is a single, short sentence not exceeding 30 words. Do not consider information quality or completeness.",
#     evaluation_params=[LLMTestCaseParams.ACTUAL_OUTPUT],
#     evaluation_steps=[
#         "Step 1: Confirm that the output is a single sentence, not a list or multiple clauses split by punctuation.",
#         "Step 2: Count the words in the sentence. It must not exceed 30 words.",
#         "Step 3: Do not evaluate the semantic content or whether the information is essential or accurate — only check sentence form and length."
#     ],
#     model=model
# )
works = ['decom', 'cfg']
# works = ['prorec', 'prorec_aug', 'prorec_aug2']
# works = ['hext5', 'bint5', 'cpbcs', 'misum']
# works = ['decom', 'prorec', 'cfg', 'prorec_aug']
works = ['hext5', 'bint5', 'cpbcs', 'misum']
works = ['prorec', 'filter_prorec']

Q_Hal = {work: 0 for work in works}
Q_Cov = {work: 0 for work in works}
Q_Eff = {work: 0 for work in works}
# Q_Cont = {work: 0 for work in works}
# Q_Conc = {work: 0 for work in works} 

with open("/home/linjk/study/NLG-evaluation/data/filter_result.json", 'r') as f, open("result/test_for_filter_160_200.jsonl", 'a') as fa:
    i = 0
    data = json.load(f)[160:200]

    range_num = 1
    for item in tqdm(data, total=len(data), desc="LLM Eval: "):
        i += 1
        # if i < 23:
        #     continue
        source_code = item['source_code']
        # comment = item['comment']
        # decompiled_code = item['decompiled_code']
        work_score = {}
        for work in works:
            if work == 'comment':
                summary = item['comment']
            else:
                summary = item[f"{work}_sum"]

            # flag = "Equal" if summary == item['decom_sum'] else "Not Equal"

            test_case = (LLMTestCase(
                input="",
                context=[source_code],
                actual_output=summary
            ))
            retries = 3
            while retries > 0:
                try:
                    Q_Hal_score = 0.0
                    for _ in range(range_num):
                        Hallucination_metric.measure(test_case)
                        Q_Hal_score += Hallucination_metric.score
                        time.sleep(0.5)
                    Q_Hal_score /= float(range_num)
                    Q_Hal[work] += Q_Hal_score
                except Exception as e:
                    print(f"Error: {e}")
                    retries -= 1
                else:
                    break
            retries = 3
            while retries > 0:
                try:
                    Q_Cov_score = 0.0
                    for _ in range(range_num):
                        Coverage_metric.measure(test_case)
                        Q_Cov_score += Coverage_metric.score
                        time.sleep(0.5)
                    Q_Cov_score /= float(range_num)
                    Q_Cov[work] += Q_Cov_score
                except Exception as e:
                    print(f"Error: {e}")
                    retries -= 1
                else:
                    break
            retries = 3
            while retries > 0:
                try:
                    Q_Eff_score = 0.0
                    for _ in range(range_num):
                        Effectiveness_metric.measure(test_case)
                        Q_Eff_score += Effectiveness_metric.score
                        time.sleep(0.5)
                    Q_Eff_score /= float(range_num)
                    Q_Eff[work] += Q_Eff_score
                except Exception as e:
                    print(f"Error: {e}")
                    retries -= 1
                else:
                    break
            # Contextual_Relevance_metric.measure(test_case)
            # Q_Cont_score = Contextual_Relevance_metric.score
            # Q_Cont[work] += Q_Cont_score
            # time.sleep(0.5) 

            # Conciseness_metric.measure(test_case)
            # Q_Conc_score = Conciseness_metric.score
            # Q_Conc[work] += Q_Conc_score
            # time.sleep(0.5)
            print(f"[{i}] {work}: {Q_Hal_score}, {Q_Cov_score}, {Q_Eff_score}")

            work_score[work] = {
                'summary': summary,
                # 'flag': True if summary == item['decom_sum'] else False,
                'score': [Q_Hal_score, Q_Cov_score, Q_Eff_score]
            }
            
        # continue
        item['work_score'] = work_score
        fa.write(json.dumps(item, indent=4, ensure_ascii=True) + '\n')
        fa.flush()

    num_items = len(data)
    print("\nAverage Scores:")
    for work in works:
        print(f"\n{work}:")
        print(f"  Hallucination: {Q_Hal[work] / num_items:.4f}")
        print(f"  Coverage: {Q_Cov[work] / num_items:.4f}")
        print(f"  Effectiveness: {Q_Eff[work] / num_items:.4f}")
        # print(f"  Contextual Relevance: {Q_Cont[work] / num_items:.4f}")
        # print(f"  Conciseness: {Q_Conc[work] / num_items:.4f}")