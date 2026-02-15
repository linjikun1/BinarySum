from deepeval.test_case import LLMTestCase, LLMTestCaseParams
from deepeval.metrics import GEval, HallucinationMetric
from deepeval.models.llms.openai_model import GPTModel

import time
import json
import random
from tqdm import tqdm

model = GPTModel(
    model="gpt-4o",
    _openai_api_key="sk-rMbghGaVULY5UMOKdJa2VfX7dPTfY4yNq2wgeFijGo4y5j3Y",
    base_url="https://aizex.top/v1",
    temperature=0.1
)

# model = GPTModel(
#     model="gpt-4o",
#     _openai_api_key="sk-F1EpMfahjheALyH1mE0uSHPBz9M1VzxiFIaHxWfAZS8WUHY8",
#     base_url="https://api-slb.packyapi.com/v1",
#     temperature=0.1
# )

# 准确率 
Accuracy_metric = GEval(
    name="Accuracy (Precision)",
    criteria="Accuracy (Precision): ",
    evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
    evaluation_steps=[
        # Step 1: 识别
        """Extract fact-based claims atomically from the SUMMARY into a temporary CLAIM_LIST = [claim1, claim2, ...] and compare each claim with SOURCE_CODE to tag it as:
            - **[ACCURATE]**: if it's a highly specific and verifiable claim that states domain-semantic behavior/contract of this function (GOLD), or it's correct but generic/boilerplate, low-info, or non-distinguishing statements (SAFE).
            - **[INACCURATE]**: if it targets source code semantics but contradictorily (FATAL), or it doesn't target code at all (NOISE)."""
        
        # Step 2: 计算 Precision
        """Calculate the proportion of [ACCURATE] in the CLAIM_LIST:
            - **Score 1-3**: only <50% of the claims are ACCURATE.
            - **Score 4-7**: 50-80% of the claims are ACCURATE. Mixed reliability.
            - **Score 8-10**: >80% of the claims are ACCURATE. High purity/precision."""
    ],
    model=model
)

# 召回率
Coverage_metric = GEval(
    name="Coverage (Recall)",
    criteria="Coverage (Recall): Evaluate how well the [ACCURATE] claims cover the critical semantics of the Source Code.",
    evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
    evaluation_steps=[
        # Step 1: 识别（保持不变）
        """Extract fact-based claims atomically from the SUMMARY into a temporary CLAIM_LIST = [claim1, claim2, ...] and compare each claim with SOURCE_CODE to tag it as:
            - **[ACCURATE]**: if it's a highly specific and verifiable claim that states domain-semantic behavior/contract of this function (GOLD), or it's correct but generic/boilerplate, low-info, or non-distinguishing statements (SAFE).
            - **[INACCURATE]**: if it targets source code semantics but contradictorily (FATAL), or it doesn't target code at all (NOISE).""",

        # Step 2: 提取 core primary purpose（只抽一个）
        """Derive one CORE_PRIMARY_PURPOSE from SOURCE_CODE:
            - One sentence of the core domain operation/effect with specific domain wording (like "perform NFS3 inode link into directory with name").
            - Must be concrete enough to distinguish from boilerplate (not just generic helper/RPC/status phrasing).""",

        # Step 3: 判断是否提及 core primary purpose，并评分
        """Using only [ACCURATE] claims from CLAIM_LIST, judge if SUMMARY covers CORE_PRIMARY_PURPOSE:
            - "Covered" only when an [ACCURATE] claim states the same domain action/effect with similar specificity; vague wording like "performs an operation" does not count.
            - Then gauge coverage of other behavior-critical semantics in SOURCE_CODE (I/O, side effects, errors, branches/edge cases, constants/configs, external interactions).

        Scoring:
            - **1-3**: Core not covered (1 almost no secondary info; 2 a little but very incomplete; 3 several secondary points yet core missing).
            - **4-6**: Core covered, secondary weak (4 very thin; 5 some; 6 decent but still incomplete).
            - **7-10**: Core covered, broad secondary (7 multiple key points; 8 most key points; 9-10 near-complete incl. branches/errors/side effects/constants)."""
    ],
    model=model
)

# 有效性
Effectiveness_metric = GEval(
    name="Effectiveness (Net Benefit)",
    criteria="Effectiveness (Net Benefit): Evaluate the helpfulness for reverse engineering based on Specificity and Insight depth. Penalize generic descriptions.",
    evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
    evaluation_steps=[
        # Step 1: 识别
        """Extract fact-based claims atomically from the SUMMARY into a temporary CLAIM_LIST = [claim1, claim2, ...] and compare each claim with SOURCE_CODE to tag it as:
            - **[ACCURATE]**: if it's a highly specific and verifiable claim that states domain-semantic behavior/contract of this function (GOLD), or it's correct but generic/boilerplate, low-info, or non-distinguishing statements (SAFE).
            - **[INACCURATE]**: if it targets source code semantics but contradictorily (FATAL), or it doesn't target code at all (NOISE)."""
        
        # Step 2: 评估负面影响 (Negative Impact Analysis)
        """Assess negative impact from [INACCURATE] claims:
            - If there is any FATAL about the PRIMARY PURPOSE (core domain action/effect, WHAT) / key I/O / key side effect, the score MUST be 1-3.
            - Else if NOISE is overwhelming (e.g., it's much more than ACCURATE claims), the score MUST be at most 4-6.
            - Briefly state what the worst failure mode is (FATAL vs NOISE).""",
        
        # Step 3: 评估正面增益 (Information Gain Analysis)
        """Assess positive gain from [ACCURATE] claims:
            - **Low Gain**: Generic and broad SAFE claims with low-info that provides little insight.
            - **High Gain**: Specific and detailed GOLD claims that saves the engineer time.""",
        
        # Step 4: 计算净收益 (Net Benefit Score)
        """Assign a score based on Net Benefit:
            - **Score 1-3 (Negative/Zero Benefit)**: 1 severe FATAL on core/key I/O/side effect (unusable); 2 FATAL present but narrower (still untrustworthy); 3 no FATAL, but noise overwhelms accuracy (net benefit ≈ 0).
            - **Score 4-6 (Low Net Benefit, NO FATAL)**: 4 no FATAL, noise noticeable, gain very low; 5 noise/gain mediocre, limited info; 6 noise acceptable, gain still weak.
            - **Score 7-10 (High Net Benefit, GOLD force multiplier present)**: 7 few specific gains, net positive; 8 most key points specific, low noise; 9-10 broad high gain,, big acceleration, noise negligible."""
    ],
    model=model
)


# works = ['comment', 'decom']
works = ['prorec', 'filter_prorec']
# works = ['hext5', 'bint5', 'cpbcs', 'misum']
# works = ['prorec', 'filter_prorec', 'prorec_aug', 'filter_prorec_aug']

Q_Acc = {work: 0 for work in works}
Q_Cov = {work: 0 for work in works}
Q_Eff = {work: 0 for work in works}

with open("/home/linjk/study/gpt_for_sum/prorec/sum/test_for_filter3_no_uncertain.json", 'r') as f, open("result/tmp.jsonl", 'a') as fa:
    i = 0
    data = json.load(f)
    data = data[:10] + data[40:50] + data[80:90]

    range_num = 1
    for item in tqdm(data, total=len(data), desc="LLM Eval: "):
        i += 1
        # if i < 196:
        #     continue
        source_code = item['source_code']
        work_score = {}
        for work in works:
            if work == 'comment':
                summary = item['comment']
            else:
                summary = item[f"{work}_sum"]

            test_case = (LLMTestCase(
                input="",
                context=[source_code],
                actual_output=summary
            ))

            retries = 3
            while retries > 0:
                try:
                    Q_Acc_score = 0.0
                    for _ in range(range_num):
                        Accuracy_metric.measure(test_case)
                        Q_Acc_score += Accuracy_metric.score
                        time.sleep(0.5)
                    Q_Acc_score /= float(range_num)
                    Q_Acc[work] += Q_Acc_score
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

            print(f"[{i}] {work}: {Q_Acc_score}, {Q_Cov_score}, {Q_Eff_score}")

            work_score[work] = {
                'summary': summary,
                'score': [Q_Acc_score, Q_Cov_score, Q_Eff_score],
                'reason': [Accuracy_metric.reason, Coverage_metric.reason, Effectiveness_metric.reason]
            }
            
        # continue
        item['work_score'] = work_score
        fa.write(json.dumps(item, indent=4, ensure_ascii=True) + '\n')
        fa.flush()

    num_items = len(data)
    print("\nAverage Scores:")
    for work in works:
        print(f"\n{work}:")
        print(f"  Accuracy: {Q_Acc[work] / num_items:.4f}")
        print(f"  Coverage: {Q_Cov[work] / num_items:.4f}")
        print(f"  Effectiveness: {Q_Eff[work] / num_items:.4f}")
