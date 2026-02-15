import sys
import os
import time

# Ensure we can import from the vendored directory
current_dir = os.path.dirname(os.path.abspath(__file__))
vendor_path = os.path.join(current_dir, "deepeval_internal")
if vendor_path not in sys.path:
    sys.path.append(vendor_path)

try:
    from deepeval.test_case import LLMTestCase, LLMTestCaseParams
    from deepeval.metrics import GEval
    from deepeval.models.llms.openai_model import GPTModel
except ImportError as e:
    raise ImportError(f"Failed to import deepeval from {vendor_path}. Please ensure you have copied the deepeval source code correctly. Error: {e}")


class LLMEvalRunner:
    def __init__(self, api_key="sk-rMbghGaVULY5UMOKdJa2VfX7dPTfY4yNq2wgeFijGo4y5j3Y", base_url="https://aizex.top/v1", model_name="gpt-4o", temperature=0.1):
        """
        Initialize the LLM Evaluator with custom GEval metrics.
        """
        self.model = GPTModel(
            model=model_name,
            _openai_api_key=api_key,
            base_url=base_url,
            temperature=temperature
        )
        self._init_metrics()

    def _init_metrics(self):
        # Accuracy (Precision)
        self.accuracy_metric = GEval(
            name="Accuracy (Precision)",
            criteria="Accuracy (Precision): ",
            evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
            evaluation_steps=[
                # Step 1: Identify
                """Extract fact-based claims atomically from the SUMMARY into a temporary CLAIM_LIST = [claim1, claim2, ...] and compare each claim with SOURCE_CODE to tag it as:
                    - **[ACCURATE]**: if it's a highly specific and verifiable claim that states domain-semantic behavior/contract of this function (GOLD), or it's correct but generic/boilerplate, low-info, or non-distinguishing statements (SAFE).
                    - **[INACCURATE]**: if it targets source code semantics but contradictorily (FATAL), or it doesn't target code at all (NOISE).""",
                
                # Step 2: Calculate Precision
                """Calculate the proportion of [ACCURATE] in the CLAIM_LIST:
                    - **Score 1-3**: only <50% of the claims are ACCURATE.
                    - **Score 4-7**: 50-80% of the claims are ACCURATE. Mixed reliability.
                    - **Score 8-10**: >80% of the claims are ACCURATE. High purity/precision."""
            ],
            model=self.model
        )

        # Coverage (Recall)
        self.coverage_metric = GEval(
            name="Coverage (Recall)",
            criteria="Coverage (Recall): Evaluate how well the [ACCURATE] claims cover the critical semantics of the Source Code.",
            evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
            evaluation_steps=[
                # Step 1: Identify (Same as Accuracy)
                """Extract fact-based claims atomically from the SUMMARY into a temporary CLAIM_LIST = [claim1, claim2, ...] and compare each claim with SOURCE_CODE to tag it as:
                    - **[ACCURATE]**: if it's a highly specific and verifiable claim that states domain-semantic behavior/contract of this function (GOLD), or it's correct but generic/boilerplate, low-info, or non-distinguishing statements (SAFE).
                    - **[INACCURATE]**: if it targets source code semantics but contradictorily (FATAL), or it doesn't target code at all (NOISE).""",

                # Step 2: Extract core primary purpose
                """Derive one CORE_PRIMARY_PURPOSE from SOURCE_CODE:
                    - One sentence of the core domain operation/effect with specific domain wording (like "perform NFS3 inode link into directory with name").
                    - Must be concrete enough to distinguish from boilerplate (not just generic helper/RPC/status phrasing).""",

                # Step 3: Judge coverage and Score
                """Using only [ACCURATE] claims from CLAIM_LIST, judge if SUMMARY covers CORE_PRIMARY_PURPOSE:
                    - "Covered" only when an [ACCURATE] claim states the same domain action/effect with similar specificity; vague wording like "performs an operation" does not count.
                    - Then gauge coverage of other behavior-critical semantics in SOURCE_CODE (I/O, side effects, errors, branches/edge cases, constants/configs, external interactions).

                Scoring:
                    - **1-3**: Core not covered (1 almost no secondary info; 2 a little but very incomplete; 3 several secondary points yet core missing).
                    - **4-6**: Core covered, secondary weak (4 very thin; 5 some; 6 decent but still incomplete).
                    - **7-10**: Core covered, broad secondary (7 multiple key points; 8 most key points; 9-10 near-complete incl. branches/errors/side effects/constants)."""
            ],
            model=self.model
        )

        # Effectiveness (Net Benefit)
        self.effectiveness_metric = GEval(
            name="Effectiveness (Net Benefit)",
            criteria="Effectiveness (Net Benefit): Evaluate the helpfulness for reverse engineering based on Specificity and Insight depth. Penalize generic descriptions.",
            evaluation_params=[LLMTestCaseParams.CONTEXT, LLMTestCaseParams.ACTUAL_OUTPUT],
            evaluation_steps=[
                # Step 1: Identify
                """Extract fact-based claims atomically from the SUMMARY into a temporary CLAIM_LIST = [claim1, claim2, ...] and compare each claim with SOURCE_CODE to tag it as:
                    - **[ACCURATE]**: if it's a highly specific and verifiable claim that states domain-semantic behavior/contract of this function (GOLD), or it's correct but generic/boilerplate, low-info, or non-distinguishing statements (SAFE).
                    - **[INACCURATE]**: if it targets source code semantics but contradictorily (FATAL), or it doesn't target code at all (NOISE).""",
                
                # Step 2: Negative Impact Analysis
                """Assess negative impact from [INACCURATE] claims:
                    - If there is any FATAL about the PRIMARY PURPOSE (core domain action/effect, WHAT) / key I/O / key side effect, the score MUST be 1-3.
                    - Else if NOISE is overwhelming (e.g., it's much more than ACCURATE claims), the score MUST be at most 4-6.
                    - Briefly state what the worst failure mode is (FATAL vs NOISE).""",
                
                # Step 3: Positive Gain Analysis
                """Assess positive gain from [ACCURATE] claims:
                    - **Low Gain**: Generic and broad SAFE claims with low-info that provides little insight.
                    - **High Gain**: Specific and detailed GOLD claims that saves the engineer time.""",
                
                # Step 4: Net Benefit Score
                """Assign a score based on Net Benefit:
                    - **Score 1-3 (Negative/Zero Benefit)**: 1 severe FATAL on core/key I/O/side effect (unusable); 2 FATAL present but narrower (still untrustworthy); 3 no FATAL, but noise overwhelms accuracy (net benefit ≈ 0).
                    - **Score 4-6 (Low Net Benefit, NO FATAL)**: 4 no FATAL, noise noticeable, gain very low; 5 noise/gain mediocre, limited info; 6 noise acceptable, gain still weak.
                    - **Score 7-10 (High Net Benefit, GOLD force multiplier present)**: 7 few specific gains, net positive; 8 most key points specific, low noise; 9-10 broad high gain,, big acceleration, noise negligible."""
            ],
            model=self.model
        )

    def evaluate_single(self, summary, source_code, retries=3):
        """
        Evaluate a single summary against source code.
        Returns a dictionary with scores and reasons.
        """
        test_case = LLMTestCase(
            input="",
            context=[source_code],
            actual_output=summary
        )

        results = {}
        metrics = [
            ("accuracy", self.accuracy_metric),
            ("coverage", self.coverage_metric),
            ("effectiveness", self.effectiveness_metric)
        ]

        for name, metric in metrics:
            score = 0.0
            reason = "Evaluation failed"
            current_retries = retries
            
            while current_retries > 0:
                try:
                    metric.measure(test_case)
                    score = metric.score
                    reason = metric.reason
                    break
                except Exception as e:
                    # print(f"Error calculating {name}: {e}")
                    current_retries -= 1
                    time.sleep(1)
            
            results[name] = score
            results[f"{name}_reason"] = reason

        return results

if __name__ == "__main__":
    # Simple test run
    runner = LLMEvalRunner()
    sample_code = "void func() { printf('Hello'); }"
    sample_summary = "The function prints Hello."
    print("Running test evaluation...")
    res = runner.evaluate_single(sample_summary, sample_code)
    print(res)
