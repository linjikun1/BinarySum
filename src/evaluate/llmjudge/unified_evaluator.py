import sys
import os
import time
import json
import re

src_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from config import get_openai_config
from openai import OpenAI


SYSTEM_PROMPT = """You are an expert reverse engineering evaluator. \
Your task is to evaluate binary function summaries against their source code ground truth.
You will follow a structured 3-step evaluation protocol. Always output valid JSON."""


# ------------------------------------------------------------------
# Prompt templates
# ------------------------------------------------------------------

STEP1_SOURCE_SEMANTICS = """\
## Step 1: Extract Core Source Semantics

Analyze the SOURCE_CODE below and extract its core semantics.

SOURCE_CODE:
```
{source_code}
```

Output JSON with exactly these fields:
{{
  "core_primary_purpose": "<one sentence: the core domain operation/effect with specific domain wording>",
  "critical_semantics": ["<semantic point 1>", "<semantic point 2>", ...]
}}

Rules for core_primary_purpose:
- Must use concrete domain terms (e.g., "perform NFS3 inode link", "resize GMP multiprecision buffer")
- Must distinguish this function from boilerplate; avoid vague wording like "performs an operation"

Rules for critical_semantics:
- Include: key I/O contracts, side effects, error paths, important constants/thresholds, external interactions
- 3-8 items, each one concrete and verifiable from the code"""


# Step 2: one call, N summaries — each gets its own claim_list
STEP2_MULTI_CLAIMS = """\
## Step 2: Extract and Tag Claims for Each Summary

SOURCE_CODE (for verification):
```
{source_code}
```

For each summary below, extract atomic fact-based claims and tag each claim as:
- [ACCURATE/GOLD]: highly specific, verifiable, states domain-semantic behavior — high information value
- [ACCURATE/SAFE]: correct but generic/boilerplate/low-info, non-distinguishing
- [INACCURATE/FATAL]: targets source code semantics but is contradictory or wrong
- [INACCURATE/NOISE]: doesn't correspond to any real behavior in the code

Summaries to evaluate:
{summaries_block}

Output JSON — one key per summary label:
{{
  "<label>": {{
    "claim_list": [
      {{"claim": "<claim text>", "tag": "<ACCURATE/GOLD|ACCURATE/SAFE|INACCURATE/FATAL|INACCURATE/NOISE>"}},
      ...
    ]
  }},
  ...
}}"""


# Step 3: one call, N summaries — each gets its own three scores
STEP3_MULTI_SCORE = """\
## Step 3: Score Three Metrics for Each Summary

SOURCE_CODE:
```
{source_code}
```

Shared Core Source Semantics (from Step 1):
- core_primary_purpose: {core_primary_purpose}
- critical_semantics: {critical_semantics}

Tagged Claims per Summary (from Step 2):
{claims_block}

For EACH summary, assign integer scores 1-10 for three metrics:

### Accuracy (Precision)
Proportion of [ACCURATE] claims:
- 1-3: <50% accurate
- 4-7: 50-80% accurate
- 8-10: >80% accurate

### Coverage (Recall)
Using only [ACCURATE] claims, coverage of core_primary_purpose + critical_semantics:
- 1-3: core_primary_purpose NOT covered
- 4-6: core_primary_purpose covered, secondary weak
- 7-10: core_primary_purpose covered + broad secondary semantics

### Effectiveness (Net Benefit for reverse engineer)
FATAL penalty first, then weigh GOLD gain vs NOISE drag:
- 1-3: FATAL present on core/key I/O/side-effect
- 4-6: No FATAL, limited gain
- 7-10: No FATAL, GOLD claims deliver concrete insight

Output JSON — one key per summary label:
{{
  "<label>": {{
    "accuracy": <int 1-10>,
    "accuracy_reason": "<brief>",
    "coverage": <int 1-10>,
    "coverage_reason": "<brief>",
    "effectiveness": <int 1-10>,
    "effectiveness_reason": "<brief>"
  }},
  ...
}}"""


# ------------------------------------------------------------------
# Unified Evaluator
# ------------------------------------------------------------------

class UnifiedLLMJudgeEvaluator:
    """
    Unified LLM-as-a-Judge evaluator with a shared 3-step pipeline.

    Improvements over the original GEval-based evaluator:

    1. Shared Step 1: SOURCE_CODE semantics (core_primary_purpose +
       critical_semantics) are extracted ONCE per source_code and reused
       across all metrics and all summaries — eliminates the inconsistent
       reference baseline that arises from independent GEval calls.

    2. Multi-summary batching: Steps 2 and 3 each make a SINGLE API call
       regardless of how many summaries are being evaluated. This means
       evaluating N summaries costs exactly 3 API calls total (not 3*N).

    3. Consistent scoring context: Because all summaries are scored in the
       same Step 3 call with the same source semantics, the judge's internal
       reference is guaranteed to be identical for every summary.

    API:
        evaluate_single(summary, source_code)  -> scores dict
        evaluate_multi({"M1": "...", "M2": "..."}, source_code) -> {label: scores, ...}
    """

    def __init__(self, profile=None, api_key=None, base_url=None,
                 model_name=None, temperature=0.1, use_logprobs=False):
        """
        Args:
            use_logprobs: If True, Step 3 scoring uses token-level logprobs for
                          probability-weighted scores (more stable, finer-grained).
                          Requires the model/API to support logprobs.
                          Falls back to integer scoring if logprobs unavailable.
        """
        if profile:
            config = get_openai_config(profile)
            api_key = config["api_key"]
            base_url = config["base_url"]
            model_name = config["model_name"]
        else:
            api_key = api_key or os.environ.get("OPENAI_API_KEY", "YOUR_API_KEY_HERE")
            base_url = base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
            model_name = model_name or os.environ.get("MODEL_NAME", "gpt-4o")

        if api_key == "YOUR_API_KEY_HERE":
            print("Warning: No API key configured.")

        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model_name = model_name
        self.temperature = temperature
        self.use_logprobs = use_logprobs

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call(self, prompt: str, retries: int = 3) -> str:
        """Single LLM call with exponential-backoff retry. Returns raw text."""
        for attempt in range(retries):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model_name,
                    temperature=self.temperature,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": prompt},
                    ],
                )
                return resp.choices[0].message.content.strip()
            except Exception as e:
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    raise e
        return ""

    def _call_with_logprobs(self, prompt: str, retries: int = 3):
        """LLM call requesting logprobs on output tokens. Returns (text, logprobs_list).

        logprobs_list is a list of dicts per output token:
            [{"token": "7", "logprob": -0.12, "top_logprobs": [{"token": "7", "logprob": ...}, ...]}, ...]
        Returns (text, None) if logprobs are not available.
        """
        for attempt in range(retries):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model_name,
                    temperature=self.temperature,
                    logprobs=True,
                    top_logprobs=10,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": prompt},
                    ],
                )
                text = resp.choices[0].message.content.strip()
                lp = resp.choices[0].logprobs
                token_logprobs = lp.content if lp else None
                return text, token_logprobs
            except Exception as e:
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    raise e
        return "", None

    def _parse_json(self, text: str) -> dict:
        """Extract the first JSON object from model output, stripping <think> if present."""
        text = re.sub(r'<think>[\s\S]*?</think>', '', text, flags=re.IGNORECASE).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        match = re.search(r'\{[\s\S]*\}', text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return {}

    def _normalize(self, score) -> float:
        """Normalize integer 1-10 score to 0.0–1.0."""
        try:
            return round((int(score) - 1) / 9.0, 4)
        except (ValueError, TypeError):
            return 0.0

    def _weighted_score_from_logprobs(self, token_logprobs) -> dict:
        """Extract probability-weighted scores for each metric from logprobs.

        Strategy: scan output tokens for digit tokens (1-10).  For each
        score-bearing position, collect the full top_logprobs distribution over
        digit tokens, compute softmax over those, and return the weighted
        expected value normalised to [0, 1].

        Returns a dict mapping position_index -> weighted_score (0-1).
        Positions correspond to the order score digits appear in the output.
        """
        import math

        DIGIT_TOKENS = {str(d) for d in range(1, 11)}  # '1'..'10'

        weighted_scores = []  # list of (position, weighted_score)

        if not token_logprobs:
            return {}

        for tok_info in token_logprobs:
            # tok_info is a ChatCompletionTokenLogprob object
            token = tok_info.token.strip()
            if token not in DIGIT_TOKENS:
                continue

            top = tok_info.top_logprobs  # list of TopLogprob
            if not top:
                # Fallback: use the token itself
                score = int(token)
                weighted_scores.append(self._normalize(score))
                continue

            # Collect logprobs for all digit tokens in the top distribution
            digit_logprobs = {}
            for entry in top:
                t = entry.token.strip()
                if t in DIGIT_TOKENS:
                    digit_logprobs[t] = entry.logprob

            if not digit_logprobs:
                weighted_scores.append(self._normalize(int(token)))
                continue

            # Convert logprobs to probabilities and compute weighted expectation
            # Renormalise over digit tokens only (ignore non-digit mass)
            max_lp = max(digit_logprobs.values())
            probs = {t: math.exp(lp - max_lp) for t, lp in digit_logprobs.items()}
            total = sum(probs.values())
            expected = sum(int(t) * p / total for t, p in probs.items())
            weighted_scores.append(self._normalize(expected))

        return weighted_scores  # list of normalised scores in appearance order

    # ------------------------------------------------------------------
    # Step 1
    # ------------------------------------------------------------------

    def _step1_source_semantics(self, source_code: str) -> dict:
        """
        Step 1 — Extract core semantics from source_code.
        Runs once; result is shared across all summaries.
        """
        prompt = STEP1_SOURCE_SEMANTICS.format(source_code=source_code)
        raw = self._call(prompt)
        result = self._parse_json(raw)
        result.setdefault("core_primary_purpose", "")
        result.setdefault("critical_semantics", [])
        return result

    # ------------------------------------------------------------------
    # Step 2 (multi-summary, single call)
    # ------------------------------------------------------------------

    def _step2_multi_claims(self, summaries: dict, source_code: str) -> dict:
        """
        Step 2 — Extract and tag claims for ALL summaries in one API call.

        Args:
            summaries: {label: summary_text, ...}
        Returns:
            {label: [{"claim": ..., "tag": ...}, ...], ...}
        """
        summaries_block = "\n\n".join(
            f'[{label}]:\n"""\n{text}\n"""'
            for label, text in summaries.items()
        )
        prompt = STEP2_MULTI_CLAIMS.format(
            source_code=source_code,
            summaries_block=summaries_block,
        )
        raw = self._call(prompt)
        result = self._parse_json(raw)
        # Normalise: each value should have a "claim_list" key
        claims = {}
        for label in summaries:
            entry = result.get(label, {})
            if isinstance(entry, dict):
                claims[label] = entry.get("claim_list", [])
            else:
                claims[label] = []
        return claims

    # ------------------------------------------------------------------
    # Step 3 (multi-summary, single call)
    # ------------------------------------------------------------------

    def _step3_multi_score(self, source_code: str, source_semantics: dict,
                           claims_per_label: dict) -> dict:
        """
        Step 3 — Score all summaries in one API call.

        Args:
            claims_per_label: {label: claim_list, ...}
        Returns:
            {label: {"accuracy": float, ..., "accuracy_reason": str, ...}, ...}
        """
        claims_block_parts = []
        for label, claim_list in claims_per_label.items():
            lines = "\n".join(
                f"    [{c.get('tag', '?')}] {c.get('claim', '')}"
                for c in claim_list
            ) if claim_list else "    (no claims extracted)"
            claims_block_parts.append(f"[{label}]:\n{lines}")
        claims_block = "\n\n".join(claims_block_parts)

        prompt = STEP3_MULTI_SCORE.format(
            source_code=source_code,
            core_primary_purpose=source_semantics.get("core_primary_purpose", ""),
            critical_semantics=json.dumps(
                source_semantics.get("critical_semantics", []), ensure_ascii=False
            ),
            claims_block=claims_block,
        )
        if self.use_logprobs:
            raw, token_logprobs = self._call_with_logprobs(prompt)
        else:
            raw = self._call(prompt)
            token_logprobs = None

        result = self._parse_json(raw)

        # If logprobs available, extract probability-weighted scores
        # weighted_list contains one float per digit token found in output,
        # in the order they appear — expected order: for each label:
        #   accuracy, coverage, effectiveness  (3 scores × N labels)
        weighted_list = None
        if token_logprobs:
            wl = self._weighted_score_from_logprobs(token_logprobs)
            if wl and len(wl) == 3 * len(claims_per_label):
                weighted_list = wl  # only use if count matches exactly

        scores = {}
        labels = list(claims_per_label.keys())
        for idx, label in enumerate(labels):
            entry = result.get(label, {})
            scores[label] = {}
            for m_idx, metric in enumerate(("accuracy", "coverage", "effectiveness")):
                if weighted_list is not None:
                    # Use probability-weighted score from logprobs
                    scores[label][metric] = round(weighted_list[idx * 3 + m_idx], 4)
                else:
                    # Fallback: parse integer from JSON and normalise
                    scores[label][metric] = self._normalize(entry.get(metric, 5))
                scores[label][f"{metric}_reason"] = entry.get(f"{metric}_reason", "")
        return scores

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_single(self, summary: str, source_code: str) -> dict:
        """
        Evaluate one summary. Internally uses evaluate_multi with a single entry.
        Returns a flat scores dict (same shape as original evaluator.py).
        """
        results = self.evaluate_multi({"summary": summary}, source_code)
        scores = results["summary"]
        scores["_source_semantics"] = results["_source_semantics"]
        scores["_claims"] = results["_claims"]["summary"]
        return scores

    def evaluate_multi(self, summaries: dict, source_code: str) -> dict:
        """
        Evaluate multiple summaries against the same source_code in 3 API calls total.

        Args:
            summaries: {"M1": "...", "M2": "...", ...}
            source_code: ground-truth source code string

        Returns:
            {
              "M1": {"accuracy": 0.61, "coverage": 0.55, "effectiveness": 0.67,
                     "accuracy_reason": "...", ...},
              "M2": {...},
              "_source_semantics": {"core_primary_purpose": "...", "critical_semantics": [...]},
              "_claims": {"M1": [{claim, tag}, ...], "M2": [...]}
            }
        """
        # Step 1: one call — source semantics (shared)
        source_semantics = self._step1_source_semantics(source_code)

        # Step 2: one call — claims for all summaries
        claims_per_label = self._step2_multi_claims(summaries, source_code)

        # Step 3: one call — scores for all summaries
        scores_per_label = self._step3_multi_score(source_code, source_semantics, claims_per_label)

        results = {
            "_source_semantics": source_semantics,
            "_claims": claims_per_label,
        }
        for label in summaries:
            results[label] = scores_per_label.get(label, {})

        return results


# ------------------------------------------------------------------
# Quick demo
# ------------------------------------------------------------------

if __name__ == "__main__":
    evaluator = UnifiedLLMJudgeEvaluator(profile="default")

    source_code = """
static int pci_pm_poweroff(struct device *dev)
{
    struct pci_dev *pci_dev = to_pci_dev(dev);
    const struct dev_pm_ops *pm = dev->driver ? dev->driver->pm : NULL;

    if (pci_has_legacy_pm_support(pci_dev))
        return pci_legacy_suspend(dev, PMSG_HIBERNATE);

    if (!pm) {
        pci_pm_default_suspend(pci_dev);
        goto Fixup;
    }

    pci_dev->state_saved = false;
    if (pm->poweroff) {
        int error = pm->poweroff(dev);
        if (error)
            return error;
    }

Fixup:
    pci_fixup_device(pci_fix_bus_pm, pci_dev);
    return 0;
}
"""

    summaries = {
        "M1": "Manages PCI device power-off by checking conditions, invoking device-specific callbacks, and performing fallback shutdown if no suitable handler is available.",
        "M3": "Shuts down a PCI device by invoking its power-management callback if present, otherwise performs local cleanup and power-off operations.",
    }

    print("=== evaluate_multi demo (3 API calls total) ===\n")
    results = evaluator.evaluate_multi(summaries, source_code)

    ss = results["_source_semantics"]
    print("Shared source semantics (Step 1):")
    print(f"  core_primary_purpose: {ss['core_primary_purpose']}")
    print(f"  critical_semantics:")
    for s in ss["critical_semantics"]:
        print(f"    - {s}")

    for label in summaries:
        r = results[label]
        print(f"\n[{label}]  summary: {summaries[label][:60]}...")
        print(f"  accuracy      = {r.get('accuracy', 0):.4f}  | {r.get('accuracy_reason','')}")
        print(f"  coverage      = {r.get('coverage', 0):.4f}  | {r.get('coverage_reason','')}")
        print(f"  effectiveness = {r.get('effectiveness', 0):.4f}  | {r.get('effectiveness_reason','')}")
        print(f"  claims (Step 2):")
        for c in results["_claims"].get(label, []):
            print(f"    [{c.get('tag','?')}] {c.get('claim','')}")
