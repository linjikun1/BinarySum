import time
import json
import openai

class CodeFilter:
    def __init__(self, api_key, model_name, base_url):
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)
        self.model_name = model_name

    def _chat(self, prompt, temperature, is_json=False, max_retries=5, base_delay=2.0):
        """
        API call with automatic retry and exponential backoff.
        """
        response_format = {"type": "json_object"} if is_json else {"type": "text"}
        
        last_exception = None
        for attempt in range(max_retries):
            try:
                start_time = time.time()
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "user", "content": prompt}
                    ],
                    temperature=temperature,
                    response_format=response_format
                )
                end_time = time.time()
                content = response.choices[0].message.content.strip()
                tokens = response.usage.total_tokens if hasattr(response, "usage") else -1
                duration = end_time - start_time
                return content, duration, tokens
            
            except (openai.InternalServerError, 
                    openai.RateLimitError, 
                    openai.APIConnectionError,
                    openai.APITimeoutError) as e:
                last_exception = e
                delay = base_delay * (2 ** attempt)
                print(f"[Retry {attempt + 1}/{max_retries}] API Error: {type(e).__name__}. Waiting {delay:.1f}s...")
                time.sleep(delay)
                continue
            
            except openai.APIError as e:
                last_exception = e
                delay = base_delay * (2 ** attempt)
                print(f"[Retry {attempt + 1}/{max_retries}] API Error: {e}. Waiting {delay:.1f}s...")
                time.sleep(delay)
                continue
        
        raise RuntimeError(f"API call failed after {max_retries} retries: {last_exception}")

    def filter_first(self, probed_srcs, temperature=0.3):
        """
        Stage 1: Basic Junk Filtering based on C semantics.
        Separates "C Logic" from "Data/Noise".
        """
        formatted_fragments = ""
        for idx, fragment in enumerate(probed_srcs):
            formatted_fragments += f"### Candidate {idx}\n```c\n{fragment}\n```\n"

        prompt = f"""
# ROLE
Code Filter. Your job is to separate "C Logic" from "Data/Noise".

# CORE PRINCIPLE
Look through any formatting artifacts (like Python quotes `'...'`, list brackets `[...]`, or escape chars `\\n`). 
Judge the **inner content** based on two simple questions:

1. **Is there C-style Logic?** 
   Does it contain C keywords (`if`, `for`, `return`), function calls, struct access (`->`), or meaningful English comments?
2. **Is it Intelligible?** 
   Can a human programmer recognize a logic flow or intent, even if the code is fragmented?

# DECISION
- **KEEP (is_junk=false)**: If the snippet contains recognizable C logic, API calls, or comments.
- **DROP (is_junk=true)**: If the snippet is primarily:
    - Repetitive data definitions (e.g., `i00='\\n'`, `T(F,...)`).
    - Random symbols, punctuation, or empty noise.
    - Just hex dumps or number lists without control flow.

# INPUT
Candidates:
{formatted_fragments}

# OUTPUT JSON
{{
  "results": [
    {{ "index": <idx>, "is_junk": <bool>, "reason": "<short_reason>" }},
    ...
  ]
}}
"""

        expected_indices = set(range(len(probed_srcs)))
        max_retries = 5
        attempt = 0
        while attempt < max_retries:
            attempt += 1
            try:
                content, _, _ = self._chat(prompt, temperature, is_json=True)
                result = json.loads(content)
                if "results" in result and isinstance(result["results"], list):
                    junk_flags = {}
                    reasons = {}
                    for item in result["results"]:
                        idx = item.get("index")
                        if idx is None:
                            continue
                        junk_flags[idx] = bool(item.get("is_junk", False))
                        reasons[idx] = item.get("reason") or "stage0_junk"
                    if set(junk_flags.keys()) == expected_indices:
                        kept = []
                        junk = []
                        for idx, frag in enumerate(probed_srcs):
                            if junk_flags.get(idx, False):
                                junk.append({"fragment": frag, "reason": reasons.get(idx, "stage0_junk")})
                            else:
                                kept.append(frag)
                        return kept, junk
                    else:
                        missing = expected_indices - set(junk_flags.keys())
                        print(f"Warning: Stage 1 missing indices {missing} on attempt {attempt}. Retrying...")
                        continue
                else:
                    print(f"Warning: Stage 1 returned invalid format on attempt {attempt}. Retrying...")
                    continue
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Warning: Stage 1 failed on attempt {attempt} due to error: {e}. Retrying...")
                continue
        raise RuntimeError("Stage 1 filter failed after 5 attempts — no LLM-backed judgments obtained.")

    def filter_second(self, code, probed_srcs, temperature=1.0):
        """
        Stage 2: Advanced Semantic Matching.
        1. Evaluate Decompiled Code Features (has_strong_features).
        2. Classify candidates as Source Match or Domain Match.
        """
        formatted_fragments = ""
        for idx, fragment in enumerate(probed_srcs):
            formatted_fragments += f"### Candidate {idx}\n```c\n{fragment}\n```\n"

        prompt = f"""
# ROLE
Code Analyst. Analyze Decompiled Code quality and compare with Candidates.

# INPUT
- Decompiled Function (Ground Truth):
{code}
- Candidate Snippets:
{formatted_fragments}

# TASK
Perform a two-step analysis:

**Step 1: Evaluate Decompiled Code Features**
Determine if the Decompiled Function contains **High-Semantic Anchors**.
- **has_strong_features = true** IF it contains:
    - Distinct C-style string literals (e.g., "Invalid XML", "/proc/cpuinfo").
    - Specific, recognizable C-style API calls (e.g., `xmlNodeGet`, `skb_push`, `PyArg_Parse`).
    - Complex, unique control flow structures specific to a C-style domain.
    - **ACTION**: You MUST extract these specific keywords/strings into the `extracted_features` list.

- **has_strong_features = false** IF it is Generic:
    - Only contains math/logic (loops, shifts, adds).
    - Only calls generic functions like `malloc`, `free`, `memcpy`.
    - No meaningful strings or domain-specific types, only all decompiled symbols (sub_/FUN_/0x...).
    - **ACTION**: Leave `extracted_features` empty.

**Step 2: Classify Candidates (Only if has_strong_features is true)**
Compare candidates against the Decompiled Function.
- **is_source_match**: EXACT logic/constant match (The "Real" Source).
- **is_domain_match**: 
    - The candidate shares **SPECIFIC ANCHORS** from the `extracted_features` list.
    - **CRITERIA**: It MUST contain at least one of the specific strings, constants, or API names identified in Step 1.
    - **NEGATIVE RULE**: If the candidate only looks similar in style but lacks the specific extracted features, it is NOT a match.

# OUTPUT JSON
{{
    "has_strong_features": <bool>,
    "extracted_features": ["<feature_1>", "<feature_2>", ...],
    "results": [
        {{ 
            "index": 0, 
            "is_source_match": <bool>, 
            "is_domain_match": <bool>, 
            "evidence": "<keyword or reason>"
        }},
        ...
    ]
}}
"""

        max_retries = 3
        for _ in range(max_retries):
            content, _, _ = self._chat(prompt, temperature, is_json=True)
            try:
                res = json.loads(content)
                if "results" in res:
                    return res
            except:
                continue
        
        return {"has_strong_features": False, "results": []}
