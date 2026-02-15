import time
import hashlib
import json
import itertools
from typing import List
import openai

class OpenAISummarizer:
    def __init__(self, api_key, model_name, base_url):
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)
        self.model_name = model_name

    def _chat(self, prompt, temperature, is_json=False):
        start_time = time.time()
        response_format = {"type": "json_object"} if is_json else {"type": "text"}
        
        try:
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
        except Exception as e:
            print(f"Error in chat completion: {e}")
            return "", 0, 0
    
    def _get_block_hash(self, block_content: str) -> str:
        """Generate unique fingerprint for basic block content"""
        return hashlib.md5(block_content.strip().encode()).hexdigest()[:8]
    
    def _calculate_context_cost(self, path_order: List[List[str]]) -> int:
        """Calculate context cost (Equation 3.1)"""
        seen_hashes = set()
        cost = 0
        REF_COST = 10
        
        for path in path_order:
            for block_content in path:
                h = self._get_block_hash(block_content)
                if h in seen_hashes:
                    cost += REF_COST
                else:
                    cost += len(block_content)
                    seen_hashes.add(h)
        return cost    

    def _optimize_path_order(self, paths: List[List[str]]) -> List[int]:
        """Find optimal path order using permutations (Section 3.4)"""
        indices = list(range(len(paths)))
        # For small K (e.g. 3), permutations are cheap
        permutations = list(itertools.permutations(indices))
        
        best_perm = None
        min_cost = float('inf')
        
        for perm in permutations:
            current_order_paths = [paths[i] for i in perm]
            cost = self._calculate_context_cost(current_order_paths)
            
            if cost < min_cost:
                min_cost = cost
                best_perm = perm
                
        return list(best_perm) if best_perm else indices

    def _construct_compressed_prompt(self, paths: List[List[str]], sorted_indices: List[int]) -> str:
        """Construct compressed prompt context using references"""
        context_lines = []
        seen_blocks = {} # map hash -> block_id
        
        context_lines.append("Here is the linear execution trace of the function, decomposed into paths.")
        context_lines.append("NOTE: Repeating basic blocks are replaced by REFERENCES to save space.\n")

        for order_idx, original_idx in enumerate(sorted_indices):
            path_blocks = paths[original_idx]
            path_label = f"Path {original_idx + 1}"
            context_lines.append(f"--- {path_label} ---")
            
            for b_idx, block_content in enumerate(path_blocks):
                b_hash = self._get_block_hash(block_content)
                
                if b_hash in seen_blocks:
                    ref_id = seen_blocks[b_hash]
                    context_lines.append(f"[Block {b_idx}]: Same as {ref_id}")
                else:
                    unique_id = f"REF_{original_idx}_{b_idx}"
                    seen_blocks[b_hash] = unique_id
                    context_lines.append(f"[Block {b_idx}] (ID: {unique_id}):")
                    context_lines.append(block_content.strip())
                    context_lines.append("") 
            
            context_lines.append("")

        return "\n".join(context_lines)

    def generate_hpss_summary(self, paths: List[List[str]], temperature=0.5):
        """
        Hierarchical Path-Sensitive Summarization (HPSS)
        """
        if not paths:
            return {"error": "No paths provided"}

        # 1. Compress context and reorder
        sorted_indices = self._optimize_path_order(paths)
        compressed_context = self._construct_compressed_prompt(paths, sorted_indices)
        
        # 2. Construct Prompt
        prompt = f"""
You are an expert Reverse Engineer. Perform a Hierarchical Path-Sensitive Summarization (HPSS) based on the execution paths below.

{compressed_context}

Follow this 2-step reasoning process strictly:

**Step 1: Path-Level Semantic Analysis**
For EACH path (Path 1, Path 2, ...), analyze the assembly code.
- If a block is a REFERENCE, look up its content from where it was first defined.
- Describe the specific execution logic of that path (e.g., "Handles error case when input is null", "Performs core encryption loop").
- Focus on register data flow and control logic.

**Step 2: Global Function Summarization**
Synthesize the insights from Step 1 into a single, comprehensive summary of the function.
- Aggregate the logic: How do these paths work together?
- Identify the main purpose (e.g., "Validates input and computes CRC32 hash").
- Output a single, concise sentence (max 30 words).

Response Format (JSON):
{{
    "path_summaries": {{
        "Path 1": "...",
        "Path 2": "..."
    }},
    "global_summary": "..."
}}
"""
        # 3. Call LLM
        content, duration, tokens = self._chat(prompt, temperature, is_json=True)
        
        try:
            result = json.loads(content)
            return {
                "path_summaries": result.get("path_summaries", {}),
                "global_summary": result.get("global_summary", ""),
                "perf": {"duration": duration, "tokens": tokens}
            }
        except json.JSONDecodeError:
            return {"error": "Failed to parse JSON", "raw_content": content}
