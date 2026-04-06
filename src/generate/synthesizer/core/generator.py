import openai
import time
from typing import Optional, List


class OpenAIFinalSummarizer:
    def __init__(self, api_key, model_name, base_url, timeout=60, max_retries=3, retry_delay=5):
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)
        self.model_name = model_name
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def _strip_thinking(self, text: str) -> str:
        """Remove <think>...</think> reasoning blocks from model output."""
        import re
        # Remove <think>...</think> blocks (including multiline)
        text = re.sub(r'<think>[\s\S]*?</think>', '', text, flags=re.IGNORECASE)
        return text.strip()

    def _chat(self, prompt, temperature=0.1):
        for attempt in range(self.max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": "You are an experienced binary reverse engineer."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=temperature
                )
                content = response.choices[0].message.content.strip()
                return self._strip_thinking(content)
            except openai.APIConnectionError as e:
                print(f"Connection error (attempt {attempt+1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
            except openai.RateLimitError as e:
                print(f"Rate limit error (attempt {attempt+1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * 2)
            except Exception as e:
                print(f"Error in generation: {e}")
                return ""
        print(f"Failed after {self.max_retries} retries")
        return ""

    def _build_prompt_m1(self, decompiled_code):
        """M1: Baseline - decompiled code only."""
        intro = "You are given a stripped and decompiled C function."
        code_section = f"""Here is the decompiled C function:
                            ```C
                            {decompiled_code}
                            ```
                        """
        task = "Your task is to generate a concise, one-sentence summary of no more than 25 words that summarizes the function's purpose."
        requirements = """Strict requirements to output:
- Make your best definitive interpretation based on code evidence, avoid placeholders and generic descriptions WHEN strong and distinct C-source-style features (explicit string literals or known API calls) are present in the decompiled code.
- DO NOT use uncertain words like "possible", "seems", "likely", "appears", "may", "might", "probably". Prohibiting the output of decompiled symbols (sub_/FUN_/0x...).
- Example of ideal answer: "Sends a byte to the device via PS/2 protocol and waits for an answer or timeout". Bad answer: "This function possibly performs specified operations on data"."""
        return "\n\n".join([intro, code_section, task, requirements])

    def _build_prompt_m2(self, decompiled_code, cfg_description):
        """M2: + HPSS (CFG description)."""
        intro = "You are given a stripped and decompiled C function, and the corresponding summary which interpreted from the control flow graph of the function."
        code_section = f"""Here is the decompiled C function:
                            ```C
                            {decompiled_code}
                            ```
                        """
        cfg_section = f"""Here is the CFG-based behavioral description of this function: {cfg_description}

Note: This description is derived from binary control flow analysis and captures low-level execution behavior (register operations, memory accesses, control flow branches, named calls if any). Use it to complement the decompiled code — it may reveal execution paths or low-level patterns not obvious from decompilation alone."""
        task = """Your task is to:
                        1. Use the decompiled function as the base and the CFG summary to enhance understanding.
                        2. Generate a concise, one-sentence summary of no more than 25 words that summarizes function's purpose.
                    """
        requirements = """Strict requirements to output:
- Make your best definitive interpretation based on code evidence, avoid placeholders and generic descriptions WHEN strong and distinct C-source-style features (explicit string literals or known API calls) are present in the decompiled code.
- DO NOT use uncertain words like "possible", "seems", "likely", "appears", "may", "might", "probably". Prohibiting the output of decompiled symbols (sub_/FUN_/0x...).
- Example of ideal answer: "Sends a byte to the device via PS/2 protocol and waits for an answer or timeout". Bad answer: "This function possibly performs specified operations on data"."""
        return "\n\n".join([intro, code_section, cfg_section, task, requirements])

    def _build_prompt_m3(self, decompiled_code, cfg_description, snippets_text):
        """M3: + HPSS + CCR (raw retrieved source snippets, no SDN filtering)."""
        intro = "You are given a stripped and decompiled C function, a CFG-based behavioral description, and some potentially related source snippets for reference."
        code_section = f"""Here is the decompiled C function:
                            ```C
                            {decompiled_code}
                            ```
                        """
        cfg_section = f"""Here is the CFG-based behavioral description of this function: {cfg_description}

Note: This description is derived from binary control flow analysis and captures low-level execution behavior (register operations, memory accesses, control flow branches, named calls if any). Use it to complement the decompiled code — it may reveal execution paths or low-level patterns not obvious from decompilation alone.""" if cfg_description else ""
        snippets_section = f"""Here are some potentially related source code snippets retrieved for reference:

{snippets_text}"""
        task = """Your task is to:
                        1. Use the decompiled function and CFG description as the primary basis, and use the source snippets to enhance understanding.
                        2. Generate a concise, one-sentence summary of no more than 25 words that summarizes the function's purpose.
                    """
        requirements = """Strict requirements to output:
- Make your best definitive interpretation based on code evidence, avoid placeholders and generic descriptions WHEN strong and distinct C-source-style features (explicit string literals or known API calls) are present in the decompiled code.
- DO NOT use uncertain words like "possible", "seems", "likely", "appears", "may", "might", "probably". Prohibiting the output of decompiled symbols (sub_/FUN_/0x...).
- Example of ideal answer: "Sends a byte to the device via PS/2 protocol and waits for an answer or timeout". Bad answer: "This function possibly performs specified operations on data"."""
        parts = [intro, code_section]
        if cfg_section:
            parts.append(cfg_section)
        parts += [snippets_section, task, requirements]
        return "\n\n".join(parts)

    def _build_prompt_m4(self, decompiled_code, cfg_description, snippets_text):
        """M4: + HPSS + CCR + SDN (filtered and tagged source snippets)."""
        intro = "You are given a stripped and decompiled C function, a CFG-based behavioral description, and some potentially related source snippets for context."
        code_section = f"""Here is the decompiled C function:
                            ```C
                            {decompiled_code}
                            ```
                        """
        cfg_section = f"""Here is the CFG-based behavioral description of this function: {cfg_description}

Note: This description is derived from binary control flow analysis and captures low-level execution behavior (register operations, memory accesses, control flow branches, named calls if any). Use it to complement the decompiled code — it may reveal execution paths or low-level patterns not obvious from decompilation alone.""" if cfg_description else ""
        snippets_section = f"""Here are some potentially related source code snippets retrieved for reference:

{snippets_text}"""
        task = """Your task is to:
                        1. Use the decompiled function and CFG description as the primary basis.
                        2. Use snippets according to their confidence tags:
                           - `[HIGH CONFIDENCE SOURCE]`: trust its logic and intent significantly, provided it doesn't contradict the decompiled code.
                           - `[CONTEXT REFERENCE]`: use for naming/domain terms ONLY, do NOT derive action semantics from it.
                           - `[UNCERTAIN FRAGMENT]`: do NOT introduce new action claims unless the decompiled code itself explicitly evidences them.
                        3. If no snippet tag is applicable or all snippets seem unrelated, fall back to the decompiled code and CFG description alone.
                        4. Generate a concise, one-sentence summary of no more than 25 words that summarizes the function's purpose.
                    """
        requirements = """Strict requirements to output:
- Make your best definitive interpretation based on code evidence, avoid placeholders and generic descriptions WHEN strong and distinct C-source-style features (explicit string literals or known API calls) are present in the decompiled code.
- DO NOT use uncertain words like "possible", "seems", "likely", "appears", "may", "might", "probably". Prohibiting the output of decompiled symbols (sub_/FUN_/0x...).
- Example of ideal answer: "Sends a byte to the device via PS/2 protocol and waits for an answer or timeout". Bad answer: "This function possibly performs specified operations on data"."""
        parts = [intro, code_section]
        if cfg_section:
            parts.append(cfg_section)
        parts += [snippets_section, task, requirements]
        return "\n\n".join(parts)

    def _build_prompt(self, decompiled_code, cfg_description, snippets_text):
        """Legacy dispatcher — routes to per-mode builders based on available context."""
        has_cfg = cfg_description is not None and cfg_description.strip() != ""
        has_snippets = snippets_text is not None
        if has_cfg and has_snippets:
            return self._build_prompt_m4(decompiled_code, cfg_description, snippets_text)
        elif has_cfg:
            return self._build_prompt_m2(decompiled_code, cfg_description)
        elif has_snippets:
            return self._build_prompt_m3(decompiled_code, None, snippets_text)
        else:
            return self._build_prompt_m1(decompiled_code)

    def generate_summary(self, decompiled_code, cfg_description=None, source_candidates=None):
        """
        Generate final summary based on available context.
        
        Args:
            decompiled_code: The decompiled C function
            cfg_description: Optional CFG summary (M2, M3, M4)
            source_candidates: Optional list of source snippets (M3, M4)
        """
        # Format source candidates
        snippets_text = None
        if source_candidates and len(source_candidates) > 0:
            snippets_text = '\n'.join(
                [f'Potential source snippet {i+1}:\n```C\n{s.strip()}\n```' for i, s in enumerate(source_candidates)]
            )
        
        prompt = self._build_prompt(decompiled_code, cfg_description, snippets_text)
        return self._chat(prompt)
