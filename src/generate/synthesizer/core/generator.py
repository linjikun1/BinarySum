import openai
import time
from typing import Optional, List


class OpenAIFinalSummarizer:
    def __init__(self, api_key, model_name, base_url, timeout=60, max_retries=3, retry_delay=5):
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)
        self.model_name = model_name
        self.max_retries = max_retries
        self.retry_delay = retry_delay

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
                return response.choices[0].message.content.strip()
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

    def _build_prompt(self, decompiled_code, cfg_description, snippets_text):
        """
        Build prompt based on available context.
        
        Template structure (maximize similarity, minimize difference):
        - Common: decompiled code section + task + requirements
        - Optional: CFG section, snippets section, Confidence Handling
        """
        # Common header
        has_cfg = cfg_description is not None
        has_snippets = snippets_text is not None
        
        # Determine intro text based on available context
        if has_cfg and has_snippets:
            intro = "You are given a stripped and decompiled C function, the corresponding description which interpreted from the control flow graph, and some potentially related source snippets for context."
        elif has_cfg:
            intro = "You are given a stripped and decompiled C function, and the corresponding summary which interpreted from the control flow graph of the function."
        elif has_snippets:
            intro = "You are given a stripped and decompiled C function, and some potentially related source snippets for context."
        else:
            intro = "You are given a stripped and decompiled C function."
        
        # Decompile code section (always present)
        code_section = f"""Here is the decompiled C function:
                            ```C
                            {decompiled_code}
                            ```
                        """
        
        # CFG section (optional)
        cfg_section =  f"""Here is the corresponding CFG description: {cfg_description}"""  if has_cfg else ""
        
        # Snippets section (optional)
        snippets_section = f"""Here are some source snippets: {snippets_text}""" if has_snippets else ""
        
        # Task section
        if has_cfg and has_snippets:
            task = """Your task is to:
                        1. Use the decompiled function as the base, the CFG description and the source snippets to enhance understanding.
                        2. Generate a concise, one-sentence summary of no more than 25 words that summarizes function's purpose.
                    """
        elif has_cfg:
            task = """Your task is to:
                        1. Use the decompiled function as the base and the CFG summary to enhance understanding.
                        2. Generate a concise, one-sentence summary of no more than 25 words that summarizes function's purpose.
                    """
        elif has_snippets:
            task = """Your task is to:
                        1. Use the decompiled function as the base and the source snippets to enhance understanding.
                        2. Generate a concise, one-sentence summary of no more than 25 words that summarizes function's purpose.
                    """
        else:
            task = "Your task is to generate a concise, one-sentence summary of no more than 25 words that summarizes the function's purpose."
        
        # Requirements section (with conditional Confidence Handling)
        requirements = """Strict requirements to output:
- Make your best definitive interpretation based on code evidence, avoid placeholders and generic descriptions WHEN strong and distinct C-source-style features (explicit string literals or known API calls) are present in the decompiled code.
- DO NOT use uncertain words like "possible", "seems", "likely", "appears", "may", "might", "probably". Prohibiting the output of decompiled symbols (sub_/FUN_/0x...).
- Example of ideal answer: "Sends a byte to the device via PS/2 protocol and waits for an answer or timeout". Bad answer: "This function possibly performs specified operations on data"."""
        
        confidence_handling = """
- **Confidence Handling**, if snippet is marked with:
    - `[HIGH CONFIDENCE SOURCE]`, you may trust its logic and intent significantly, provided it doesn't blatantly contradict the decompiled code.
    - `[CONTEXT REFERENCE]`, just use its domain knowledge for Naming/Structs ONLY, DO NOT derive semantics that go beyond the code domain implied by the code itself.
    - `[UNCERTAIN FRAGMENT]`, DO NOT introduce new action claims (e.g., parse/validate/register/serialize) unless the decompiled code itself explicitly evidences them (strong and distinct features)."""
        
        if has_snippets:
            requirements += confidence_handling
        
        # Assemble prompt
        parts = [intro, code_section]
        if cfg_section:
            parts.append(cfg_section)
        if snippets_section:
            parts.append(snippets_section)
        parts.append(task)
        parts.append(requirements)
        
        return "\n\n".join(parts)

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
