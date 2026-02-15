import openai
import time

class OpenAIFinalSummarizer:
    def __init__(self, api_key, model_name, base_url):
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)
        self.model_name = model_name

    def _chat(self, prompt, temperature=0.2):
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
        except Exception as e:
            print(f"Error in generation: {e}")
            return ""

    def generate_summary(self, decompiled_code, cfg_description=None, source_candidates=None):
        """
        Generate final summary based on available context.
        """
        # Base Prompt
        prompt_parts = [
            "You are given a stripped and decompiled C function.",
            f"Here is the decompiled C function:\n```C\n{decompiled_code}\n```"
        ]

        # Add CFG Context
        if cfg_description:
            prompt_parts.append(f"Here is the corresponding description interpreted from the control flow graph:\n{cfg_description}")

        # Add Source Snippets Context
        if source_candidates and len(source_candidates) > 0:
            formatted_candidates = '\n'.join(
                [f'Potential source function {i+1}:\n```C\n{s.strip()}\n```' for i, s in enumerate(source_candidates)]
            )
            prompt_parts.append(f"Here are some potentially related source snippets for context:\n{formatted_candidates}")

        # Task Instruction
        task_instruction = """
Your task is to generate a concise, one-sentence summary of no more than 25 words that summarizes the function's purpose.

Strict requirements:
1. Use the decompiled function as the base truth.
2. Use the provided CFG description (if any) and source snippets (if any) to enhance understanding.
3. **Confidence Handling**:
    - `[HIGH CONFIDENCE SOURCE]`: Trust its logic significantly unless it blatantly contradicts the code.
    - `[CONTEXT REFERENCE]`: Use for Naming/Structs context only.
    - `[UNCERTAIN SOURCE]`: Do not infer new actions without code evidence.
4. DO NOT use uncertain words like "possible", "seems", "likely".
5. Example ideal answer: "Sends a byte to the device via PS/2 protocol and waits for an answer or timeout".
"""
        prompt_parts.append(task_instruction)
        
        full_prompt = "\n\n".join(prompt_parts)
        return self._chat(full_prompt)
