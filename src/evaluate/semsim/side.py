"""
SIDE (Summary-Code Semantic Similarity) Calculator

Uses UniXcoder (SOTA for code-search tasks) to compute semantic similarity
between generated summaries and decompiled code.

Reference: "Code Search by Semantic Similarity" - UniXcoder achieves SOTA on CodeSearchNet
"""

import torch
import torch.nn.functional as F
from transformers import RobertaTokenizer, RobertaModel
import os
import logging

# Suppress transformers verbose logging
logging.getLogger("transformers").setLevel(logging.ERROR)

# Default model path - can be overridden via environment variable or constructor
DEFAULT_MODEL_PATH = os.environ.get(
    "UNIXCODER_MODEL_PATH",
    "microsoft/unixcoder-base"  # fallback to HF hub if not set
)


class SideCalculator:
    """
    SIDE (Summary-Code Semantic Similarity) Evaluator.
    
    UniXcoder is based on RoBERTa architecture and achieves SOTA on code-search tasks.
    Uses [CLS] token embedding as sentence representation.
    """
    
    def __init__(self, model_path=None, device=None, batch_size=16):
        """
        Initialize SIDE evaluator.
        
        Args:
            model_path: Local model path or HF model identifier (default: from env or HF hub)
            device: Device to run on (auto-detect if None)
            batch_size: Batch size for inference
        """
        self.device = device if device else ("cuda" if torch.cuda.is_available() else "cpu")
        self.batch_size = batch_size
        
        # Use local model path if provided, otherwise use default
        model_name = model_path or DEFAULT_MODEL_PATH
        
        # Suppress tqdm output during model loading
        import io
        import sys
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()
        
        try:
            # UniXcoder uses RoBERTa architecture
            self.tokenizer = RobertaTokenizer.from_pretrained(model_name, local_files_only=True, verbose=False)
            self.model = RobertaModel.from_pretrained(model_name, local_files_only=True).to(self.device)
            self.model.eval()
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
    
    def _get_embeddings(self, text_list, desc="Computing embeddings"):
        """
        Get sentence embeddings for a list of texts in batches.
        Uses [CLS] token (index 0) as sentence representation.
        
        Args:
            text_list: List of strings
            desc: Description for progress bar (only shown in verbose mode)
            
        Returns:
            Tensor of shape [N, D] with L2-normalized embeddings
        """
        all_embeddings = []
        
        # Disable tqdm output by using disable=True
        for i in range(0, len(text_list), self.batch_size):
            batch_texts = text_list[i : i + self.batch_size]
            
            # Tokenize with truncation for long code
            inputs = self.tokenizer(
                batch_texts, 
                return_tensors="pt", 
                padding=True, 
                truncation=True, 
                max_length=512  # Handle long decompiled code
            ).to(self.device)
            
            with torch.no_grad():
                outputs = self.model(**inputs)
            
            # [CLS] token embedding (index 0)
            embeddings = outputs.last_hidden_state[:, 0, :]
            
            # L2 normalize for cosine similarity
            embeddings = F.normalize(embeddings, p=2, dim=1)
            all_embeddings.append(embeddings.cpu())
        
        if not all_embeddings:
            return torch.tensor([])
        
        return torch.cat(all_embeddings, dim=0)

    def compute(self, summaries, codes):
        """
        Compute SIDE score (cosine similarity between summary and code embeddings).
        
        Args:
            summaries: List of generated summaries [str]
            codes: List of corresponding decompiled codes [str]
            
        Returns:
            List of cosine similarity scores [float]
        """
        if len(summaries) != len(codes):
            raise ValueError("Summaries and codes lists must have the same length.")
        
        # Get embeddings
        summary_embs = self._get_embeddings(summaries)
        code_embs = self._get_embeddings(codes)
        
        # Cosine similarity (already normalized, so dot product = cosine)
        cosine_scores = torch.sum(summary_embs * code_embs, dim=1)
        
        return cosine_scores.tolist()

    def compute_single(self, code_snippet, generated_summary):
        """
        Compute SIDE score for a single pair (convenience method).
        
        Args:
            code_snippet: Decompiled code string
            generated_summary: Generated summary string
            
        Returns:
            Cosine similarity score (float)
        """
        code_embedding = self._get_embeddings([code_snippet])
        summary_embedding = self._get_embeddings([generated_summary])
        
        similarity = torch.sum(code_embedding * summary_embedding, dim=1)
        return similarity.item()


# ================= Test Code =================
if __name__ == "__main__":
    evaluator = SideCalculator()

    # Simulated decompiled code
    decompiled_code = """
    int sub_401000(int a1, int a2) {
        int v3;
        v3 = a1;
        while ( a2 ) {
            v3 *= a1;
            --a2;
        }
        return v3;
    }
    """

    # Summary A: High quality
    summary_good = "This function calculates the power of a given number by repeatedly multiplying it."
    
    # Summary B: Low quality (hallucination)
    summary_bad = "This function opens a network socket and sends a packet."
    
    # Summary C: Generic (low information)
    summary_generic = "This function takes two arguments and returns an integer."

    # Compute scores
    score_good = evaluator.compute_single(decompiled_code, summary_good)
    score_bad = evaluator.compute_single(decompiled_code, summary_bad)
    score_generic = evaluator.compute_single(decompiled_code, summary_generic)

    print("\n--- SIDE Scores (Code-Summary Semantic Similarity) ---")
    print(f"Good Summary Score   : {score_good:.4f}")
    print(f"Generic Summary Score: {score_generic:.4f}")
    print(f"Bad Summary Score    : {score_bad:.4f}")
