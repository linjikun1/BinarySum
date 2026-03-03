import torch
from bert_score import score
import os
import warnings
import logging
from tqdm import tqdm

# Suppress all verbose logging
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("bert_score").setLevel(logging.ERROR)

# Default model path - can be overridden via environment variable or constructor
DEFAULT_MODEL_PATH = os.environ.get(
    "CODEBERT_MODEL_PATH",
    "microsoft/codebert-base"  # fallback to HF hub if not set
)


class CodeBERTScoreCalculator:
    def __init__(self, device=None, batch_size=32, model_path=None):
        self.device = device if device else ("cuda" if torch.cuda.is_available() else "cpu")
        self.batch_size = batch_size
        # Use local model path if provided, otherwise use default
        self.model_type = model_path or DEFAULT_MODEL_PATH

    def compute(self, predictions, references):
        """
        Calculate CodeBERTScore.
        :param predictions: List of generated summaries [str]
        :param references: List of reference summaries [str]
        :return: List of F1 scores for each sample (and prints average)
        """
        # Suppress all verbose output
        import io
        import sys
        
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            # Redirect stdout/stderr to suppress tqdm bars
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()
            
            try:
                P, R, F1 = score(
                    predictions, 
                    references, 
                    lang="en", 
                    model_type=self.model_type, 
                    num_layers=10,
                    verbose=False,
                    device=self.device,
                    batch_size=self.batch_size
                )
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr
        
        # F1 is a tensor of shape (N,)
        # We return the list of scores for each sample
        return F1.tolist()
