import torch
from bert_score import score

class CodeBERTScoreCalculator:
    def __init__(self, device=None, batch_size=32):
        self.device = device if device else ("cuda" if torch.cuda.is_available() else "cpu")
        self.batch_size = batch_size
        # Specific model for code tasks
        self.model_type = "microsoft/codebert-base"

    def compute(self, predictions, references):
        """
        Calculate CodeBERTScore.
        :param predictions: List of generated summaries [str]
        :param references: List of reference summaries [str]
        :return: List of F1 scores for each sample (and prints average)
        """
        print(f"Computing CodeBERTScore using {self.model_type} on {self.device}...")
        
        P, R, F1 = score(
            predictions, 
            references, 
            lang="en", 
            model_type=self.model_type, 
            num_layers=10,
            verbose=True,
            device=self.device,
            batch_size=self.batch_size
        )
        
        # F1 is a tensor of shape (N,)
        # We return the list of scores for each sample
        return F1.tolist()
