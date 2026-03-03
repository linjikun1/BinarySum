# -*- coding: utf-8 -*-
"""
Semantic similarity metrics evaluator.
Computes CodeBERTScore and SIDE scores.
"""

from .code_bert_score import CodeBERTScoreCalculator
from .side import SideCalculator


class SemSimEvaluator:
    """Evaluator for semantic similarity metrics (CodeBERTScore, SIDE)."""

    def __init__(self, device=None, batch_size=16, 
                 codebert_model_path=None, unixcoder_model_path=None):
        """
        Initialize semantic similarity evaluator.
        
        Args:
            device: Device to run on (auto-detect if None)
            batch_size: Batch size for inference
            codebert_model_path: Local path to CodeBERT model (or env CODEBERT_MODEL_PATH)
            unixcoder_model_path: Local path to UniXcoder model (or env UNIXCODER_MODEL_PATH)
        """
        self.code_bert_score = CodeBERTScoreCalculator(
            device=device, batch_size=batch_size, model_path=codebert_model_path
        )
        self.side = SideCalculator(
            device=device, batch_size=batch_size, model_path=unixcoder_model_path
        )

    def compute_code_bert_score(self, predictions, references):
        """
        Compute CodeBERTScore between predictions and references.
        
        Args:
            predictions: List of generated summaries
            references: List of reference summaries
            
        Returns:
            List of F1 scores for each sample
        """
        return self.code_bert_score.compute(predictions, references)

    def compute_side(self, summaries, codes):
        """
        Compute SIDE score between summaries and codes.
        
        Args:
            summaries: List of generated summaries
            codes: List of corresponding decompiled codes
            
        Returns:
            List of cosine similarity scores
        """
        return self.side.compute(summaries, codes)
