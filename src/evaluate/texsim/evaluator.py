# -*- coding: utf-8 -*-
"""
Textual similarity metrics evaluator.
Computes BLEU, METEOR, and ROUGE-L scores.
"""

from .bleu import Bleu
from .meteor import Meteor
from .rouge import Rouge


class TexSimEvaluator:
    """Evaluator for textual similarity metrics (BLEU, METEOR, ROUGE-L)."""

    def __init__(self, bleu=True, meteor=True, rouge=True, n=4):
        """
        Initialize textual similarity evaluator.
        
        Args:
            bleu: Enable BLEU metric
            meteor: Enable METEOR metric
            rouge: Enable ROUGE-L metric
            n: Maximum n-gram for BLEU
        """
        self.scorers = []
        
        if bleu:
            self.scorers.append((Bleu(n), ["BLEU-1", "BLEU-2", "BLEU-3", "BLEU-4"]))
        if meteor:
            try:
                from .meteor import Meteor
                self.scorers.append((Meteor(), "METEOR"))
            except Exception as e:
                print(f"Warning: Failed to initialize METEOR: {e}")
        if rouge:
            self.scorers.append((Rouge(), "ROUGE-L"))

    def compute(self, references, hypotheses):
        """
        Compute lexical metrics for a list of references and hypotheses.
        
        Args:
            references: List of reference strings
            hypotheses: List of hypothesis strings
            
        Returns:
            tuple: (avg_scores dict, individual_scores dict)
        """
        # Convert list to dictionary format expected by the scorers
        ref_dict = {i: [r] for i, r in enumerate(references)}
        hyp_dict = {i: [h] for i, h in enumerate(hypotheses)}
        
        final_scores = {}
        individual_scores_dict = {}

        for scorer, metric_names in self.scorers:
            try:
                avg_score, ind_scores = scorer.compute_score(ref_dict, hyp_dict)
            except Exception as e:
                print(f"Warning: Failed to compute {metric_names}: {e}")
                continue
            
            if isinstance(metric_names, list):
                for m_name, avg_s, ind_s in zip(metric_names, avg_score, ind_scores):
                    final_scores[m_name] = avg_s
                    individual_scores_dict[m_name] = ind_s
            else:
                final_scores[metric_names] = avg_score
                individual_scores_dict[metric_names] = ind_scores
                
        return final_scores, individual_scores_dict
