import sys
import os

# Ensure we can import from the Metrics directory which is now inside n_gram_metrics
current_dir = os.path.dirname(os.path.abspath(__file__))
# The Metrics folder was copied to evaluate/n_gram_metrics/Metrics
# We need to add evaluate/n_gram_metrics to sys.path so that "from Metrics..." works
metrics_root = os.path.join(current_dir) 
if metrics_root not in sys.path:
    sys.path.append(metrics_root)

# Now we can import using the structure from your original run_eval.py
# Note: The original code used "from Metrics.bleu.bleu import Bleu", which assumes "Metrics" is a package in path
# Since we copied Metrics folder INTO n_gram_metrics, the structure is evaluate/n_gram_metrics/Metrics/...
# So if we add evaluate/n_gram_metrics to path, "import Metrics.bleu.bleu" should work.

try:
    from Metrics.bleu.bleu import Bleu
    from Metrics.rouge.rouge import Rouge
    from Metrics.meteor.meteor import Meteor
    from Metrics.cider.cider import Cider
except ImportError:
    # Fallback: try relative import if run as module
    try:
        from .Metrics.bleu.bleu import Bleu
        from .Metrics.rouge.rouge import Rouge
        from .Metrics.meteor.meteor import Meteor
        from .Metrics.cider.cider import Cider
    except ImportError as e:
        print(f"Error importing metrics: {e}")
        print(f"Current path: {sys.path}")
        print(f"Looking in: {metrics_root}")
        raise

class NGramMetricsCalculator:
    def __init__(self, bleu=True, meteor=True, rouge=True, cider=False, n=4):
        self.scorers = []
        
        if bleu:
            self.scorers.append((Bleu(n), ["BLEU-1", "BLEU-2", "BLEU-3", "BLEU-4"]))
        if meteor:
            self.scorers.append((Meteor(), "METEOR"))
        if rouge:
            self.scorers.append((Rouge(), "ROUGE-L"))
        if cider:
            self.scorers.append((Cider(), "CIDEr"))

    def compute(self, references, hypotheses):
        """
        Compute N-Gram metrics for a list of references and hypotheses.
        Format expected by these legacy scorers:
        refs: {0: ["ref1"], 1: ["ref2"], ...}
        hypos: {0: ["hyp1"], 1: ["hyp2"], ...}
        """
        # Convert list to dictionary format expected by the legacy scorers
        ref_dict = {i: [r] for i, r in enumerate(references)}
        hyp_dict = {i: [h] for i, h in enumerate(hypotheses)}
        
        final_scores = {}
        
        # Note: These legacy scorers typically return the AVERAGE score across the corpus,
        # NOT a list of scores per sample.
        # Bleu.compute_score returns (average_score, list_of_individual_scores) usually, 
        # but let's check the implementation if we need individual scores.
        # Based on typical COCO-caption code (which this seems to be based on):
        # score, scores = scorer.compute_score(ref, hypo)
        # So we can get individual scores!
        
        individual_scores_dict = {}

        for scorer, metric_names in self.scorers:
            # compute_score returns (avg_score, list_of_scores)
            avg_score, ind_scores = scorer.compute_score(ref_dict, hyp_dict)
            
            if isinstance(metric_names, list):
                for m_name, avg_s, ind_s in zip(metric_names, avg_score, ind_scores):
                    final_scores[m_name] = avg_s
                    individual_scores_dict[m_name] = ind_s
            else:
                final_scores[metric_names] = avg_score
                individual_scores_dict[metric_names] = ind_scores
                
        return final_scores, individual_scores_dict
