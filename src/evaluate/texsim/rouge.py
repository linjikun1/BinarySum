# -*- coding: utf-8 -*-
"""
ROUGE-L metric implementation for lexical-based evaluation.
"""

from __future__ import absolute_import, division, print_function

import numpy as np


def _lcs(string, sub):
    """Computes longest common subsequence (LCS) for a pair of tokenized strings."""
    if len(string) < len(sub):
        sub, string = string, sub
    str_len, sub_len = len(string), len(sub)
    lengths = [[0 for _ in range(sub_len + 1)] for _ in range(str_len + 1)]
    for j in range(1, sub_len + 1):
        for i in range(1, str_len + 1):
            if string[i - 1] == sub[j - 1]:
                lengths[i][j] = lengths[i - 1][j - 1] + 1
            else:
                lengths[i][j] = max(lengths[i - 1][j], lengths[i][j - 1])
    return lengths[str_len][sub_len]


class Rouge(object):
    """ROUGE-L metric calculator."""

    def __init__(self):
        self.beta = 1.2

    def _calc_score(self, candidate, refs):
        """Compute ROUGE-L score given one candidate and references."""
        assert len(candidate) == 1
        assert len(refs) > 0
        prec = []
        rec = []
        token_c = candidate[0].split()
        for reference in refs:
            token_r = reference.split()
            lcs = _lcs(token_r, token_c)
            prec.append(lcs / float(len(token_c)))
            rec.append(lcs / float(len(token_r)))
        prec_max = max(prec)
        rec_max = max(rec)
        if prec_max != 0 and rec_max != 0:
            score = ((1 + self.beta ** 2) * prec_max * rec_max) / float(rec_max + self.beta ** 2 * prec_max)
        else:
            score = 0.0
        return score

    def compute_score(self, gts, res):
        """Computes Rouge-L score for the dataset."""
        scores = []
        for idx in sorted(gts.keys()):
            hypo = res[idx]
            ref = gts[idx]
            scores.append(self._calc_score(hypo, ref))
            assert isinstance(hypo, list) and len(hypo) == 1
            assert isinstance(ref, list) and len(ref) > 0
        average_score = np.mean(np.array(scores))
        return 100 * average_score, np.array(scores)

    @staticmethod
    def method():
        return "ROUGE-L"
