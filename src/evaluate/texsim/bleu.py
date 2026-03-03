# -*- coding: utf-8 -*-
"""
BLEU metric implementation for lexical-based evaluation.
"""

from __future__ import absolute_import, division, print_function

import copy
import math
from collections import defaultdict


def _precook(s, n=4, out=False):
    """Takes a string as input and returns ngram counts."""
    words = s.split()
    counts = defaultdict(int)
    for k in range(1, n + 1):
        for i in range(len(words) - k + 1):
            ngram = tuple(words[i:i + k])
            counts[ngram] += 1
    return len(words), counts


def _cook_refs(refs, eff=None, n=4):
    """Takes a list of reference sentences and returns BLEU data."""
    reflen = []
    maxcounts = {}
    for ref in refs:
        rl, counts = _precook(ref, n)
        reflen.append(rl)
        for (ngram, count) in counts.items():
            maxcounts[ngram] = max(maxcounts.get(ngram, 0), count)
    if eff == "shortest":
        reflen = min(reflen)
    elif eff == "average":
        reflen = float(sum(reflen)) / len(reflen)
    return reflen, maxcounts


def _cook_test(test, ref_len_counts, eff=None, n=4):
    """Takes a test sentence and returns BLEU data."""
    reflen, refmaxcounts = ref_len_counts
    testlen, counts = _precook(test, n, True)
    result = {}
    if eff == "closest":
        result["reflen"] = min((abs(l - testlen), l) for l in reflen)[1]
    else:
        result["reflen"] = reflen
    result["testlen"] = testlen
    result["guess"] = [max(0, testlen - k + 1) for k in range(1, n + 1)]
    result["correct"] = [0 for _ in range(n)]
    for ngram, count in counts.items():
        result["correct"][len(ngram) - 1] += min(refmaxcounts.get(ngram, 0), count)
    return result


class _BleuScorer(object):
    """BLEU scorer."""

    __slots__ = "n", "crefs", "ctest", "_score", "_ratio", "_testlen", "_reflen", "special_reflen"

    def __init__(self, test=None, refs=None, n=4, special_reflen=None):
        self.n = n
        self.crefs = []
        self.ctest = []
        self._cook_append(test, refs)
        self.special_reflen = special_reflen

    def _cook_append(self, test, refs):
        if refs is not None:
            self.crefs.append(_cook_refs(refs))
            if test is not None:
                self.ctest.append(_cook_test(test, self.crefs[-1]))
            else:
                self.ctest.append(None)
        self._score = None

    def __iadd__(self, other):
        if isinstance(other, tuple):
            self._cook_append(other[0], other[1])
        else:
            self.ctest.extend(other.ctest)
            self.crefs.extend(other.crefs)
            self._score = None
        return self

    def compute_score(self, option=None, verbose=0):
        n = self.n
        small = 1e-9
        tiny = 1e-15
        bleu_list = [[] for _ in range(n)]

        if self._score is not None:
            return self._score

        if option is None:
            option = "average" if len(self.crefs) == 1 else "closest"

        self._testlen = 0
        self._reflen = 0
        totalcomps = {"testlen": 0, "reflen": 0, "guess": [0 for _ in range(n)], "correct": [0 for _ in range(n)]}

        for comps in self.ctest:
            testlen = comps["testlen"]
            self._testlen += testlen
            if self.special_reflen is None:
                reflen = min((abs(l - testlen), l) for l in comps["reflen"])[1] if option == "closest" else comps["reflen"]
            else:
                reflen = self.special_reflen
            self._reflen += reflen
            for key in ["guess", "correct"]:
                for k in range(n):
                    totalcomps[key][k] += comps[key][k]

            bleu = 1.0
            for k in range(n):
                bleu *= (float(comps["correct"][k]) + tiny) / (float(comps["guess"][k]) + small)
                bleu_list[k].append(bleu ** (1.0 / (k + 1)))

            ratio = (testlen + tiny) / (reflen + small)
            if ratio < 1:
                for k in range(n):
                    bleu_list[k][-1] *= math.exp(1 - 1.0 / ratio)

        totalcomps["reflen"] = self._reflen
        totalcomps["testlen"] = self._testlen

        bleus = []
        bleu = 1.0
        for k in range(n):
            bleu *= float(totalcomps["correct"][k] + tiny) / (totalcomps["guess"][k] + small)
            bleus.append(bleu ** (1.0 / (k + 1)))

        ratio = (self._testlen + tiny) / (self._reflen + small)
        if ratio < 1:
            for k in range(n):
                bleus[k] *= math.exp(1 - 1.0 / ratio)

        bleus = [100 * b for b in bleus]
        self._score = bleus
        return self._score, bleu_list


class Bleu(object):
    """BLEU metric calculator."""

    def __init__(self, n=4):
        self._n = n

    def compute_score(self, gts, res):
        bleu_scorer = _BleuScorer(n=self._n)
        for idx in sorted(gts.keys()):
            hypo = res[idx]
            ref = gts[idx]
            assert type(hypo) is list and len(hypo) == 1
            assert type(ref) is list and len(ref) >= 1
            bleu_scorer += (hypo[0], ref)
        score, scores = bleu_scorer.compute_score(option='closest', verbose=0)
        return score, scores

    @staticmethod
    def method():
        return "BLEU"
