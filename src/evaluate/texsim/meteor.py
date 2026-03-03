# -*- coding: utf-8 -*-
"""
METEOR metric implementation for lexical-based evaluation.
Requires Java and meteor-1.5.jar.
"""

from __future__ import absolute_import, division, print_function

import os
import threading
import subprocess
import re

# Use relative path like original, cwd will be set correctly
METEOR_JAR = "./meteor-1.5.jar"


def _clean_text(text):
    """Clean text for METEOR processing - remove problematic patterns."""
    # Remove common LLM prefixes like "Summary:", "Final one-sentence summary:", etc.
    text = re.sub(r'^(Final\s+)?(one-sentence\s+)?summary\s*(\([^)]*\))?\s*:\s*', '', text, flags=re.IGNORECASE)
    # Remove multiple newlines
    text = re.sub(r'\n+', ' ', text)
    # Remove multiple spaces
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


class Meteor(object):
    """METEOR metric calculator using Java implementation."""

    def __init__(self, language="en", norm=True):
        self.meteor_cmd = ["java", "-jar", "-Xmx2G", METEOR_JAR,
                           "-", "-", "-stdio", "-l", language]

        if norm:
            self.meteor_cmd.append("-norm")

        # Set cwd to the directory containing this file (where meteor-1.5.jar is)
        self.meteor_p = subprocess.Popen(
            self.meteor_cmd, stdin=subprocess.PIPE,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, bufsize=1)

        self.lock = threading.Lock()

    def compute_score(self, gts, res):
        imgIds = sorted(list(gts.keys()))
        scores = []
        eval_line = "EVAL"
        self.lock.acquire()

        try:
            for i in imgIds:
                assert(len(res[i]) == 1)

                # Clean text to avoid METEOR jar issues
                hypothesis_str = _clean_text(res[i][0]).replace("|||", "").replace("  ", " ")
                refs_str = " ||| ".join([_clean_text(r) for r in gts[i]])
                
                score_line = " ||| ".join(("SCORE", refs_str, hypothesis_str))

                self.meteor_p.stdin.write(score_line + "\n")
                self.meteor_p.stdin.flush()
                stat = self.meteor_p.stdout.readline().strip()
                eval_line += " ||| {}".format(stat)

            # Send to METEOR
            self.meteor_p.stdin.write(eval_line + "\n")
            self.meteor_p.stdin.flush()

            # Collect segment scores
            for i in range(len(imgIds)):
                score = float(self.meteor_p.stdout.readline().strip())
                scores.append(score)

            # Final score
            final_score = 100 * float(self.meteor_p.stdout.readline().strip())
            
            return final_score, scores
        finally:
            self.lock.release()

    def __del__(self):
        self.lock.acquire()
        try:
            self.meteor_p.stdin.close()
            self.meteor_p.wait()
        except:
            pass
        self.lock.release()

    @staticmethod
    def method():
        return "METEOR"
