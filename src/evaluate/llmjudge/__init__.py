# -*- coding: utf-8 -*-
"""
LLM-as-a-Judge evaluation module.
"""

__all__ = ['LLMJudgeEvaluator']


def __getattr__(name):
    """Lazy import to avoid loading heavy dependencies when not needed."""
    if name == 'LLMJudgeEvaluator':
        from .evaluator import LLMJudgeEvaluator
        return LLMJudgeEvaluator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
