# -*- coding: utf-8 -*-
"""
LLM-as-a-Judge evaluation module.
"""

__all__ = ['LLMJudgeEvaluator', 'UnifiedLLMJudgeEvaluator']


def __getattr__(name):
    """Lazy import to avoid loading heavy dependencies when not needed."""
    if name == 'LLMJudgeEvaluator':
        from .evaluator import LLMJudgeEvaluator
        return LLMJudgeEvaluator
    if name == 'UnifiedLLMJudgeEvaluator':
        from .unified_evaluator import UnifiedLLMJudgeEvaluator
        return UnifiedLLMJudgeEvaluator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
