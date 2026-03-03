# -*- coding: utf-8 -*-
"""
Semantic similarity metrics module.
"""

__all__ = ['SemSimEvaluator']


def __getattr__(name):
    """Lazy import to avoid loading heavy dependencies when not needed."""
    if name == 'SemSimEvaluator':
        from .evaluator import SemSimEvaluator
        return SemSimEvaluator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
