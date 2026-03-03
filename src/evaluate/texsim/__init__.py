# -*- coding: utf-8 -*-
"""
Textual similarity metrics module.
"""

__all__ = ['TexSimEvaluator']


def __getattr__(name):
    """Lazy import to avoid loading heavy dependencies when not needed."""
    if name == 'TexSimEvaluator':
        from .evaluator import TexSimEvaluator
        return TexSimEvaluator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
