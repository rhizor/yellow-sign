"""
Yellow Sign - Secrets Scanner

A powerful secrets detection tool that scans code and configurations
for leaked API keys, passwords, tokens, and other sensitive data.

"""

__version__ = "1.0.0"
__author__ = "rhizor"
__license__ = "MIT"

from .scanner import SecretScanner
from .rules import RuleSet, DetectionRule
from .entropy import EntropyAnalyzer
from .findings import Finding, Severity

__all__ = [
    "SecretScanner",
    "RuleSet", 
    "DetectionRule",
    "EntropyAnalyzer",
    "Finding",
    "Severity",
]
