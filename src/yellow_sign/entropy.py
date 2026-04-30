"""
Entropy analysis for detecting high-entropy strings (likely secrets)
"""

import math
import re
from typing import Tuple


class EntropyAnalyzer:
    """
    Analyzes string entropy to detect potential secrets.
    High entropy strings are more likely to be random (e.g., API keys, tokens).
    """
    
    # Thresholds for entropy detection
    HIGH_ENTROPY = 4.5    # Very likely a secret
    MEDIUM_ENTROPY = 4.0  # Possible secret, review needed
    LOW_ENTROPY = 3.5     # Probably not a secret
    
    def __init__(self):
        # Common patterns that look like secrets but aren't
        self.false_positive_patterns = [
            r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',  # UUID
            r'^v[0-9]+\.[0-9]+\.[0-9]+$',  # Version strings
            r'^https?://',  # URLs
            r'^#?[0-9A-Fa-f]{6}$',  # Hex colors
            r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$',  # IP addresses
        ]
    
    def calculate_shannon_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string.
        Higher entropy = more random = more likely a secret.
        
        Formula: H(X) = -sum(p(x) * log2(p(x)))
        """
        if not string:
            return 0.0
        
        # Remove common delimiters that don't add entropy
        clean_string = string.replace('-', '').replace('_', '').replace('/', '')
        if not clean_string:
            return 0.0
        
        entropy = 0
        length = len(clean_string)
        
        # Count frequency of each character
        for x in set(clean_string):
            p_x = clean_string.count(x) / length
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        
        return entropy
    
    def analyze(self, string: str) -> Tuple[float, str]:
        """
        Analyze a string and return entropy score and classification.
        
        Returns:
            Tuple of (entropy_score, classification)
            classification: "high", "medium", "low", "ignore"
        """
        # Skip false positives
        if self._is_false_positive(string):
            return (0.0, "ignore")
        
        # Calculate entropy
        entropy = self.calculate_shannon_entropy(string)
        
        # Classify
        if entropy >= self.HIGH_ENTROPY:
            return (entropy, "high")
        elif entropy >= self.MEDIUM_ENTROPY:
            return (entropy, "medium")
        else:
            return (entropy, "low")
    
    def _is_false_positive(self, string: str) -> bool:
        """Check if string is a known false positive pattern"""
        import re
        for pattern in self.false_positive_patterns:
            if re.match(pattern, string):
                return True
        return False
    
    def get_candidate_substrings(self, text: str, min_length: int = 20, max_length: int = 100) -> list:
        """
        Extract candidate substrings that might contain secrets.
        
        Looks for:
        - Long alphanumeric strings
        - Base64-like strings
        - Hex strings
        """
        import re
        
        candidates = []
        
        # Pattern 1: Base64-like strings (alphanumeric + / + =)
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        for match in re.finditer(base64_pattern, text):
            candidate = match.group()
            if min_length <= len(candidate) <= max_length:
                entropy, classification = self.analyze(candidate)
                if classification in ["high", "medium"]:
                    candidates.append({
                        'string': candidate,
                        'entropy': entropy,
                        'classification': classification,
                        'start': match.start(),
                        'end': match.end(),
                    })
        
        # Pattern 2: Hex strings
        hex_pattern = r'[0-9a-fA-F]{32,}'
        for match in re.finditer(hex_pattern, text):
            candidate = match.group()
            if min_length <= len(candidate) <= max_length:
                entropy, classification = self.analyze(candidate)
                if classification in ["high", "medium"]:
                    candidates.append({
                        'string': candidate,
                        'entropy': entropy,
                        'classification': classification,
                        'start': match.start(),
                        'end': match.end(),
                    })
        
        return candidates


def quick_entropy_check(string: str) -> float:
    """Quick helper to check entropy of a single string"""
    analyzer = EntropyAnalyzer()
    return analyzer.calculate_shannon_entropy(string)
