"""
Tests for Yellow Sign secrets scanner
"""

import pytest
import tempfile
import os
from pathlib import Path

from yellow_sign.findings import Finding, Severity, ScanResult
from yellow_sign.entropy import EntropyAnalyzer
from yellow_sign.rules import RuleSet, DetectionRule, get_default_ruleset
from yellow_sign.scanner import SecretScanner


class TestEntropyAnalyzer:
    """Test entropy analysis"""
    
    def test_shannon_entropy_calculation(self):
        """Test entropy calculation for known strings"""
        analyzer = EntropyAnalyzer()
        
        # High entropy (random string)
        high = analyzer.calculate_shannon_entropy("AKIAIOSFODNN7EXAMPLE")
        assert high > 4.0
        
        # Low entropy (repetitive)
        low = analyzer.calculate_shannon_entropy("aaaaaaaaaa")
        assert low < 2.0
        
        # Medium entropy
        med = analyzer.calculate_shannon_entropy("password123")
        assert 2.0 < med < 4.0
    
    def test_entropy_classification(self):
        """Test entropy classification"""
        analyzer = EntropyAnalyzer()
        
        # Should classify high entropy as "high"
        entropy, classification = analyzer.analyze("AKIAIOSFODNN7EXAMPLE123456")
        assert classification in ["high", "medium"]
        
        # Should ignore UUIDs (false positive)
        entropy, classification = analyzer.analyze("550e8400-e29b-41d4-a716-446655440000")
        assert classification == "ignore"


class TestDetectionRules:
    """Test detection rules"""
    
    def test_aws_access_key_pattern(self):
        """Test AWS access key detection"""
        ruleset = get_default_ruleset()
        
        # Should match
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        found = False
        for rule in ruleset.get_rules():
            if rule.name == "AWS Access Key ID":
                match = rule.match(aws_key)
                assert match is not None
                found = True
        assert found
        
        # Should not match (invalid format)
        invalid = "NOTANAWSKEY123456789"
        for rule in ruleset.get_rules():
            if rule.name == "AWS Access Key ID":
                match = rule.match(invalid)
                assert match is None
    
    def test_github_token_pattern(self):
        """Test GitHub token detection"""
        ruleset = get_default_ruleset()
        
        # Should match
        token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        found = False
        for rule in ruleset.get_rules():
            if rule.name == "GitHub Personal Access Token":
                match = rule.match(token)
                if match:
                    found = True
        assert found
    
    def test_private_key_pattern(self):
        """Test private key detection"""
        ruleset = get_default_ruleset()
        
        # Should match OpenSSH private key
        key_line = "-----BEGIN OPENSSH PRIVATE KEY-----"
        found = False
        for rule in ruleset.get_rules():
            if rule.name == "SSH Private Key":
                match = rule.match(key_line)
                if match:
                    found = True
        assert found


class TestSecretScanner:
    """Test the main scanner"""
    
    def test_scan_single_file_with_secret(self, tmp_path):
        """Test scanning a file containing a secret"""
        # Create temp file with secret
        test_file = tmp_path / "config.py"
        test_file.write_text("""
# Config file
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
""")
        
        scanner = SecretScanner()
        findings = scanner.scan_file(str(test_file))
        
        # Should find at least one secret
        assert len(findings) >= 1
        
        # Should find AWS key
        aws_findings = [f for f in findings if "AWS" in f.rule_name]
        assert len(aws_findings) >= 1
    
    def test_scan_single_file_without_secrets(self, tmp_path):
        """Test scanning a clean file"""
        test_file = tmp_path / "clean.py"
        test_file.write_text("""
# Clean config file
DEBUG = True
PORT = 8080
HOST = "localhost"
""")
        
        scanner = SecretScanner()
        findings = scanner.scan_file(str(test_file))
        
        # Should not find secrets
        assert len(findings) == 0
    
    def test_scan_directory(self, tmp_path):
        """Test scanning a directory"""
        # Create multiple files
        (tmp_path / "secret.py").write_text('API_KEY = "sk_live_1234567890abcdef"')
        (tmp_path / "clean.py").write_text("DEBUG = True")
        
        scanner = SecretScanner()
        result = scanner.scan_path(str(tmp_path))
        
        assert result.files_scanned == 2
        assert result.total_findings >= 1
    
    def test_exclude_patterns(self, tmp_path):
        """Test exclusion patterns"""
        # Create file in excluded directory
        node_modules = tmp_path / "node_modules" / "package.json"
        node_modules.parent.mkdir()
        node_modules.write_text('{"token": "secret123"}')
        
        # Create file in regular directory
        (tmp_path / "app.py").write_text('API_KEY = "normal_secret"')
        
        scanner = SecretScanner()
        result = scanner.scan_path(str(tmp_path))
        
        # Should not scan node_modules
        assert "node_modules" not in str(result.findings)


class TestIntegration:
    """Integration tests"""
    
    def test_full_scan_workflow(self, tmp_path):
        """Test complete scan workflow"""
        # Create test repo structure
        (tmp_path / "src" / "config.py").parent.mkdir(parents=True)
        (tmp_path / "src" / "config.py").write_text("""
DATABASE_URL = "postgres://user:password123@localhost:5432/db"
SLACK_WEBHOOK = "https://hooks.slack.example.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
""")
        
        (tmp_path / ".env").write_text("""
STRIPE_KEY=sk_test_example_key_not_real_123456789
""")
        
        # Run scan
        scanner = SecretScanner()
        result = scanner.scan_path(str(tmp_path))
        
        # Verify results
        assert result.total_findings >= 3  # DB password, Slack webhook, Stripe key
        
        # Check severity
        critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 1
        
        # Verify structure
        for finding in result.findings:
            assert finding.file_path
            assert finding.line_number > 0
            assert finding.rule_name
            assert finding.severity


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
