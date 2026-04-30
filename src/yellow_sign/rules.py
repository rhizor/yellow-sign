"""
Detection rules for Yellow Sign secrets scanner
"""

import re
from typing import Pattern, Optional, List
from dataclasses import dataclass, field
from .findings import Severity


@dataclass
class DetectionRule:
    """
    A rule for detecting specific types of secrets.
    """
    name: str
    # Regex pattern to match
    pattern: Pattern
    # Minimum entropy threshold (0-5 scale)
    min_entropy: float = 3.5
    # Severity of finding
    severity: Severity = Severity.HIGH
    # Human-readable description
    description: str = ""
    # How to fix/remediate
    remediation: str = ""
    # Confidence level (0.0-1.0)
    confidence: float = 0.8
    # Tags for categorization
    tags: List[str] = field(default_factory=list)
    
    def match(self, text: str) -> Optional[re.Match]:
        """Try to match this rule against text"""
        return self.pattern.search(text)


class RuleSet:
    """
    Collection of detection rules.
    """
    
    def __init__(self):
        self.rules: List[DetectionRule] = []
        self._load_default_rules()
    
    def add_rule(self, rule: DetectionRule):
        """Add a custom rule"""
        self.rules.append(rule)
    
    def get_rules(self) -> List[DetectionRule]:
        """Get all rules"""
        return self.rules
    
    def _load_default_rules(self):
        """Load built-in detection rules"""
        
        # AWS Access Keys
        self.rules.append(DetectionRule(
            name="AWS Access Key ID",
            pattern=re.compile(r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
            min_entropy=3.5,
            severity=Severity.CRITICAL,
            description="AWS Access Key ID found",
            remediation="Move to environment variables or AWS Secrets Manager",
            confidence=0.95,
            tags=["aws", "cloud", "credentials"]
        ))
        
        # AWS Secret Access Key
        self.rules.append(DetectionRule(
            name="AWS Secret Access Key",
            pattern=re.compile(r'['\"\'][A-Za-z0-9/+=]{40}['\"\']'),
            min_entropy=4.0,
            severity=Severity.CRITICAL,
            description="Possible AWS Secret Access Key found",
            remediation="Move to environment variables or AWS Secrets Manager",
            confidence=0.85,
            tags=["aws", "cloud", "credentials"]
        ))
        
        # GitHub Personal Access Token
        self.rules.append(DetectionRule(
            name="GitHub Personal Access Token",
            pattern=re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
            min_entropy=4.0,
            severity=Severity.CRITICAL,
            description="GitHub Personal Access Token found",
            remediation="Move to environment variables or GitHub Secrets",
            confidence=0.95,
            tags=["github", "token", "git"]
        ))
        
        # Slack Webhook
        self.rules.append(DetectionRule(
            name="Slack Webhook URL",
            pattern=re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{10}/[a-zA-Z0-9_]{24}'),
            min_entropy=3.0,
            severity=Severity.HIGH,
            description="Slack webhook URL found",
            remediation="Move to environment variables",
            confidence=0.95,
            tags=["slack", "webhook", "messaging"]
        ))
        
        # Slack Token
        self.rules.append(DetectionRule(
            name="Slack API Token",
            pattern=re.compile(r'xox[baprs]-[0-9a-zA-Z-]+'),
            min_entropy=3.5,
            severity=Severity.CRITICAL,
            description="Slack API token found",
            remediation="Move to environment variables",
            confidence=0.9,
            tags=["slack", "token", "messaging"]
        ))
        
        # Private Keys
        self.rules.append(DetectionRule(
            name="Private Key",
            pattern=re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'),
            min_entropy=2.0,
            severity=Severity.CRITICAL,
            description="Private key found",
            remediation="Move to secure vault, never commit to git",
            confidence=0.99,
            tags=["crypto", "key", "sensitive"]
        ))
        
        # Generic API Key patterns
        self.rules.append(DetectionRule(
            name="Generic API Key",
            pattern=re.compile(r'[aA][pP][iI][-_]?[kK][eE][yY][\s]*[:=][\s]*[\'\"][a-zA-Z0-9_\-]{16,}[\'\"]'),
            min_entropy=3.5,
            severity=Severity.HIGH,
            description="Possible API key found",
            remediation="Review and move to environment variables if sensitive",
            confidence=0.7,
            tags=["api", "key", "generic"]
        ))
        
        # Database connection strings
        self.rules.append(DetectionRule(
            name="Database Connection String",
            pattern=re.compile(r'(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/\s]+'),
            min_entropy=3.0,
            severity=Severity.CRITICAL,
            description="Database connection string with credentials",
            remediation="Use connection pooling or vault for credentials",
            confidence=0.9,
            tags=["database", "credentials", "connection-string"]
        ))
        
        # JWT Token
        self.rules.append(DetectionRule(
            name="JWT Token",
            pattern=re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
            min_entropy=4.0,
            severity=Severity.MEDIUM,
            description="JWT token found",
            remediation="Review if this is a test token or production secret",
            confidence=0.8,
            tags=["jwt", "token", "auth"]
        ))
        
        # Google API Key
        self.rules.append(DetectionRule(
            name="Google API Key",
            pattern=re.compile(r'AIza[0-9A-Za-z_-]{35}'),
            min_entropy=3.5,
            severity=Severity.HIGH,
            description="Google API key found",
            remediation="Move to environment variables",
            confidence=0.9,
            tags=["google", "api", "cloud"]
        ))
        
        # Azure Service Principal
        self.rules.append(DetectionRule(
            name="Azure Service Principal Secret",
            pattern=re.compile(r'[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12}'),
            min_entropy=3.5,
            severity=Severity.HIGH,
            description="Possible Azure Service Principal credential found",
            remediation="Move to Azure Key Vault",
            confidence=0.6,
            tags=["azure", "microsoft", "cloud"]
        ))
        
        # Heroku API Key
        self.rules.append(DetectionRule(
            name="Heroku API Key",
            pattern=re.compile(r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),
            min_entropy=3.0,
            severity=Severity.CRITICAL,
            description="Heroku API key found",
            remediation="Move to environment variables",
            confidence=0.85,
            tags=["heroku", "paas", "api"]
        ))
        
        # Password in URL
        self.rules.append(DetectionRule(
            name="Password in URL",
            pattern=re.compile(r'[a-zA-Z]{3,10}://[^/\s:@]+:[^/\s:@]+@[^/\s]+'),
            min_entropy=2.5,
            severity=Severity.CRITICAL,
            description="Password found embedded in URL",
            remediation="Remove credentials from URLs, use environment variables",
            confidence=0.9,
            tags=["url", "password", "credentials"]
        ))
        
        # NPM Token
        self.rules.append(DetectionRule(
            name="NPM Access Token",
            pattern=re.compile(r'npm_[A-Za-z0-9]{36}'),
            min_entropy=4.0,
            severity=Severity.HIGH,
            description="NPM access token found",
            remediation="Move to .npmrc or environment variables",
            confidence=0.95,
            tags=["npm", "nodejs", "token"]
        ))
        
        # PyPI Token
        self.rules.append(DetectionRule(
            name="PyPI API Token",
            pattern=re.compile(r'pypi-[A-Za-z0-9-_]{32,}'),
            min_entropy=4.0,
            severity=Severity.HIGH,
            description="PyPI API token found",
            remediation="Move to ~/.pypirc or environment variables",
            confidence=0.95,
            tags=["pypi", "python", "token"]
        ))
        
        # SendGrid API Key
        self.rules.append(DetectionRule(
            name="SendGrid API Key",
            pattern=re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
            min_entropy=4.0,
            severity=Severity.CRITICAL,
            description="SendGrid API key found",
            remediation="Move to environment variables",
            confidence=0.95,
            tags=["sendgrid", "email", "api"]
        ))
        
        # Stripe API Key
        self.rules.append(DetectionRule(
            name="Stripe API Key",
            pattern=re.compile(r'(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}'),
            min_entropy=4.0,
            severity=Severity.CRITICAL,
            description="Stripe API key found",
            remediation="Never commit live keys. Use test keys for development",
            confidence=0.95,
            tags=["stripe", "payment", "api"]
        ))
        
        # Twilio API Key
        self.rules.append(DetectionRule(
            name="Twilio API Key",
            pattern=re.compile(r'SK[0-9a-f]{32}'),
            min_entropy=3.5,
            severity=Severity.CRITICAL,
            description="Twilio API key found",
            remediation="Move to environment variables",
            confidence=0.9,
            tags=["twilio", "sms", "api"]
        ))
        
        # Discord Webhook
        self.rules.append(DetectionRule(
            name="Discord Webhook URL",
            pattern=re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]{18,}/[a-zA-Z0-9_-]{68,}'),
            min_entropy=3.5,
            severity=Severity.HIGH,
            description="Discord webhook URL found",
            remediation="Move to environment variables",
            confidence=0.95,
            tags=["discord", "webhook", "messaging"]
        ))
        
        # Telegram Bot Token
        self.rules.append(DetectionRule(
            name="Telegram Bot Token",
            pattern=re.compile(r'[0-9]{9}:[a-zA-Z0-9_-]{35}'),
            min_entropy=3.5,
            severity=Severity.HIGH,
            description="Telegram bot token found",
            remediation="Move to environment variables",
            confidence=0.9,
            tags=["telegram", "bot", "token"]
        ))
        
        # Generic Secret/Password patterns
        self.rules.append(DetectionRule(
            name="Possible Password Assignment",
            pattern=re.compile(r'[\'\"]?[pP][aA][sS][sS][wW][oO][rR][dD][\'\"]?\s*(=|:)\s*[\'\"][^\'"]{8,}[\'\"]'),
            min_entropy=3.0,
            severity=Severity.MEDIUM,
            description="Possible hardcoded password",
            remediation="Review and remove if hardcoded, use environment variables",
            confidence=0.6,
            tags=["password", "generic", "assignment"]
        ))
        
        self.rules.append(DetectionRule(
            name="Possible Secret Assignment",
            pattern=re.compile(r'[\'\"]?[sS][eE][cC][rR][eE][tT][\'\"]?\s*(=|:)\s*[\'\"][a-zA-Z0-9_\-]{8,}[\'\"]'),
            min_entropy=3.5,
            severity=Severity.HIGH,
            description="Possible hardcoded secret",
            remediation="Review and move to secure vault",
            confidence=0.7,
            tags=["secret", "generic", "assignment"]
        ))
        
        # SSH Keys (OpenSSH format)
        self.rules.append(DetectionRule(
            name="SSH Private Key",
            pattern=re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
            min_entropy=2.0,
            severity=Severity.CRITICAL,
            description="SSH private key found",
            remediation="Move to ~/.ssh/ with proper permissions (600), never commit",
            confidence=0.99,
            tags=["ssh", "key", "crypto"]
        ))
        
        # PGP Private Key
        self.rules.append(DetectionRule(
            name="PGP Private Key",
            pattern=re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
            min_entropy=2.0,
            severity=Severity.CRITICAL,
            description="PGP private key found",
            remediation="Move to secure keyring, never commit",
            confidence=0.99,
            tags=["pgp", "key", "crypto"]
        ))


def get_default_ruleset() -> RuleSet:
    """Get the default ruleset with all built-in rules"""
    return RuleSet()
