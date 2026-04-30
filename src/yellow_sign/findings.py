"""
Core data models for Yellow Sign
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import hashlib


class Severity(Enum):
    """Severity levels for findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """
    Represents a detected secret finding.
    """
    rule_name: str
    file_path: str
    line_number: int
    match: str
    severity: Severity
    entropy: float = 0.0
    confidence: float = 0.0
    description: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def __post_init__(self):
        # Hash the secret for deduplication
        self.secret_hash = hashlib.sha256(self.match.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            "rule_name": self.rule_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "match": self.match[:50] + "..." if len(self.match) > 50 else self.match,  # Truncate for display
            "match_hash": self.secret_hash,
            "severity": self.severity.value,
            "entropy": round(self.entropy, 2),
            "confidence": round(self.confidence, 2),
            "description": self.description,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }
    
    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.rule_name}: {self.file_path}:{self.line_number}"


@dataclass
class ScanResult:
    """
    Results from a complete scan.
    """
    scan_id: str
    timestamp: str
    files_scanned: int
    files_with_secrets: int
    total_findings: int
    findings: List[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    
    def get_summary_by_severity(self) -> Dict[str, int]:
        """Get count of findings by severity"""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            summary[finding.severity.value] += 1
        return summary
    
    def has_critical(self) -> bool:
        """Check if any critical findings"""
        return any(f.severity == Severity.CRITICAL for f in self.findings)
    
    def has_high(self) -> bool:
        """Check if any high severity findings"""
        return any(f.severity == Severity.HIGH for f in self.findings)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert results to dictionary"""
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "summary": {
                "files_scanned": self.files_scanned,
                "files_with_secrets": self.files_with_secrets,
                "total_findings": self.total_findings,
                "by_severity": self.get_summary_by_severity(),
            },
            "findings": [f.to_dict() for f in self.findings],
            "duration_seconds": self.duration_seconds,
        }
