"""
Core scanner engine for Yellow Sign
"""

import os
import re
import uuid
import mimetypes
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Set, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed

from .findings import Finding, Severity, ScanResult
from .rules import RuleSet, get_default_ruleset
from .entropy import EntropyAnalyzer


class SecretScanner:
    """
    Main scanner engine that orchestrates the detection of secrets.
    """
    
    # Default file extensions to scan
    DEFAULT_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb',
        '.php', '.cs', '.cpp', '.c', '.h', '.swift', '.kt',
        '.yaml', '.yml', '.json', '.xml', '.toml', '.ini',
        '.sh', '.bash', '.zsh', '.fish',
        '.md', '.txt', '.rst',
        '.env', '.conf', '.config',
        '.sql', '.psql', '.mysql',
        '.dockerfile', '.tf', '.hcl',
        '.vue', '.svelte', '.html', '.htm',
    }
    
    # Default files/directories to exclude
    DEFAULT_EXCLUDES = {
        'node_modules',
        'vendor',
        '.git',
        '.github',
        '.vscode',
        '.idea',
        '__pycache__',
        '.pytest_cache',
        'venv',
        'env',
        '.venv',
        'dist',
        'build',
        'target',
        'bin',
        'obj',
        '.DS_Store',
        'Thumbs.db',
        '*.min.js',
        '*.min.css',
        'package-lock.json',
        'yarn.lock',
        'Gemfile.lock',
        'Pipfile.lock',
        'poetry.lock',
        '*.pyc',
        '*.pyo',
        '*.class',
        '*.o',
        '*.so',
        '*.dll',
        '*.exe',
    }
    
    # Binary file extensions to skip
    BINARY_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
        '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv',
        '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.exe', '.bin', '.dll', '.so', '.dylib',
        '.db', '.sqlite', '.sqlite3',
    }
    
    def __init__(
        self,
        rules: Optional[RuleSet] = None,
        extensions: Optional[Set[str]] = None,
        excludes: Optional[Set[str]] = None,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        entropy_analyzer: Optional[EntropyAnalyzer] = None,
    ):
        self.rules = rules or get_default_ruleset()
        self.extensions = extensions or self.DEFAULT_EXTENSIONS
        self.excludes = excludes or self.DEFAULT_EXCLUDES
        self.max_file_size = max_file_size
        self.entropy_analyzer = entropy_analyzer or EntropyAnalyzer()
        self._scanned_hashes: Set[str] = set()  # For deduplication
    
    def scan_path(
        self,
        path: str,
        recursive: bool = True,
        workers: int = 4,
    ) -> ScanResult:
        """
        Scan a file or directory for secrets.
        
        Args:
            path: Path to file or directory
            recursive: Whether to scan subdirectories
            workers: Number of parallel workers
            
        Returns:
            ScanResult with all findings
        """
        start_time = datetime.now()
        scan_id = str(uuid.uuid4())[:8]
        
        # Collect files to scan
        files = self._collect_files(path, recursive)
        
        findings: List[Finding] = []
        files_scanned = 0
        files_with_secrets = 0
        
        # Parallel scanning
        if workers > 1 and len(files) > 1:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(self.scan_file, f): f for f in files}
                for future in as_completed(futures):
                    file_path = futures[future]
                    try:
                        file_findings = future.result()
                        files_scanned += 1
                        if file_findings:
                            findings.extend(file_findings)
                            files_with_secrets += 1
                    except Exception as e:
                        print(f"Error scanning {file_path}: {e}")
        else:
            # Sequential scanning
            for file_path in files:
                try:
                    file_findings = self.scan_file(file_path)
                    files_scanned += 1
                    if file_findings:
                        findings.extend(file_findings)
                        files_with_secrets += 1
                except Exception as e:
                    print(f"Error scanning {file_path}: {e}")
        
        # Calculate duration
        duration = (datetime.now() - start_time).total_seconds()
        
        return ScanResult(
            scan_id=scan_id,
            timestamp=start_time.isoformat(),
            files_scanned=files_scanned,
            files_with_secrets=files_with_secrets,
            total_findings=len(findings),
            findings=findings,
            duration_seconds=duration,
        )
    
    def scan_file(self, file_path: str) -> List[Finding]:
        """
        Scan a single file for secrets.
        
        Args:
            file_path: Path to file
            
        Returns:
            List of findings
        """
        findings: List[Finding] = []
        
        # Check if file exists and is readable
        if not os.path.exists(file_path):
            return findings
        
        if not os.path.isfile(file_path):
            return findings
        
        # Check file size
        try:
            size = os.path.getsize(file_path)
            if size > self.max_file_size:
                return findings
        except OSError:
            return findings
        
        # Skip binary files
        if self._is_binary_file(file_path):
            return findings
        
        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception:
            return findings
        
        # Scan each line
        for line_num, line in enumerate(lines, 1):
            line_findings = self.scan_line(line, file_path, line_num)
            findings.extend(line_findings)
        
        # Also check for high-entropy strings in the whole file
        entropy_findings = self._scan_for_entropy(content, file_path)
        findings.extend(entropy_findings)
        
        return findings
    
    def scan_line(
        self,
        line: str,
        file_path: str,
        line_number: int,
    ) -> List[Finding]:
        """
        Scan a single line for secrets.
        
        Args:
            line: Line content
            file_path: Source file path
            line_number: Line number
            
        Returns:
            List of findings
        """
        findings: List[Finding] = []
        
        # Skip empty lines and comments
        stripped = line.strip()
        if not stripped or stripped.startswith(('#', '//', '/*', '*', '<!--')):
            return findings
        
        # Apply each rule
        for rule in self.rules.get_rules():
            match = rule.match(line)
            if match:
                # Calculate entropy for the match
                matched_text = match.group(0)
                entropy, classification = self.entropy_analyzer.analyze(matched_text)
                
                # Skip if entropy is too low (likely false positive)
                if entropy < rule.min_entropy:
                    continue
                
                # Calculate confidence based on entropy
                confidence = min(1.0, rule.confidence + (entropy / 10))
                
                finding = Finding(
                    rule_name=rule.name,
                    file_path=file_path,
                    line_number=line_number,
                    match=matched_text,
                    severity=rule.severity,
                    entropy=entropy,
                    confidence=confidence,
                    description=rule.description,
                    remediation=rule.remediation,
                )
                
                findings.append(finding)
        
        return findings
    
    def _collect_files(self, path: str, recursive: bool = True) -> List[str]:
        """Collect files to scan from a path"""
        files: List[str] = []
        
        if os.path.isfile(path):
            # Single file
            if self._should_scan_file(path):
                files.append(path)
        elif os.path.isdir(path):
            # Directory
            if recursive:
                for root, dirs, filenames in os.walk(path):
                    # Filter out excluded directories
                    dirs[:] = [d for d in dirs if not self._should_exclude(os.path.join(root, d))]
                    
                    for filename in filenames:
                        file_path = os.path.join(root, filename)
                        if self._should_scan_file(file_path):
                            files.append(file_path)
            else:
                # Non-recursive: only immediate files
                for filename in os.listdir(path):
                    file_path = os.path.join(path, filename)
                    if os.path.isfile(file_path) and self._should_scan_file(file_path):
                        files.append(file_path)
        
        return files
    
    def _should_scan_file(self, file_path: str) -> bool:
        """Determine if a file should be scanned"""
        # Check exclusion patterns
        if self._should_exclude(file_path):
            return False
        
        # Check extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() in self.BINARY_EXTENSIONS:
            return False
        
        # Check if extension is in scan list (if specified)
        if self.extensions and ext.lower() not in self.extensions:
            return False
        
        return True
    
    def _should_exclude(self, path: str) -> bool:
        """Check if path should be excluded"""
        name = os.path.basename(path)
        
        for exclude in self.excludes:
            # Exact match
            if name == exclude:
                return True
            # Glob pattern
            if exclude.startswith('*') and name.endswith(exclude[1:]):
                return True
            # Directory match
            if exclude in path.split(os.sep):
                return True
        
        return False
    
    def _is_binary_file(self, file_path: str) -> bool:
        """Check if a file is binary"""
        _, ext = os.path.splitext(file_path)
        if ext.lower() in self.BINARY_EXTENSIONS:
            return True
        
        # Try to detect binary by content
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if b'\x00' in chunk:
                    return True
        except:
            pass
        
        return False
    
    def _scan_for_entropy(
        self,
        content: str,
        file_path: str,
    ) -> List[Finding]:
        """
        Scan content for high-entropy strings that might be secrets.
        This catches secrets that don't match known patterns.
        """
        findings: List[Finding] = []
        
        # Get candidates from entropy analyzer
        candidates = self.entropy_analyzer.get_candidate_substrings(content)
        
        for candidate in candidates:
            if candidate['classification'] == 'high':
                # Find line number
                line_num = content[:candidate['start']].count('\n') + 1
                
                # Check if this is a duplicate (already found by rules)
                secret_hash = hash(candidate['string']) % 100000
                if secret_hash in self._scanned_hashes:
                    continue
                self._scanned_hashes.add(secret_hash)
                
                finding = Finding(
                    rule_name="High Entropy String",
                    file_path=file_path,
                    line_number=line_num,
                    match=candidate['string'],
                    severity=Severity.LOW,  # Lower confidence since no pattern match
                    entropy=candidate['entropy'],
                    confidence=0.5,
                    description="High entropy string detected - possible secret",
                    remediation="Review this string - if it's a secret, move to environment variables",
                )
                
                findings.append(finding)
        
        return findings
