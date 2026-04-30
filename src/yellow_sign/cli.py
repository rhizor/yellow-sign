#!/usr/bin/env python3
"""
Yellow Sign CLI
Command-line interface for the secrets scanner
"""

import sys
import json
import click
from pathlib import Path
from typing import Optional

from yellow_sign import __version__
from yellow_sign.scanner import SecretScanner
from yellow_sign.rules import get_default_ruleset
from yellow_sign.findings import Severity


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="yellow-sign")
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.pass_context
def cli(ctx, verbose):
    """
    🔍 Yellow Sign - Secrets Scanner
    
    Detect secrets and credentials in code before they are committed.
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    
    if ctx.invoked_subcommand is None:
        # Default action: show help
        click.echo(ctx.get_help())


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--recursive', '-r', is_flag=True, default=True, help='Scan recursively')
@click.option('--workers', '-w', type=int, default=4, help='Number of parallel workers')
@click.option('--config', '-c', type=click.Path(), help='Path to config file')
@click.option('--output', '-o', type=click.Choice(['text', 'json', 'sarif']), default='text', help='Output format')
@click.option('--output-file', '-f', type=click.Path(), help='Output file (default: stdout)')
@click.option('--severity', '-s', type=click.Choice(['critical', 'high', 'medium', 'low', 'info']), 
              multiple=True, help='Filter by severity')
@click.option('--fail-on-secrets', is_flag=True, help='Exit with error code if secrets found')
@click.option('--exclude', '-e', multiple=True, help='Paths to exclude')
@click.option('--no-entropy', is_flag=True, help='Disable entropy scanning')
@click.pass_context
def scan(ctx, path, recursive, workers, config, output, output_file, severity, fail_on_secrets, exclude, no_entropy):
    """
    Scan a file or directory for secrets.
    
    PATH: File or directory to scan
    """
    verbose = ctx.obj.get('verbose', False)
    
    if verbose:
        click.echo(f"🔍 Scanning: {path}", err=True)
    
    # Initialize scanner
    scanner = SecretScanner(
        excludes=set(exclude) if exclude else None
    )
    
    # Run scan
    try:
        result = scanner.scan_path(path, recursive=recursive, workers=workers)
        
        # Filter by severity if specified
        if severity:
            severities = {Severity(s) for s in severity}
            result.findings = [f for f in result.findings if f.severity in severities]
            result.total_findings = len(result.findings)
        
        # Output results
        if output == 'json':
            output_text = json.dumps(result.to_dict(), indent=2)
        elif output == 'sarif':
            output_text = _format_sarif(result)
        else:
            output_text = _format_text(result, verbose)
        
        # Write output
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output_text)
            click.echo(f"✅ Results written to {output_file}", err=True)
        else:
            click.echo(output_text)
        
        # Exit code
        if fail_on_secrets and result.total_findings > 0:
            sys.exit(1)
        
        sys.exit(0)
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(2)


@cli.command()
@click.argument('repo_path', type=click.Path(exists=True), default='.')
@click.option('--force', is_flag=True, help='Overwrite existing hook')
def install_hook(repo_path, force):
    """
    Install pre-commit hook in a Git repository.
    
    REPO_PATH: Path to Git repository (default: current directory)
    """
    git_dir = Path(repo_path) / '.git'
    
    if not git_dir.exists():
        click.echo(f"❌ {repo_path} is not a Git repository", err=True)
        sys.exit(1)
    
    hooks_dir = git_dir / 'hooks'
    hooks_dir.mkdir(exist_ok=True)
    
    hook_file = hooks_dir / 'pre-commit'
    
    if hook_file.exists() and not force:
        click.echo(f"⚠️  Pre-commit hook already exists. Use --force to overwrite.", err=True)
        sys.exit(1)
    
    # Create hook script
    hook_script = '''#!/bin/bash
# Yellow Sign Pre-Commit Hook
# Automatically installed by yellow-sign install-hook

# Get the list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

# Check if yellow-sign is installed
if ! command -v yellow-sign &> /dev/null; then
    echo "⚠️  Warning: yellow-sign not found in PATH"
    echo "Skipping secrets scan. Install with: pip install yellow-sign"
    exit 0
fi

# Scan staged files
echo "🔍 Scanning staged files for secrets..."

SECRETS_FOUND=0
for file in $STAGED_FILES; do
    if [ -f "$file" ]; then
        # Run yellow-sign on the staged content
        if git show ":$file" | yellow-sign scan --path /dev/stdin --fail-on-secrets 2>/dev/null; then
            :
        else
            if [ $? -eq 1 ]; then
                echo "❌ Secret detected in: $file"
                SECRETS_FOUND=1
            fi
        fi
    fi
done

if [ $SECRETS_FOUND -eq 1 ]; then
    echo ""
    echo "🚫 Commit blocked!"
    echo "Secrets detected in staged files. Please review and remove them."
    echo ""
    echo "To bypass this check (not recommended):"
    echo "  git commit --no-verify"
    exit 1
fi

echo "✅ No secrets detected"
exit 0
'''
    
    hook_file.write_text(hook_script)
    hook_file.chmod(0o755)  # Make executable
    
    click.echo(f"✅ Pre-commit hook installed at {hook_file}")
    click.echo("")
    click.echo("The hook will automatically scan staged files for secrets.")
    click.echo("To uninstall: rm .git/hooks/pre-commit")


@cli.command()
@click.argument('repo_path', type=click.Path(exists=True), default='.')
def uninstall_hook(repo_path):
    """
    Uninstall pre-commit hook from a Git repository.
    
    REPO_PATH: Path to Git repository (default: current directory)
    """
    hook_file = Path(repo_path) / '.git' / 'hooks' / 'pre-commit'
    
    if not hook_file.exists():
        click.echo("⚠️  No pre-commit hook found", err=True)
        sys.exit(1)
    
    # Check if it's our hook
    content = hook_file.read_text()
    if 'Yellow Sign Pre-Commit Hook' not in content:
        click.echo("⚠️  Pre-commit hook exists but was not installed by yellow-sign", err=True)
        click.echo("Not removing to avoid breaking existing hooks.")
        sys.exit(1)
    
    hook_file.unlink()
    click.echo(f"✅ Pre-commit hook removed from {repo_path}")


@cli.command()
def list_rules():
    """
    List all detection rules.
    """
    ruleset = get_default_ruleset()
    
    click.echo("📋 Detection Rules")
    click.echo("=" * 60)
    
    for rule in ruleset.get_rules():
        severity_color = {
            'critical': 'red',
            'high': 'yellow',
            'medium': 'blue',
            'low': 'green',
            'info': 'white'
        }.get(rule.severity.value, 'white')
        
        click.echo(f"\n[{click.style(rule.severity.value.upper(), fg=severity_color)}] {rule.name}")
        click.echo(f"  Description: {rule.description}")
        click.echo(f"  Min Entropy: {rule.min_entropy}")
        click.echo(f"  Confidence: {rule.confidence}")
        if rule.tags:
            click.echo(f"  Tags: {', '.join(rule.tags)}")
    
    click.echo(f"\nTotal: {len(ruleset.get_rules())} rules")


@cli.command()
@click.argument('string')
def check_entropy(string):
    """
    Check the entropy of a string.
    
    Useful for debugging false positives or testing custom patterns.
    """
    from yellow_sign.entropy import EntropyAnalyzer
    
    analyzer = EntropyAnalyzer()
    entropy, classification = analyzer.analyze(string)
    
    click.echo(f"String: {string[:50]}{'...' if len(string) > 50 else ''}")
    click.echo(f"Entropy: {entropy:.2f}")
    click.echo(f"Classification: {classification}")
    
    if classification == 'high':
        click.echo(click.style("⚠️  High entropy - likely a secret!", fg='red'))
    elif classification == 'medium':
        click.echo(click.style("ℹ️  Medium entropy - review recommended", fg='yellow'))
    else:
        click.echo(click.style("✅ Low entropy - likely not a secret", fg='green'))


def _format_text(result, verbose: bool = False) -> str:
    """Format scan results as text"""
    lines = []
    
    # Header
    lines.append("🔍 Yellow Sign Scan Results")
    lines.append("=" * 60)
    lines.append(f"Scan ID: {result.scan_id}")
    lines.append(f"Timestamp: {result.timestamp}")
    lines.append("")
    
    # Summary
    summary = result.get_summary_by_severity()
    lines.append("📊 Summary:")
    lines.append(f"  Files scanned: {result.files_scanned}")
    lines.append(f"  Files with secrets: {result.files_with_secrets}")
    lines.append(f"  Total findings: {result.total_findings}")
    lines.append("")
    
    if result.total_findings > 0:
        lines.append("By Severity:")
        for sev, count in summary.items():
            if count > 0:
                color = {
                    'critical': 'red',
                    'high': 'yellow',
                    'medium': 'blue',
                    'low': 'green',
                    'info': 'white'
                }.get(sev, 'white')
                lines.append(f"  {sev.upper()}: {count}")
        lines.append("")
        
        # Findings
        lines.append("🔎 Findings:")
        lines.append("-" * 60)
        
        for finding in result.findings:
            sev_color = {
                Severity.CRITICAL: 'red',
                Severity.HIGH: 'yellow',
                Severity.MEDIUM: 'blue',
                Severity.LOW: 'green',
                Severity.INFO: 'white',
            }.get(finding.severity, 'white')
            
            lines.append(f"\n[{click.style(finding.severity.value.upper(), fg=sev_color)}] {finding.rule_name}")
            lines.append(f"  File: {finding.file_path}:{finding.line_number}")
            
            match_display = finding.match
            if len(match_display) > 50:
                match_display = match_display[:50] + "..."
            lines.append(f"  Match: {match_display}")
            
            if verbose:
                lines.append(f"  Entropy: {finding.entropy:.2f}")
                lines.append(f"  Confidence: {finding.confidence:.2f}")
                if finding.description:
                    lines.append(f"  Description: {finding.description}")
                if finding.remediation:
                    lines.append(f"  Remediation: {finding.remediation}")
            
            lines.append("-" * 60)
    else:
        lines.append("✅ No secrets detected!")
    
    lines.append("")
    lines.append(f"Duration: {result.duration_seconds:.2f}s")
    
    return "\n".join(lines)


def _format_sarif(result) -> str:
    """Format scan results as SARIF (Static Analysis Results Interchange Format)"""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Yellow Sign",
                    "version": __version__,
                    "informationUri": "https://github.com/rhizor/yellow-sign"
                }
            },
            "results": []
        }]
    }
    
    for finding in result.findings:
        sarif["runs"][0]["results"].append({
            "ruleId": finding.rule_name,
            "level": finding.severity.value,
            "message": {
                "text": finding.description or f"{finding.rule_name} detected"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path
                    },
                    "region": {
                        "startLine": finding.line_number
                    }
                }
            }]
        })
    
    return json.dumps(sarif, indent=2)


if __name__ == '__main__':
    cli()
