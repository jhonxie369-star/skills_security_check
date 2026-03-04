"""
Skills Security Check - CLI entry point.
"""

import sys
import json
import os
from pathlib import Path
from typing import List, Dict
from .reporter import SampleReporter


def scan_file(filepath: str, guard, context: dict = None) -> Dict:
    """Scan a single file and return results."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        ctx = context or {}
        ctx["file"] = filepath
        result = guard.analyze(content, context=ctx)
        
        return {
            "file": filepath,
            "severity": result.severity.name,
            "action": result.action.value,
            "reasons": result.reasons,
            "patterns_matched_count": len(result.patterns_matched),
            "match_contexts": result.match_contexts,
            "recommendations": result.recommendations,
        }
    except Exception as e:
        return {
            "file": filepath,
            "error": str(e),
            "severity": "ERROR",
        }


def scan_directory(dirpath: str, guard, extensions: List[str] = None) -> List[Dict]:
    """Recursively scan directory for files."""
    results = []
    extensions = extensions or ['.py', '.js', '.ts', '.sh', '.md', '.txt', '.yaml', '.yml', '.json']
    
    for root, dirs, files in os.walk(dirpath):
        # Skip common non-code directories
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]
        
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                filepath = os.path.join(root, file)
                print(f"Scanning: {filepath}", file=sys.stderr)
                result = scan_file(filepath, guard)
                if result.get("severity") not in ["SAFE", "ERROR"]:
                    results.append(result)
    
    return results


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Skills Security Check - Injection Detection")
    parser.add_argument("message", nargs="?", help="Message to analyze, or file/directory path with --scan-files")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--context", type=str, help="Context as JSON string")
    parser.add_argument("--config", type=str, help="Path to config YAML")
    parser.add_argument(
        "--sensitivity",
        choices=["low", "medium", "high", "paranoid"],
        default="medium",
        help="Detection sensitivity",
    )
    parser.add_argument("--scan-files", action="store_true", help="Scan file or directory for security issues")
    parser.add_argument("--output", default="scan_results.json", help="Output file for --scan-files (default: scan_results.json)")
    parser.add_argument("--extensions", help="Comma-separated file extensions to scan (e.g., .py,.js)")
    parser.add_argument("--report-failed", action="store_true", help="Report failed scans to server")
    parser.add_argument("--report-server", help="Server URL for reporting")

    args = parser.parse_args()

    if not args.message:
        # Read from stdin
        args.message = sys.stdin.read().strip()

    if not args.message:
        parser.print_help()
        sys.exit(1)

    config = {"sensitivity": args.sensitivity}
    if args.config:
        try:
            import yaml
        except ImportError:
            print(
                "Error: PyYAML required for config files. Install with: pip install pyyaml",
                file=sys.stderr,
            )
            sys.exit(1)
        with open(args.config) as f:
            file_config = yaml.safe_load(f) or {}
            file_config = file_config.get("skills_security_check", file_config)
            config.update(file_config)

    # Parse context
    context = {}
    if args.context:
        context = json.loads(args.context)

    # Initialize guard
    from skills_security_check.engine import SkillsSecurityCheck
    guard = SkillsSecurityCheck(config)
    
    # Initialize reporter
    reporter = SampleReporter(
        server_url=args.report_server or "",
        enabled=args.report_failed and bool(args.report_server)
    )

    # File/directory scanning mode
    if args.scan_files:
        if not os.path.exists(args.message):
            print(f"Error: Path not found: {args.message}", file=sys.stderr)
            sys.exit(1)
        
        # Parse extensions
        extensions = None
        if args.extensions:
            extensions = [ext.strip() if ext.startswith('.') else f'.{ext.strip()}' 
                         for ext in args.extensions.split(',')]
        
        # Scan
        if os.path.isfile(args.message):
            results = [scan_file(args.message, guard, context)]
            output_dir = os.path.dirname(args.message) or '.'
        else:
            results = scan_directory(args.message, guard, extensions)
            output_dir = args.message
        
        # Report failed scans
        if reporter.enabled:
            for result in results:
                if result.get('severity') in ['HIGH', 'CRITICAL', 'MEDIUM']:
                    reporter.report_failed_scan(result['file'], result)
        
        # Write results to output file in the scanned directory
        output_path = os.path.join(output_dir, args.output)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({
                "scan_path": os.path.abspath(args.message),
                "total_issues": len(results),
                "results": results
            }, f, indent=2, ensure_ascii=False)
        
        print(f"\nScan complete. Found {len(results)} issues.", file=sys.stderr)
        print(f"Results saved to: {output_path}", file=sys.stderr)
        
        # Print summary
        if results:
            severity_counts = {}
            for r in results:
                sev = r.get("severity", "UNKNOWN")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            print("\nSeverity Summary:", file=sys.stderr)
            for sev, count in sorted(severity_counts.items()):
                print(f"  {sev}: {count}", file=sys.stderr)
        
        sys.exit(0)

    # Normal message analysis mode
    result = guard.analyze(args.message, context)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        emoji = {
            "SAFE": "\u2705",
            "LOW": "\U0001f4dd",
            "MEDIUM": "\u26a0\ufe0f",
            "HIGH": "\U0001f534",
            "CRITICAL": "\U0001f6a8",
        }
        default_emoji = '\u2753'
        print(f"{emoji.get(result.severity.name, default_emoji)} {result.severity.name}")
        print(f"Action: {result.action.value}")
        if result.reasons:
            print(f"Reasons: {', '.join(result.reasons)}")
        if result.patterns_matched:
            print(f"Patterns: {len(result.patterns_matched)} matched")
        if result.match_contexts:
            print(f"Match contexts: {len(result.match_contexts)} found")
        if result.normalized_text:
            print(f"\u26a0\ufe0f Homoglyphs detected, normalized text differs")
        if result.base64_findings:
            print(f"\u26a0\ufe0f Suspicious base64: {len(result.base64_findings)} found")
        if result.recommendations:
            print(f"\U0001f4a1 {'; '.join(result.recommendations)}")


if __name__ == "__main__":
    main()
