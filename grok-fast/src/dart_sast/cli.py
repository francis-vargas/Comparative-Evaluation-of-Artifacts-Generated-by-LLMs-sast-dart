"""CLI for dart_sast."""

import argparse
import sys
import os
from .scanner import DartSASTScanner
from .reporter import to_console, to_json

def main():
    parser = argparse.ArgumentParser(description="dart_sast - SAST for Dart/Flutter")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--format", choices=["console", "json"], default="console", help="Output format")
    parser.add_argument("--output", help="Output file for JSON")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    scanner = DartSASTScanner()
    target_path = os.path.abspath(args.target)
    
    if os.path.isfile(target_path) and target_path.endswith('.dart'):
        findings = scanner.scan_file(target_path)
    elif os.path.isdir(target_path):
        findings = scanner.scan_directory(target_path)
    else:
        print("Error: Target must be a .dart file or directory.")
        sys.exit(1)
    
    if args.format == "json":
        output = to_json(findings)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Results written to {args.output}")
        else:
            print(output)
    else:
        to_console(findings, summary=True)
    
    if findings:
        sys.exit(1)  # Non-zero exit for CI/CD

if __name__ == "__main__":
    main()