#!/usr/bin/env python3
"""
dart_sast - Static Application Security Testing (SAST) for Dart & Flutter code.
Meets SBRC 2026 SeloF (Funcionalidade) and SeloS (Sustentabilidade) requirements.
"""

import sys
import os
import json
import argparse
from typing import List, Dict, Any

# Ensure we can import from local folder even when running directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dart_sast.engine import SASTEngine
from dart_sast.rules_definitions import RULES

# Colors for terminal output
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_GREEN = "\033[92m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

def supports_color() -> bool:
    """Checks if the active terminal supports color outputs."""
    platform_is_supported = sys.platform != 'win32' or 'ANSICON' in os.environ
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    return platform_is_supported and is_a_tty

def print_banner():
    banner = f"""
{COLOR_BLUE}{COLOR_BOLD}========================================================================
     ___          _     ____    _    ____ _____ 
    |  _ \  __ _ | |_  / ___|  / \  / ___|_   _|
    | | | |/ _` || __| \___ \ / _ \ \___ \ | |  
    | |_| | (_| || |_   ___) / ___ \ ___) || |  
    |____/ \__,_| \__| |____/_/   \_\____/ |_|  
                                                
    Static Application Security Testing for Dart & Flutter
    SBRC 2026 Scientific Artifact Compliance Bundle
========================================================================{COLOR_RESET}
"""
    if supports_color():
        print(banner, file=sys.stderr)
    else:
        # Strip ANSI codes for plain console text
        print(banner.replace(COLOR_BLUE, "").replace(COLOR_BOLD, "").replace(COLOR_RESET, ""), file=sys.stderr)

def convert_to_sarif(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Converts raw scan findings into standard SARIF v2.1.0 JSON format.
    Enables native integration with GitHub Code Scanning, SonarQube, and DefectDojo.
    """
    sarif_rules = []
    seen_rules = set()
    
    for rule in RULES:
        if rule["id"] not in seen_rules:
            sarif_rules.append({
                "id": rule["id"],
                "shortDescription": {"text": rule["name"]},
                "fullDescription": {"text": rule["description"]},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{rule['cwe'].split('-')[1]}.html",
                "properties": {
                    "tags": ["security", rule["cwe"].lower()],
                    "precision": "high",
                    "severity": "error" if rule["severity"] == "HIGH" else "warning"
                }
            })
            seen_rules.add(rule["id"])

    results = []
    for f in findings:
        level = "error" if f["severity"] == "HIGH" else "warning" if f["severity"] == "MEDIUM" else "note"
        results.append({
            "ruleId": f["rule_id"],
            "message": {
                "text": f"{f['name']} ({f['cwe']}): {f['description']}\nRecommendation: {f['recommendation']}"
            },
            "level": level,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f["file"]
                        },
                        "region": {
                            "startLine": f["line"],
                            "snippet": {
                                "text": f["code"]
                            }
                        }
                    }
                }
            ]
        })

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dart_sast",
                        "informationUri": "https://github.com/doc-artefatos/dart_sast",
                        "version": "1.0.0",
                        "rules": sarif_rules
                    }
                },
                "results": results
            }
        ]
    }

def print_console_output(findings: List[Dict[str, Any]]):
    """Prints findings to the stdout console in a clean, human-readable format."""
    use_color = supports_color()
    
    if not findings:
        msg = f"{COLOR_GREEN}{COLOR_BOLD}[✔] No security vulnerabilities detected in target!{COLOR_RESET}" if use_color else "[✔] No security vulnerabilities detected in target!"
        print(msg)
        return

    # Sort findings by severity and location
    findings_sorted = sorted(findings, key=lambda x: (x["severity"] == "LOW", x["severity"] == "MEDIUM", x["severity"] == "HIGH", x["file"], x["line"]))
    
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for f in findings_sorted:
        sev = f["severity"]
        severity_counts[sev] += 1
        
        if sev == "HIGH":
            sev_colored = f"{COLOR_RED}{COLOR_BOLD}[HIGH]{COLOR_RESET}" if use_color else "[HIGH]"
        elif sev == "MEDIUM":
            sev_colored = f"{COLOR_YELLOW}{COLOR_BOLD}[MEDIUM]{COLOR_RESET}" if use_color else "[MEDIUM]"
        else:
            sev_colored = f"{COLOR_BLUE}{COLOR_BOLD}[LOW]{COLOR_RESET}" if use_color else "[LOW]"

        print("-" * 80)
        print(f"{sev_colored} {COLOR_BOLD}{f['name']}{COLOR_RESET} ({f['cwe']})")
        print(f"  Rule ID  : {f['rule_id']}")
        print(f"  Location : {f['file']}:{f['line']}")
        print(f"  Evidence : {COLOR_BOLD}{f['code']}{COLOR_RESET}" if use_color else f"  Evidence : {f['code']}")
        print(f"  Details  : {f['description']}")
        print(f"  Fix      : {COLOR_GREEN}{f['recommendation']}{COLOR_RESET}" if use_color else f"  Fix      : {f['recommendation']}")

    print("=" * 80)
    summary_msg = (
        f"{COLOR_BOLD}Scan Summary:{COLOR_RESET}\n"
        f"  Total findings: {len(findings)}\n"
        f"  {COLOR_RED}High: {severity_counts['HIGH']}{COLOR_RESET} | "
        f"  {COLOR_YELLOW}Medium: {severity_counts['MEDIUM']}{COLOR_RESET} | "
        f"  {COLOR_BLUE}Low: {severity_counts['LOW']}{COLOR_RESET}"
    ) if use_color else (
        f"Scan Summary:\n"
        f"  Total findings: {len(findings)}\n"
        f"  High: {severity_counts['HIGH']} | "
        f"  Medium: {severity_counts['MEDIUM']} | "
        f"  Low: {severity_counts['LOW']}"
    )
    print(summary_msg)

def main():
    parser = argparse.ArgumentParser(
        description="dart_sast: Static Application Security Testing for Dart & Flutter code.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "target",
        help="Path to a single .dart file, .yaml file, or a project directory."
    )
    parser.add_argument(
        "--format",
        choices=["console", "json", "sarif"],
        default="console",
        help="Output report format (default: console)."
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Path to save the generated report."
    )
    parser.add_argument(
        "--fail-on",
        choices=["HIGH", "MEDIUM", "LOW"],
        help="Exit with code 1 if any vulnerability equal to or greater than this severity is found. (Ideal for CI/CD)."
    )

    args = parser.parse_args()

    target_path = args.target
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(2)

    # Initialize Engine and Scan
    engine = SASTEngine()
    findings = []

    if os.path.isdir(target_path):
        findings = engine.scan_directory(target_path)
    else:
        findings = engine.scan_file(target_path)

    # Output formatting
    report_data = ""
    if args.format == "console":
        print_banner()
        print_console_output(findings)
    elif args.format == "json":
        report_data = json.dumps(findings, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out:
                out.write(report_data)
        else:
            print(report_data)
    elif args.format == "sarif":
        sarif_data = convert_to_sarif(findings)
        report_data = json.dumps(sarif_data, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out:
                out.write(report_data)
        else:
            print(report_data)

    # CI/CD fail trigger logic
    if args.fail_on:
        severity_values = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        threshold = severity_values[args.fail_on]
        
        for f in findings:
            if severity_values.get(f["severity"], 0) >= threshold:
                sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
