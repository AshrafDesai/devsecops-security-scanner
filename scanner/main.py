import argparse
import sys
import os
import json
import time
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from port_scan import run_port_scan
from ssl_check import run_ssl_check
from header_check import run_header_check
from zap_scan import run_zap_scan
from evaluator import evaluate
from report_generator import generate_reports

BANNER = r"""
  ____             ____                ___
 |  _ \  _____   _/ ___|  ___  ___   / _ \ _ __  ___
 | | | |/ _ \ \ / /\___ \/ _ \/ __| | | | | '_ \/ __|
 | |_| |  __/\ V /  ___) |  __/ (__  | |_| | |_) \__ \
 |____/ \___| \_/  |____/ \___|\___|  \___/| .__/|___/
                                           |_|
           Automated Security Scanner v1.0.0
"""

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[33m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[92m",
    "INFO":     "\033[94m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "GREEN":    "\033[92m",
    "RED":      "\033[91m",
}

def c(text: str, color: str) -> str:
    if sys.platform == "win32":
        return text
    return f"{SEVERITY_COLORS.get(color, '')}{text}{SEVERITY_COLORS['RESET']}"


def print_banner():
    print(c(BANNER, "BOLD"))


def print_section(title: str):
    print(f"\n{c('─' * 60, 'INFO')}")
    print(c(f"  {title}", "BOLD"))
    print(c('─' * 60, 'INFO'))


def print_finding(finding: dict, verbose: bool = False):
    sev = finding.get("severity", "LOW")
    ftype = finding.get("type", "unknown")
    detail = finding.get("detail", "")
    line = f"  [{c(sev[:4], sev)}] {ftype} — {detail[:90]}"
    print(line)
    if verbose and finding.get("recommendation"):
        print(f"       {c('→', 'INFO')} {finding['recommendation'][:100]}")


def print_summary(evaluation: dict):
    counts = evaluation.get("severity_counts", {})
    passed = evaluation.get("passed", False)
    score = evaluation.get("risk_score", 0)
    rating = evaluation.get("risk_rating", "UNKNOWN")

    print_section("SCAN SUMMARY")
    print(f"  {'Status':<20} {c('PASS ✓', 'GREEN') if passed else c('FAIL ✗', 'RED')}")
    print(f"  {'Risk Score':<20} {score}/100  ({rating})")
    print(f"  {'Total Findings':<20} {evaluation.get('total_findings', 0)}")
    print(f"  {'CRITICAL':<20} {c(str(counts.get('CRITICAL', 0)), 'CRITICAL')}")
    print(f"  {'HIGH':<20} {c(str(counts.get('HIGH', 0)), 'HIGH')}")
    print(f"  {'MEDIUM':<20} {c(str(counts.get('MEDIUM', 0)), 'MEDIUM')}")
    print(f"  {'LOW':<20} {c(str(counts.get('LOW', 0)), 'LOW')}")

    if evaluation.get("failure_reasons"):
        print(f"\n  {c('FAILURE REASONS:', 'RED')}")
        for reason in evaluation["failure_reasons"]:
            print(f"    {c('!!', 'RED')} {reason}")

    print()


def validate_target(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def run_scan(args) -> int:
    print_banner()
    target = validate_target(args.target)
    out_dir = args.out_dir
    verbose = args.verbose

    print(f"  Target  : {c(target, 'BOLD')}")
    print(f"  Output  : {out_dir}")
    print(f"  ZAP     : {'Enabled' if args.zap else 'Disabled'}")
    print(f"  Started : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

    all_findings = []
    start_time = time.time()

    print_section("SSL / TLS CHECKS")
    ssl_findings = run_ssl_check(target)
    all_findings.extend(ssl_findings)
    for f in ssl_findings:
        print_finding(f, verbose)
    print(f"  → {len(ssl_findings)} finding(s)")

    print_section("HTTP SECURITY HEADERS")
    header_findings = run_header_check(target)
    all_findings.extend(header_findings)
    for f in header_findings:
        print_finding(f, verbose)
    print(f"  → {len(header_findings)} finding(s)")

    print_section("PORT SCAN")
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0]
    port_findings = run_port_scan(hostname)
    all_findings.extend(port_findings)
    for f in port_findings:
        print_finding(f, verbose)
    print(f"  → {len(port_findings)} finding(s)")

    if args.zap:
        print_section("OWASP ZAP DAST SCAN")
        print("  Running ZAP baseline scan — this may take several minutes...")
        zap_findings = run_zap_scan(
            target,
            use_api=args.zap_api,
            zap_host=args.zap_host,
            api_key=args.zap_api_key,
        )
        all_findings.extend(zap_findings)
        for f in zap_findings:
            print_finding(f, verbose)
        print(f"  → {len(zap_findings)} finding(s)")

    custom_thresholds = None
    if args.threshold_critical is not None or args.threshold_high is not None:
        custom_thresholds = {
            "CRITICAL": args.threshold_critical if args.threshold_critical is not None else 0,
            "HIGH":     args.threshold_high     if args.threshold_high     is not None else 2,
            "MEDIUM":   args.threshold_medium   if args.threshold_medium   is not None else 10,
            "LOW":      999,
        }

    evaluation = evaluate(all_findings, custom_thresholds)

    json_path, html_path = generate_reports(target, all_findings, evaluation, out_dir)

    elapsed = time.time() - start_time
    print_summary(evaluation)

    print_section("REPORTS GENERATED")
    print(f"  JSON : {json_path}")
    print(f"  HTML : {html_path}")
    print(f"  Time : {elapsed:.1f}s")
    print()

    return evaluation["exit_code"]


def main():
    parser = argparse.ArgumentParser(
        description="DevSecOps Automated Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target https://example.com
  python main.py --target https://example.com --zap
  python main.py --target https://example.com --verbose --out-dir C:\\reports
  python main.py --target https://example.com --threshold-critical 0 --threshold-high 1
        """
    )

    parser.add_argument("--target",              required=True, help="Target URL to scan (e.g. https://example.com)")
    parser.add_argument("--out-dir",             default="reports", help="Output directory for reports (default: reports)")
    parser.add_argument("--verbose", "-v",       action="store_true", help="Show recommendations for each finding")
    parser.add_argument("--zap",                 action="store_true", help="Enable OWASP ZAP DAST scan (requires Docker)")
    parser.add_argument("--zap-api",             action="store_true", help="Use ZAP API instead of Docker")
    parser.add_argument("--zap-host",            default="http://localhost:8090", help="ZAP API host (default: http://localhost:8090)")
    parser.add_argument("--zap-api-key",         default="", help="ZAP API key")
    parser.add_argument("--threshold-critical",  type=int, default=None, help="Max allowed CRITICAL findings (default: 0)")
    parser.add_argument("--threshold-high",      type=int, default=None, help="Max allowed HIGH findings (default: 2)")
    parser.add_argument("--threshold-medium",    type=int, default=None, help="Max allowed MEDIUM findings (default: 10)")
    parser.add_argument("--output-json",         action="store_true", help="Print JSON evaluation to stdout (for CI parsing)")

    args = parser.parse_args()

    if sys.platform == "win32":
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        os.system("color")

    exit_code = run_scan(args)

    if args.output_json:
        latest = os.path.join(args.out_dir, "scan_report_latest.json")
        if os.path.exists(latest):
            with open(latest, encoding="utf-8") as f:
                data = json.load(f)
            print(json.dumps(data.get("evaluation", {}), indent=2))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()