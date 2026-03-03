import os
import sys
import json
import yaml
import argparse
import hashlib
import pyfiglet
from rich.console import Console
from rich.table import Table
from rich.text import Text
from jinja2 import Environment, FileSystemLoader
from scanner import Scanner
from rule_engine import RuleEngine

console = Console()


# -------------------------------------------------
# Banner
# -------------------------------------------------
def print_banner():
    banner = pyfiglet.figlet_format("APKSensify", font="slant")
    console.print(f"[bold magenta]{banner}[/bold magenta]")
    console.print("[grey54]Soft Launch: Beta v1.0[/grey54]\n\n")
    console.print("[bold chartreuse1]Running the Scans...[/bold chartreuse1]\n")


# -------------------------------------------------
# Severity Style
# -------------------------------------------------
def get_severity_style(severity):
    styles = {
        "critical": "bold dark_red",
        "high": "bold bright_red",
        "medium": "bold bright_yellow",
        "low": "bold yellow1",
        "info": "bold bright_black"
    }
    return styles.get(severity.lower(), "bold white")


# -------------------------------------------------
# Summary Table
# -------------------------------------------------
def print_summary_table(summary):

    if not summary:
        console.print("[bold green]No secrets found.[/bold green]")
        return

    table = Table(title="Scan Summary", header_style="bold cyan")
    table.add_column("Severity")
    table.add_column("Count")

    for sev, count in summary.items():
        table.add_row(sev, str(count))

    console.print(table)


# -------------------------------------------------
# HTML Report
# -------------------------------------------------
def generate_html_report(findings, summary):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report.html")
    html = template.render(findings=findings, summary=summary)

    with open("report.html", "w") as f:
        f.write(html)

    console.print("[bold green]HTML report generated: report.html[/bold green]")


# -------------------------------------------------
# SARIF Report
# -------------------------------------------------
def generate_sarif(findings):

    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "APKSensify",
                    "informationUri": "https://github.com/yourrepo"
                }
            },
            "results": []
        }]
    }

    for f in findings:
        for match in f["matches"]:
            sarif["runs"][0]["results"].append({
                "ruleId": f["rule"],
                "level": f["severity"].lower(),
                "message": {"text": match},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]}
                    }
                }]
            })

    with open("report.sarif", "w") as file:
        json.dump(sarif, file, indent=4)

    console.print("[bold green]SARIF report generated: report.sarif[/bold green]")


# -------------------------------------------------
# Exploit Mode
# -------------------------------------------------
def run_exploit(rule_name):
    exploit_path = os.path.join("rules", "exploit.yaml")

    if not os.path.isfile(exploit_path):
        console.print("[bold red]exploit.yaml not found![/bold red]")
        sys.exit(1)

    with open(exploit_path) as f:
        exploits = yaml.safe_load(f)

    if rule_name not in exploits:
        console.print(f"[bold bright_red]No exploit steps for {rule_name}[/bold bright_red]")
        sys.exit(1)

    console.print(f"\n[bold yellow]Exploit Steps for {rule_name}:[/bold yellow]\n")

    for step in exploits[rule_name]:
        console.print(f" - {step}")

    sys.exit(0)


# -------------------------------------------------
# Caching Helpers
# -------------------------------------------------
def get_file_hash(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


def load_from_cache(apk_hash):
    cache_dir = ".cache"
    cached_file = os.path.join(cache_dir, apk_hash + ".json")

    if os.path.exists(cached_file):
        console.print("[cyan]Using cached results...[/cyan]\n")
        with open(cached_file) as f:
            return json.load(f)

    return None


def save_to_cache(apk_hash, findings):
    cache_dir = ".cache"
    os.makedirs(cache_dir, exist_ok=True)

    cached_file = os.path.join(cache_dir, apk_hash + ".json")

    with open(cached_file, "w") as f:
        json.dump(findings, f)


# -------------------------------------------------
# Scan Wrapper
# -------------------------------------------------
def run_scan(apk_path, json_output=False, html=False, sarif=False, no_cache=False):

    if not os.path.isfile(apk_path):
        console.print(f"[bold red]APK not found: {apk_path}[/bold red]")
        sys.exit(1)

    apk_hash = get_file_hash(apk_path)

    engine = RuleEngine()
    scanner = Scanner(engine.rules)

    findings = None

    # 🔥 NEW LOGIC
    if not no_cache:
        findings = load_from_cache(apk_hash)

    if findings is None:
        findings, summary, critical_found = scanner.scan(apk_path)
        save_to_cache(apk_hash, findings)
    else:
        summary = {}
        critical_found = False

    # rebuild summary
    summary = {}
    critical_found = False

    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + len(f["matches"])
        if f["severity"].lower() == "critical":
            critical_found = True

    # Verbose output
    if not json_output:
        for f in findings:
            style = get_severity_style(f["severity"])
            header = Text(f"[!] {f['rule']} ({f['severity']})")
            header.stylize(style)

            console.print(header)
            console.print(f"    File: {f['file']}")

            for m in f["matches"]:
                console.print(f"    → {m}")

            console.print()

        print_summary_table(summary)
        console.print("\n[bold green][✓] Scan completed.[/bold green]")

    else:
        print(json.dumps(findings, indent=4))

    if html:
        generate_html_report(findings, summary)

    if sarif:
        generate_sarif(findings)

    sys.exit(2 if critical_found else 0)


# -------------------------------------------------
# Main
# -------------------------------------------------
def main():

    parser = argparse.ArgumentParser(description="APKSensify Static Scanner")
    parser.add_argument("apk", nargs="?", help="Path to APK file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--sarif", action="store_true", help="Generate SARIF report")
    parser.add_argument("--exploit", help="Show exploit steps only")
    parser.add_argument("--no-cache", action="store_true", help="Run fresh scan (ignore cache)")

    args = parser.parse_args()

    print_banner()

    if args.exploit:
        run_exploit(args.exploit)

    if not args.apk:
        console.print("[bold yellow]Usage:[/bold yellow] python apksensify.py <apk_path>")
        sys.exit(1)

    run_scan(
        apk_path=args.apk,
        json_output=args.json,
        html=args.html,
        sarif=args.sarif,
        no_cache=args.no_cache
    )


if __name__ == "__main__":
    main()
