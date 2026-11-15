from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__, report, scan
from .config import ConfigError, load
from .rules import RULES, severity


def parse(argv):
    parser = argparse.ArgumentParser(prog="pysast", description="Taint analysis for Python web apps.")
    parser.add_argument("--version", action="version", version=f"pysast {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="scan a file or a folder")
    s.add_argument("path")
    s.add_argument("--format", choices=["text", "json", "sarif"])
    s.add_argument("--output", "-o")
    s.add_argument("--config")
    s.add_argument("--min-severity", choices=["low", "medium", "high"])
    s.add_argument("--rules", help="comma separated rule ids to run")
    s.add_argument("--baseline", help="hide findings already in this baseline file")
    s.add_argument("--write-baseline", help="write all current findings to a baseline file")
    s.add_argument("--exit-zero", action="store_true", help="exit with 0 even when there are findings")
    sub.add_parser("rules", help="list the rules")
    return parser.parse_args(argv)


def list_rules():
    width = max(len(r) for r in RULES)
    lines = []
    for rid in sorted(RULES):
        r = RULES[rid]
        lines.append(f"{rid:<{width}}  CWE-{r.cwe:<5} {severity(rid):<6}  {r.title}")
    return "\n".join(lines) + "\n"


def main(argv=None):
    args = parse(sys.argv[1:] if argv is None else argv)
    if args.command == "rules":
        sys.stdout.write(list_rules())
        return 0
    target = Path(args.path)
    if not target.exists():
        sys.stderr.write(f"pysast: {args.path} does not exist\n")
        return 2
    try:
        cfg = load(args.config, project=target if target.is_dir() else target.parent)
        if args.min_severity:
            cfg["report"]["min_severity"] = args.min_severity
        if args.format:
            cfg["report"]["format"] = args.format
        if args.rules:
            picked = [r.strip() for r in args.rules.split(",") if r.strip()]
            unknown = [r for r in picked if r not in RULES]
            if unknown:
                raise ConfigError("unknown rule ids: " + ", ".join(unknown))
            cfg["rules"]["enable"] = picked
    except (ConfigError, OSError, ValueError) as exc:
        sys.stderr.write(f"pysast: {exc}\n")
        return 2
    result = scan(target, cfg)
    findings = result.findings
    if args.write_baseline:
        report.write_baseline(args.write_baseline, findings)
    if args.baseline:
        try:
            known = report.load_baseline(args.baseline)
        except (OSError, ValueError) as exc:
            sys.stderr.write(f"pysast: {exc}\n")
            return 2
        findings = [f for f in findings if f.fingerprint not in known]
    files = len(result.project.modules)
    fmt = cfg["report"]["format"]
    if fmt == "json":
        out = report.as_json(result.project, findings, result.seconds, files, result.project.errors)
    elif fmt == "sarif":
        out = report.sarif(result.project, findings, result.started, time.time())
    else:
        out = report.text(result.project, findings, result.seconds, files, result.project.errors)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
    if findings and not args.exit_zero:
        return 1
    return 0
