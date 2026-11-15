from __future__ import annotations

import argparse
import ast
import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

from pysast import scan
from pysast.config import load


def git(args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def checkout(repo, sha, dest):
    if not (dest / ".git").is_dir():
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)
        git(["init", "-q"], dest)
        git(["remote", "add", "origin", repo], dest)
    if git(["cat-file", "-e", sha + "^{commit}"], dest).returncode != 0:
        r = git(["fetch", "-q", "--depth", "1", "origin", sha], dest)
        if r.returncode != 0:
            sys.exit(f"could not fetch {sha} from {repo}: {r.stderr.strip()}")
    git(["checkout", "-q", "--force", sha], dest)
    git(["clean", "-qfdx"], dest)


def functions(tree):
    spans = []

    def walk(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                spans.append((child.lineno, child.end_lineno, prefix + child.name))
                walk(child, prefix + child.name + ".")
            elif isinstance(child, ast.ClassDef):
                walk(child, prefix + child.name + ".")
            else:
                walk(child, prefix)

    walk(tree, "")
    return spans


def owner(project, spans, rel, line):
    if rel not in spans:
        mod = project.by_rel.get(rel)
        spans[rel] = functions(mod.tree) if mod is not None else []
    best = None
    for a, b, name in spans[rel]:
        if a <= line <= b and (best is None or a >= best[0]):
            best = (a, name)
    return f"{rel}:{best[1]}" if best else rel


def hits(case, root):
    cfg = load()
    cfg["analysis"]["exclude"] = ["**/tests/**", "**/test/**", "tests/**", "test/**"]
    cfg["report"]["max_trace_steps"] = 100
    result = scan(root, cfg)
    spans = {}
    sinks, entry = [], []
    for f in result.findings:
        if f.rule != case["rule"]:
            continue
        touched = {owner(result.project, spans, s.file, s.line) for s in f.trace}
        if f.source is not None:
            touched.add(owner(result.project, spans, f.source.file, f.source.line))
        if not touched & set(case["entry"]):
            continue
        entry.append((f.file, f.func, f.line))
        if f"{f.file}:{f.func}" in case["sinks"]:
            sinks.append((f.file, f.func, f.line))
    return sinks, entry, result.seconds


def main():
    ap = argparse.ArgumentParser(description="Scan real CVEs before and after their fix commits.")
    ap.add_argument("--cases", default=str(Path(__file__).with_name("cves.toml")))
    ap.add_argument("--only", help="comma separated CVE ids")
    ap.add_argument("--json", help="also write the results to this file")
    args = ap.parse_args()
    with open(args.cases, "rb") as f:
        cases = tomllib.load(f)["case"]
    if args.only:
        keep = set(args.only.split(","))
        cases = [c for c in cases if c["cve"] in keep]
    cache = Path(load()["bench"]["cache_dir"]).resolve() / "cves"
    rows = []
    for case in cases:
        dest = cache / case["cve"]
        checkout(case["repo"], case["vulnerable"], dest)
        before, _, t1 = hits(case, dest)
        checkout(case["repo"], case["fixed"], dest)
        _, after, t2 = hits(case, dest)
        quiet = bool(before) and not after
        rows.append({"cve": case["cve"], "project": case["project"], "rule": case["rule"], "flagged": bool(before), "quiet_after_fix": quiet, "before": before, "after": after, "seconds": round(t1 + t2, 1)})
        print(f"{case['cve']:<16} {case['project']:<24} {case['rule']:<15} flagged={'yes' if before else 'no':<4} quiet_after_fix={'yes' if quiet else 'no'}", flush=True)
    flagged = sum(r["flagged"] for r in rows)
    quiet = sum(r["quiet_after_fix"] for r in rows)
    print(f"\n{flagged} of {len(rows)} vulnerable commits flagged, {quiet} of {flagged} quiet after the fix")
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
