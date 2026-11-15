from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

from pysast import scan
from pysast.config import load
from pysast.rules import RULES

SEMGREP_CWE = {22: 22, 23: 22, 35: 22, 78: 78, 79: 79, 80: 79, 89: 89, 90: 90, 326: 327, 327: 327, 329: 327, 696: 327, 328: 328, 330: 330, 338: 330, 501: 501, 611: 611, 614: 614, 643: 643, 1004: 1004}

BANDIT_CATEGORY = {
    "B102": 94, "B307": 94, "B303": 328, "B324": 328, "B311": 330, "B301": 502, "B403": 502, "B506": 502,
    "B602": 78, "B603": 78, "B604": 78, "B605": 78, "B606": 78, "B607": 78, "B404": 78, "B608": 89,
    "B313": 611, "B314": 611, "B315": 611, "B316": 611, "B317": 611, "B318": 611, "B319": 611, "B320": 611,
    "B405": 611, "B406": 611, "B407": 611, "B408": 611, "B409": 611, "B410": 611, "B411": 611,
}

TEST = re.compile(r"(BenchmarkTest\d+)\.py$")


def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def fetch(repo, commit, dest):
    if (dest / ".git").is_dir() and run(["git", "rev-parse", "HEAD"], cwd=dest).stdout.strip() == commit:
        return dest
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for cmd in (["git", "init", "-q"], ["git", "remote", "add", "origin", repo], ["git", "fetch", "-q", "--depth", "1", "origin", commit], ["git", "checkout", "-q", "FETCH_HEAD"]):
        r = run(cmd, cwd=dest)
        if r.returncode != 0:
            sys.exit(f"git failed: {' '.join(cmd)}\n{r.stderr}")
    return dest


def expected(root):
    out = {}
    with open(root / "expectedresults-0.1.csv", newline="") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            out[row[0]] = (row[1], row[2].strip() == "true", int(row[3]))
    return out


def pysast_hits(root):
    result = scan(root)
    strict = defaultdict(set)
    for f in result.findings:
        m = TEST.search(f.file)
        if m:
            strict[m.group(1)].add(RULES[f.rule].cwe)
    return strict, strict, result.seconds


def bandit_hits(root, out):
    start = time.time()
    r = run([sys.executable, "-m", "bandit", "-q", "-r", "testcode", "helpers", "-f", "json", "-o", str(out)], cwd=root)
    if not out.exists():
        print("bandit did not run:", r.stderr.strip()[:300])
        return None
    seconds = time.time() - start
    strict, loose = defaultdict(set), defaultdict(set)
    for item in json.loads(out.read_text())["results"]:
        m = TEST.search(item["filename"])
        if not m:
            continue
        cwe = item.get("issue_cwe", {}).get("id")
        if cwe:
            strict[m.group(1)].add(cwe)
            loose[m.group(1)].add(cwe)
        if item["test_id"] in BANDIT_CATEGORY:
            loose[m.group(1)].add(BANDIT_CATEGORY[item["test_id"]])
    return strict, loose, seconds


def semgrep_hits(root, rules, out):
    exe = shutil.which("semgrep")
    if exe is None:
        print("semgrep is not installed, skipping it")
        return None
    start = time.time()
    run([exe, "--config", str(rules / "python"), "--metrics=off", "--disable-version-check", "--json", "-o", str(out), "testcode", "helpers"], cwd=root)
    if not out.exists():
        print("semgrep did not run")
        return None
    seconds = time.time() - start
    strict, loose = defaultdict(set), defaultdict(set)
    for item in json.loads(out.read_text())["results"]:
        m = TEST.search(item["path"])
        if not m:
            continue
        cwe = item["extra"].get("metadata", {}).get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        if not cwe:
            continue
        found = re.search(r"\d+", str(cwe))
        if not found:
            continue
        n = SEMGREP_CWE.get(int(found.group(0)), int(found.group(0)))
        strict[m.group(1)].add(n)
        loose[m.group(1)].add(n)
        check = item["check_id"].lower()
        if n == 95:
            loose[m.group(1)].add(94)
        if n == 327 and any(w in check for w in ("hash", "md5", "sha1")):
            loose[m.group(1)].add(328)
    return strict, loose, seconds


def score(exp, hits, tests):
    cats = defaultdict(lambda: [0, 0, 0, 0])
    for t in tests:
        cat, real, cwe = exp[t]
        hit = cwe in hits.get(t, ())
        c = cats[cat]
        if real:
            c[0 if hit else 1] += 1
        else:
            c[2 if hit else 3] += 1
    out = {}
    for cat, (tp, fn, fp, tn) in sorted(cats.items()):
        tpr = tp / (tp + fn) if tp + fn else None
        fpr = fp / (fp + tn) if fp + tn else None
        out[cat] = {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "tpr": tpr, "fpr": fpr, "score": None if tpr is None or fpr is None else tpr - fpr}
    scored = [v["score"] for v in out.values() if v["score"] is not None]
    return out, sum(scored) / len(scored)


def pct(x):
    return "   --" if x is None else f"{x * 100:5.1f}"


def table(exp, tools, mode):
    names = list(tools)
    rows = {}
    avgs = {}
    for name in names:
        rows[name], avgs[name] = score(exp, tools[name][0 if mode == "strict" else 1], sorted(exp))
    cats = sorted({c for _, (c, _, _) in exp.items()})
    head = f"{'category':<16}" + "".join(f"  {n:>22}" for n in names)
    lines = [head, f"{'':<16}" + "".join(f"  {'TPR   FPR  score':>22}" for _ in names)]
    for c in cats:
        line = f"{c:<16}"
        for n in names:
            v = rows[n][c]
            line += f"  {pct(v['tpr'])} {pct(v['fpr'])} {pct(v['score']):>6}"
        lines.append(line)
    lines.append(f"{'average':<16}" + "".join(f"  {'':>11}{pct(avgs[n]):>11}" for n in names))
    return "\n".join(lines), rows, avgs


def halves(exp, hits, split):
    out = {}
    for label, keep in (("tests 1 to %d" % split, lambda n: n <= split), ("tests %d to %d" % (split + 1, len(exp)), lambda n: n > split)):
        tests = [t for t in sorted(exp) if keep(int(t[len("BenchmarkTest"):]))]
        wrong = sum(1 for t in tests if (exp[t][2] in hits.get(t, ())) != exp[t][1])
        out[label] = {"tests": len(tests), "wrong": wrong}
    return out


def main():
    ap = argparse.ArgumentParser(description="Score pysast, Bandit and Semgrep on the OWASP Benchmark for Python.")
    ap.add_argument("--tools", default="pysast,bandit,semgrep")
    ap.add_argument("--json", help="also write the scores to this file")
    ap.add_argument("--fail-under", type=float, help="exit with 1 when the pysast average score is lower than this percent")
    args = ap.parse_args()
    cfg = load()["bench"]
    cache = Path(cfg["cache_dir"]).resolve()
    cache.mkdir(parents=True, exist_ok=True)
    root = fetch(cfg["owasp_repo"], cfg["owasp_commit"], cache / "BenchmarkPython")
    exp = expected(root)
    wanted = [t.strip() for t in args.tools.split(",") if t.strip()]
    tools = {}
    if "pysast" in wanted:
        tools["pysast"] = pysast_hits(root)
    if "bandit" in wanted:
        got = bandit_hits(root, cache / "bandit.json")
        if got:
            tools["bandit"] = got
    if "semgrep" in wanted:
        rules = fetch(cfg["semgrep_rules_repo"], cfg["semgrep_rules_commit"], cache / "semgrep-rules")
        got = semgrep_hits(root, rules, cache / "semgrep.json")
        if got:
            tools["semgrep"] = got
    print(f"OWASP Benchmark for Python, {len(exp)} test cases, commit {cfg['owasp_commit'][:12]}\n")
    text, rows, avgs = table(exp, tools, "strict")
    print("Official scoring (a test counts when the tool reports its exact CWE)\n")
    print(text)
    loose_text, loose_rows, loose_avgs = table(exp, tools, "loose")
    print("\nLoose scoring (any finding of the right vulnerability class counts)\n")
    print(loose_text)
    print("\nScan time: " + ", ".join(f"{n} {tools[n][2]:.1f}s" for n in tools))
    if "pysast" in tools:
        h = halves(exp, tools["pysast"][0], cfg["split_at"])
        print("pysast wrong answers: " + ", ".join(f"{k}: {v['wrong']} of {v['tests']}" for k, v in h.items()))
    if args.json:
        data = {"strict": {"rows": rows, "average": avgs}, "loose": {"rows": loose_rows, "average": loose_avgs}, "seconds": {n: tools[n][2] for n in tools}}
        if "pysast" in tools:
            data["halves"] = halves(exp, tools["pysast"][0], cfg["split_at"])
        Path(args.json).write_text(json.dumps(data, indent=2) + "\n")
    if args.fail_under is not None and "pysast" in tools and avgs["pysast"] * 100 < args.fail_under - 1e-9:
        sys.exit(f"pysast average {avgs['pysast'] * 100:.1f} is below {args.fail_under}")


if __name__ == "__main__":
    main()
