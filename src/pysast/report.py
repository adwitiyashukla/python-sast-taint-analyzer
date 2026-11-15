from __future__ import annotations

import hashlib
import io
import json
import os
import re
import tokenize
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .rules import RULES, severity

SUPPRESS = re.compile(r"pysast:\s*ignore(?:\[([a-z0-9,\s-]+)\])?")
LEVELS = {"high": "error", "medium": "warning", "low": "note"}


@dataclass
class Finding:
    rule: str
    file: str
    line: int
    col: int
    end_line: int
    end_col: int
    func: str
    label: str
    source: object
    trace: tuple
    fingerprint: str = ""

    @property
    def severity(self):
        return severity(self.rule)

    @property
    def cwe(self):
        return RULES[self.rule].cwe

    @property
    def title(self):
        return RULES[self.rule].title

    def message(self):
        r = RULES[self.rule]
        if self.source is None:
            return f"{r.title}: {self.label}"
        where = f"line {self.source.line}" if self.source.file == self.file else f"{self.source.file}:{self.source.line}"
        return f"{r.title}: {self.source.label} ({where}) reaches {self.label}"


def line_text(project, rel, line):
    mod = project.by_rel.get(rel)
    if mod is None or not 1 <= line <= len(mod.lines):
        return ""
    return mod.lines[line - 1].strip()


def fingerprint(project, f):
    parts = [f.rule, f.file, f.func, " ".join(line_text(project, f.file, f.line).split())]
    if f.source is not None:
        parts.append(f.source.label)
        parts.append(f.source.file)
        parts.append(" ".join(line_text(project, f.source.file, f.source.line).split()))
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]


def build(project, raw):
    out = []
    for r in raw:
        file, line, col, end_line, end_col, func = r["loc"]
        f = Finding(r["rule"], file, line, col, end_line, end_col, func, r["label"], r["source"], tuple(r["trace"]))
        f.fingerprint = fingerprint(project, f)
        out.append(f)
    seen = set()
    counts = {}
    unique = []
    for f in out:
        src = f.source
        key = (f.rule, f.file, f.line, f.col, src.file, src.line, src.col) if src is not None else (f.rule, f.file, f.line, f.col)
        if key in seen:
            continue
        seen.add(key)
        n = counts[f.fingerprint] = counts.get(f.fingerprint, 0) + 1
        if n > 1:
            f.fingerprint = hashlib.sha256(f"{f.fingerprint}:{n}".encode()).hexdigest()[:20]
        unique.append(f)
    return unique


def suppressed_lines(project, rel):
    mod = project.by_rel.get(rel)
    out = {}
    if mod is None:
        return out
    try:
        tokens = tokenize.generate_tokens(io.StringIO(mod.source).readline)
        for tok in tokens:
            if tok.type != tokenize.COMMENT:
                continue
            m = SUPPRESS.search(tok.string)
            if m:
                rules = {x.strip() for x in m.group(1).split(",")} if m.group(1) else None
                out[tok.start[0]] = rules
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return out


def apply_suppressions(project, findings):
    cache = {}
    kept = []
    dropped = 0
    for f in findings:
        if f.file not in cache:
            cache[f.file] = suppressed_lines(project, f.file)
        marks = cache[f.file]
        hit = False
        for line in (f.line, f.line - 1):
            if line in marks and (marks[line] is None or f.rule in marks[line]):
                hit = True
        if hit:
            dropped += 1
        else:
            kept.append(f)
    return kept, dropped


def load_baseline(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("fingerprints"), list):
        raise ValueError(f"{path} is not a pysast baseline file")
    return set(data["fingerprints"])


def write_baseline(path, findings):
    data = {"version": 1, "fingerprints": sorted(f.fingerprint for f in findings)}
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def steps(project, f):
    out = []
    seen = set()
    for s in f.trace:
        key = (s.file, s.line)
        if key in seen:
            continue
        seen.add(key)
        out.append((s.file, s.line, s.col, s.note))
    key = (f.file, f.line)
    if key not in seen:
        out.append((f.file, f.line, f.col, f.label))
    return out


def text(project, findings, elapsed, files, errors, color=False):
    buf = io.StringIO()
    paint = {"high": "\x1b[31m", "medium": "\x1b[33m", "low": "\x1b[36m"} if color else {}
    reset = "\x1b[0m" if color else ""
    for f in findings:
        sev = f.severity
        buf.write(f"{f.file}:{f.line}:{f.col}  {paint.get(sev, '')}{sev}{reset}  {f.rule}  {f.message()}\n")
        if f.source is not None:
            for file, line, _, _ in steps(project, f):
                prefix = "" if file == f.file else f"{file}:"
                buf.write(f"    {prefix}{line:>5} | {line_text(project, file, line)}\n")
        else:
            buf.write(f"    {f.line:>5} | {line_text(project, f.file, f.line)}\n")
        buf.write("\n")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("high", "medium", "low")}
    parts = ", ".join(f"{n} {s}" for s, n in counts.items() if n)
    noun = "finding" if len(findings) == 1 else "findings"
    summary = f"{len(findings)} {noun}" + (f" ({parts})" if parts else "")
    buf.write(f"{summary} in {files} files, {elapsed:.1f}s\n")
    for rel, msg in errors:
        buf.write(f"skipped {rel}: {msg}\n")
    return buf.getvalue()


def as_json(project, findings, elapsed, files, errors):
    items = []
    for f in findings:
        item = {
            "rule": f.rule,
            "cwe": f.cwe,
            "severity": f.severity,
            "title": f.title,
            "message": f.message(),
            "file": f.file,
            "line": f.line,
            "column": f.col,
            "end_line": f.end_line,
            "end_column": f.end_col,
            "function": f.func,
            "fingerprint": f.fingerprint,
        }
        if f.source is not None:
            item["source"] = {"label": f.source.label, "file": f.source.file, "line": f.source.line}
            item["trace"] = [{"file": a, "line": b, "column": c, "note": d, "code": line_text(project, a, b)} for a, b, c, d in steps(project, f)]
        items.append(item)
    data = {
        "tool": "pysast",
        "version": __version__,
        "files": files,
        "seconds": round(elapsed, 3),
        "findings": items,
        "skipped": [{"file": a, "reason": b} for a, b in errors],
    }
    return json.dumps(data, indent=2) + "\n"


def sarif_uri(project, rel):
    full = project.root / rel
    try:
        r = os.path.relpath(full, Path.cwd())
    except ValueError:
        return rel
    if r.startswith(".."):
        return rel
    return Path(r).as_posix()


def location(project, file, line, col, end_line=None, end_col=None):
    region = {"startLine": line, "startColumn": max(col, 1)}
    if end_line:
        region["endLine"] = end_line
        if end_col and (end_line > line or end_col > col):
            region["endColumn"] = end_col
    return {"physicalLocation": {"artifactLocation": {"uri": sarif_uri(project, file)}, "region": region}}


def sarif(project, findings, started, finished):
    ids = sorted(RULES)
    index = {r: i for i, r in enumerate(ids)}
    rules = []
    for rid in ids:
        r = RULES[rid]
        rules.append({
            "id": rid,
            "name": r.title.replace(" ", "").replace("-", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.summary},
            "help": {"text": r.fix, "markdown": f"{r.title} (CWE-{r.cwe})\n\n{r.summary}\n\nFix: {r.fix}"},
            "defaultConfiguration": {"level": LEVELS[severity(rid)]},
            "properties": {"tags": ["security", f"external/cwe/cwe-{r.cwe}"], "precision": "high", "security-severity": f"{r.score:.1f}"},
        })
    results = []
    for f in findings:
        res = {
            "ruleId": f.rule,
            "ruleIndex": index[f.rule],
            "level": LEVELS[f.severity],
            "message": {"text": f.message()},
            "locations": [location(project, f.file, f.line, f.col, f.end_line, f.end_col)],
            "partialFingerprints": {"pysast/v1": f.fingerprint},
        }
        if f.source is not None:
            flow = []
            for file, line, col, note in steps(project, f):
                loc = location(project, file, line, col)
                loc["message"] = {"text": note}
                flow.append({"location": loc})
            res["codeFlows"] = [{"threadFlows": [{"locations": flow}]}]
        results.append(res)
    run = {
        "tool": {"driver": {"name": "pysast", "version": __version__, "semanticVersion": __version__, "informationUri": "https://github.com/adwitiyashukla/python-sast-taint-analyzer", "rules": rules}},
        "invocations": [{"executionSuccessful": True, "startTimeUtc": stamp(started), "endTimeUtc": stamp(finished)}],
        "results": results,
    }
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]}
    return json.dumps(doc, indent=2) + "\n"


def stamp(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
