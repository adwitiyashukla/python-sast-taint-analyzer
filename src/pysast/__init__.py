from __future__ import annotations

import time
from dataclasses import dataclass

__version__ = "0.1.0"


@dataclass
class Result:
    findings: list
    project: object
    analyzer: object
    seconds: float
    started: float
    suppressed: int


def deep(fn):
    import sys
    import threading

    box = {}

    def work():
        try:
            box["value"] = fn()
        except BaseException as exc:
            box["error"] = exc

    old_limit = sys.getrecursionlimit()
    old_stack = threading.stack_size()
    sys.setrecursionlimit(20000)
    try:
        threading.stack_size(256 * 1024 * 1024)
    except ValueError:
        threading.stack_size(128 * 1024 * 1024)
    try:
        t = threading.Thread(target=work, daemon=True)
        t.start()
        while t.is_alive():
            t.join(0.2)
    finally:
        threading.stack_size(old_stack)
        sys.setrecursionlimit(old_limit)
    if "error" in box:
        raise box["error"]
    return box["value"]


def scan(target, config=None):
    from pathlib import Path

    from . import report
    from .config import load
    from .engine import Analyzer
    from .library import Library
    from .project import Project
    from .rules import RULES, SEVERITY_ORDER, severity

    base = Path(target)
    cfg = config if config is not None else load(project=base if base.is_dir() else base.parent)
    started = time.time()
    project = Project(target, cfg["analysis"]["exclude"])
    library = Library(cfg, cfg["models"]["files"])
    analyzer = Analyzer(project, cfg, library)
    raw = deep(analyzer.run)
    enabled = set(cfg["rules"]["enable"]) or set(RULES)
    enabled -= set(cfg["rules"]["disable"])
    floor = SEVERITY_ORDER[cfg["report"]["min_severity"]]
    kept = [f for f in raw.values() if f["rule"] in enabled and SEVERITY_ORDER[severity(f["rule"])] >= floor]
    kept.sort(key=lambda f: (f["loc"][0], f["loc"][1], f["loc"][2], f["rule"], f["source"].line if f["source"] else 0))
    findings = report.build(project, kept)
    findings, suppressed = report.apply_suppressions(project, findings)
    return Result(findings, project, analyzer, time.time() - started, started, suppressed)
