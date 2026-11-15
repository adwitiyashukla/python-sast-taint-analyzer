from __future__ import annotations

import ast
import fnmatch
import os
import warnings
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env", ".tox", ".nox", "node_modules", "site-packages", ".mypy_cache", ".pytest_cache", ".ruff_cache", "build", "dist"}


@dataclass
class Module:
    name: str
    path: Path
    rel: str
    source: str
    tree: ast.Module
    lines: list = field(default_factory=list)
    imports: set = field(default_factory=set)


class Project:
    def __init__(self, target, exclude=()):
        target = Path(target).resolve()
        self.root = target if target.is_dir() else target.parent
        self.modules = {}
        self.errors = []
        files = [target] if target.is_file() else self.discover(self.root, exclude)
        for f in sorted(files):
            self.load(f)
        self.by_rel = {m.rel: m for m in self.modules.values()}
        self.prefixes = set()
        for name in self.modules:
            parts = name.split(".")
            for i in range(1, len(parts) + 1):
                self.prefixes.add(".".join(parts[:i]))
        packages = {name for name, m in self.modules.items() if m.rel.endswith("__init__.py")}
        self.suffix_index = {}
        for name in self.modules:
            parts = name.split(".")
            for i in range(1, len(parts)):
                if ".".join(parts[:i]) not in packages:
                    self.suffix_index.setdefault(".".join(parts[i:]), []).append(name)

    @staticmethod
    def discover(root, exclude):
        out = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                p = Path(dirpath) / fn
                rel = p.relative_to(root).as_posix()
                if any(fnmatch.fnmatch(rel, pat) for pat in exclude):
                    continue
                out.append(p)
        return out

    def load(self, path):
        rel = path.relative_to(self.root).as_posix()
        parts = rel[:-3].split("/")
        if parts[-1] == "__init__":
            parts = parts[:-1]
        name = ".".join(parts) if parts else path.stem
        try:
            source = path.read_bytes().decode("utf-8", errors="replace")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                tree = ast.parse(source, filename=rel)
        except (SyntaxError, ValueError) as exc:
            self.errors.append((rel, str(exc)))
            return
        mod = Module(name, path, rel, source, tree, source.splitlines())
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mod.imports.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
                mod.imports.add(n.module.split(".")[0])
        self.modules[name] = mod

    def resolve(self, name, importer=None):
        if importer is not None:
            parts = importer.name.split(".")
            pkg = parts if importer.rel.endswith("__init__.py") else parts[:-1]
            if pkg and ".".join(pkg) not in self.modules:
                cand = ".".join(pkg + [name])
                if cand in self.prefixes:
                    return cand
        if name in self.prefixes:
            return name
        hits = self.suffix_index.get(name)
        if hits and len(hits) == 1:
            return hits[0]
        return None

    def relative(self, mod, level, name):
        base = mod.name.split(".")
        if not mod.rel.endswith("__init__.py"):
            base = base[:-1]
        if level > 1:
            base = base[: len(base) - (level - 1)]
        full = ".".join(base + ([name] if name else []))
        return full
