from __future__ import annotations

import copy
import tomllib
from importlib import resources
from pathlib import Path


class ConfigError(Exception):
    pass


def _int(lo, hi):
    def check(v):
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            raise ConfigError(f"must be an integer from {lo} to {hi}")
    return check


def _choice(*options):
    def check(v):
        if v not in options:
            raise ConfigError("must be one of " + ", ".join(options))
    return check


def _strings(v):
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError("must be a list of strings")


def _string(v):
    if not isinstance(v, str) or not v:
        raise ConfigError("must be a non-empty string")


def _bool(v):
    if not isinstance(v, bool):
        raise ConfigError("must be true or false")


SCHEMA = {
    "analysis": {
        "max_call_depth": _int(1, 64),
        "max_contexts": _int(1, 10000),
        "max_alternatives": _int(2, 64),
        "max_string_parts": _int(4, 512),
        "max_list_items": _int(1, 1024),
        "max_chars": _int(1, 512),
        "widen_after": _int(1, 50),
        "function_budget": _int(100, 1000000),
        "exclude": _strings,
    },
    "rules": {
        "enable": _strings,
        "disable": _strings,
        "weak_random": _choice("sensitive", "always", "off"),
        "sensitive_names": _strings,
        "argument_injection": _bool,
    },
    "report": {
        "format": _choice("text", "json", "sarif"),
        "min_severity": _choice("low", "medium", "high"),
        "max_trace_steps": _int(2, 100),
    },
    "models": {
        "files": _strings,
    },
    "bench": {
        "owasp_repo": _string,
        "owasp_commit": _string,
        "semgrep_rules_repo": _string,
        "semgrep_rules_commit": _string,
        "cache_dir": _string,
        "split_at": _int(1, 100000),
    },
}


def defaults():
    text = resources.files("pysast").joinpath("config.toml").read_text(encoding="utf-8")
    return tomllib.loads(text)


def merge(base, extra, origin):
    out = copy.deepcopy(base)
    for section, table in extra.items():
        if section not in SCHEMA:
            raise ConfigError(f"{origin}: unknown section [{section}]")
        if not isinstance(table, dict):
            raise ConfigError(f"{origin}: [{section}] must be a table")
        for key, value in table.items():
            if key not in SCHEMA[section]:
                raise ConfigError(f"{origin}: unknown key {section}.{key}")
            out[section][key] = value
    return out


def validate(cfg):
    from .rules import RULES

    for section, keys in SCHEMA.items():
        if section not in cfg:
            raise ConfigError(f"missing section [{section}]")
        for key, check in keys.items():
            if key not in cfg[section]:
                raise ConfigError(f"missing key {section}.{key}")
            try:
                check(cfg[section][key])
            except ConfigError as exc:
                raise ConfigError(f"{section}.{key} {exc}") from None
    for key in ("enable", "disable"):
        unknown = [r for r in cfg["rules"][key] if r not in RULES]
        if unknown:
            raise ConfigError(f"rules.{key} has unknown rule ids: {', '.join(unknown)}")
    return cfg


def load(path=None, project=None):
    cfg = defaults()
    if project is not None:
        pyproject = Path(project) / "pyproject.toml"
        if pyproject.is_file():
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
            tool = data.get("tool", {}).get("pysast")
            if tool:
                cfg = merge(cfg, tool, str(pyproject))
    if path is not None:
        with open(path, "rb") as f:
            cfg = merge(cfg, tomllib.load(f), str(path))
    return validate(cfg)
