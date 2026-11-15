from __future__ import annotations

import re
from dataclasses import dataclass

from .values import NUMERIC, Str


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    cwe: int
    score: float
    fact: str
    summary: str
    fix: str


RULES = {
    r.id: r
    for r in [
        Rule("sqli", "SQL injection", 89, 8.8, "input", "User input is built into a SQL query string.", "Pass values as query parameters instead of formatting them into the SQL text."),
        Rule("cmdi", "Command injection", 78, 9.8, "input", "User input reaches a shell command.", "Pass an argument list without shell=True, or quote the value with shlex.quote."),
        Rule("codeinj", "Code injection", 94, 9.8, "input", "User input is evaluated as Python code.", "Do not eval or exec request data. Use ast.literal_eval or a real parser."),
        Rule("path-traversal", "Path traversal", 22, 7.5, "input", "User input controls a file system path.", "Resolve the path and check it stays inside the base folder, or use a safe join."),
        Rule("xss", "Cross-site scripting", 79, 6.1, "input", "User input is written into an HTML response without escaping.", "Escape the value (html.escape, markupsafe.escape) or render it through a template."),
        Rule("open-redirect", "Open redirect", 601, 6.1, "input", "User input decides where the response redirects.", "Redirect only to relative paths or to hosts on an allowlist."),
        Rule("ldapi", "LDAP injection", 90, 7.5, "input", "User input is built into an LDAP search filter.", "Escape the value with ldap3.utils.conv.escape_filter_chars."),
        Rule("xpathi", "XPath injection", 643, 7.5, "input", "User input is built into an XPath expression.", "Use XPath variables (root.xpath(query, name=value)) instead of string building."),
        Rule("deserialization", "Unsafe deserialization", 502, 9.8, "input", "User input is deserialized with a loader that can run code.", "Use json, or yaml.safe_load, instead of pickle or yaml.load."),
        Rule("xxe", "XML external entities", 611, 8.2, "input", "User input is parsed by an XML parser with external entities turned on.", "Keep external entity resolution off, or use defusedxml."),
        Rule("trust-boundary", "Trust boundary violation", 501, 5.3, "input", "Unvalidated user input is stored in the session.", "Validate the value before putting it in trusted session state."),
        Rule("ssrf", "Server-side request forgery", 918, 8.6, "input", "User input controls the URL of an outgoing request.", "Fix the scheme and host in code, or check the host against an allowlist."),
        Rule("ssti", "Template injection", 1336, 9.0, "input", "User input is used as template source.", "Pass user input as template variables, never as the template itself."),
        Rule("weak-hash", "Weak hash", 328, 5.9, "", "MD5 or SHA-1 is used for hashing.", "Use SHA-256 or better, or pass usedforsecurity=False for non-security uses."),
        Rule("weak-random", "Weak randomness", 330, 5.3, "weakrand", "A non-cryptographic random value ends up in a security-sensitive place.", "Use the secrets module or random.SystemRandom for tokens and cookies."),
        Rule("insecure-cookie", "Cookie without Secure flag", 614, 4.3, "", "A cookie is set without the Secure flag.", "Pass secure=True to set_cookie."),
    ]
}


def severity(rule):
    s = RULES[rule].score
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    return "low"


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

SHELL_META = ";&|`$()<>\n\r"
LDAP_META = "*()\\\x00"
HOST_FIXED = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\]+[/?#]")


def quote_state(text, quotes="'\"", backslash=False):
    q = None
    i = 0
    while i < len(text):
        c = text[i]
        if backslash and c == "\\" and q != "'":
            i += 2
            continue
        if q is None and c in quotes:
            q = c
        elif q == c:
            q = None
        i += 1
    return q


def numeric(props):
    return props.allowed is not None and props.allowed <= NUMERIC.allowed


def quoted_safe(props, before, kind, backslash=False):
    if kind in props.kinds:
        return True
    q = quote_state(before, backslash=backslash)
    if q is not None:
        return props.excludes(q)
    return numeric(props) or props.allowed == frozenset()


def safe_sql(props, before, after):
    return quoted_safe(props, before, "sqli")


def safe_xpath(props, before, after):
    return quoted_safe(props, before, "xpathi")


def safe_ldap(props, before, after):
    return "ldapi" in props.kinds or all(props.excludes(c) for c in LDAP_META)


def safe_shell(props, before, after):
    if "cmdi" in props.kinds:
        return True
    q = quote_state(before, backslash=True)
    if q == "'":
        return props.excludes("'")
    if q == '"':
        return all(props.excludes(c) for c in '"$`\\')
    return all(props.excludes(c) for c in SHELL_META)


def safe_code(props, before, after):
    if "codeinj" in props.kinds or numeric(props):
        return True
    q = quote_state(before)
    return q is not None and props.excludes(q)


def safe_path(props, before, after):
    if "path-traversal" in props.kinds:
        return True
    if props.excludes("/") and props.excludes("\\"):
        return True
    if not before:
        return False
    return props.excludes("..") or props.excludes("../")


def safe_url(props, before, after, kind):
    if kind in props.kinds:
        return True
    if HOST_FIXED.match(before):
        return True
    return len(before) >= 2 and before[0] == "/" and before[1] not in "/\\"


def safe_redirect(props, before, after):
    return safe_url(props, before, after, "open-redirect")


def safe_ssrf(props, before, after):
    return safe_url(props, before, after, "ssrf")


def safe_html(props, before, after):
    if "xss" in props.kinds:
        return True
    if not (props.excludes("<") and props.excludes(">")):
        return False
    in_tag = before.rfind("<") > before.rfind(">")
    if in_tag:
        return props.excludes('"') and props.excludes("'")
    return True


def safe_template(props, before, after):
    return "ssti" in props.kinds or (props.excludes("{") and props.excludes("%"))


def never_safe(props, before, after):
    return False


def safe_trust(props, before, after):
    return "trust-boundary" in props.kinds or "via-call" in props.flags


MODES = {
    "sql": safe_sql,
    "xpath": safe_xpath,
    "ldap": safe_ldap,
    "shell": safe_shell,
    "code": safe_code,
    "path": safe_path,
    "redirect": safe_redirect,
    "ssrf": safe_ssrf,
    "html": safe_html,
    "template": safe_template,
    "any": never_safe,
    "trust": safe_trust,
}


def unsafe_parts(mode, s, fact_kind):
    check = MODES[mode]
    out = []
    for i, part in enumerate(s.parts):
        if isinstance(part, str) or not part.facts:
            continue
        if not any(f.kind == fact_kind or f.kind == "param" for f in part.facts):
            continue
        before = "".join(p for p in s.parts[:i] if isinstance(p, str))
        after = "".join(p for p in s.parts[i + 1:] if isinstance(p, str))
        if not check(part.props, before, after):
            out.append((part, before, after))
    return out


def as_parts(alt):
    if isinstance(alt, Str):
        return alt
    return None
