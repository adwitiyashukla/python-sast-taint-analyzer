# python-sast-taint-analyzer

[![ci](https://github.com/adwitiyashukla/python-sast-taint-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/adwitiyashukla/python-sast-taint-analyzer/actions/workflows/ci.yml)

pysast is a static analyzer that finds injection bugs in Python web apps. It follows untrusted input (query args, form fields, cookies, headers, route parameters) through the code and reports when that input reaches something dangerous, like a SQL query, a shell command or a file path. It knows Flask, Django, FastAPI and Starlette, and it only uses the Python standard library.

```
$ pysast scan example
app.py:16:12  high  sqli  SQL injection: request.args (line 21) reaches Connection.execute
       21 | owner = request.args.get("owner", "")
       22 | rows = find_notes(owner)
       15 | sql = "SELECT title, body FROM notes WHERE owner = '%s'" % owner
       16 | return db().execute(sql).fetchall()
```

Every finding comes with the path from the input to the sink, across functions and files. The same path shows up in GitHub code scanning when you use the SARIF output.

## Results

### OWASP Benchmark for Python

The [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) has 1,230 small Flask test cases in 14 categories. 452 of them are real vulnerabilities and 778 are fake ones built to look dangerous, like dead branches, values that get overwritten in a dict and parameterized queries. Each category is scored as true positive rate minus false positive rate, so a tool that flags everything gets 0.

I ran pysast, Bandit 1.9.4 and Semgrep 1.181.0 (all 371 Python rules in the public semgrep-rules repo) on the same pinned commit, and scored them the way OWASP BenchmarkUtils does. A test counts as detected only when the tool reports the expected CWE in that test file.

| Category | Real | Fake | pysast | Bandit | Semgrep |
|---|---:|---:|---:|---:|---:|
| Code injection | 20 | 33 | 100.0 | 0.0 | 0.0 |
| Command injection | 13 | 7 | 100.0 | 0.0 | 0.0 |
| Deserialization | 18 | 36 | 100.0 | 52.8 | 66.7 |
| Insecure cookie | 24 | 15 | 100.0 | 0.0 | 0.0 |
| LDAP injection | 16 | 13 | 100.0 | 0.0 | 0.0 |
| Open redirect | 13 | 21 | 100.0 | 0.0 | 2.9 |
| Path traversal | 65 | 103 | 100.0 | 0.0 | 1.1 |
| SQL injection | 5 | 11 | 100.0 | 0.0 | 100.0 |
| Trust boundary | 18 | 19 | 100.0 | 0.0 | 0.0 |
| Weak hash | 71 | 80 | 100.0 | 0.0 | 0.0 |
| Weak random | 99 | 227 | 100.0 | 77.8 | 0.0 |
| XPath injection | 51 | 135 | 100.0 | 0.0 | 0.0 |
| XSS | 31 | 58 | 100.0 | 0.0 | -27.6 |
| XXE | 8 | 20 | 100.0 | 0.0 | 0.0 |
| **Average** | **452** | **778** | **100.0** | **9.3** | **10.2** |

A 0 can also mean a tool flags everything in a category. Bandit reports every real and every fake case of command injection and SQL injection, so it scores 0 there.

The scorer also has a loose mode that gives Bandit and Semgrep credit for any finding in the right class, since for example Bandit tags eval with CWE-78 and MD5 with CWE-327. In loose mode Bandit averages 17.5 and Semgrep 15.7.

A perfect score on a test suite you can read is easy to overfit, so I kept a held-out half. I read through the test patterns of the whole suite before writing the engine, but I only debugged against failures in tests 1 to 615. Tests 616 to 1230 were scored once at the end and got 0 wrong answers out of 615. There is also no benchmark-specific config. The run uses the same defaults as any other scan, and helper functions like the benchmark's own HTML encoder are analyzed like normal code.

### Real CVEs

The benchmark is made of small test files, so I also checked pysast against 20 real CVEs in open source Python web apps. To avoid picking ones it would do well on, I took the PyPI advisories in the GitHub Advisory Database that have a CVE id, a CWE pysast has a rule for and a linked fix commit (1,100 of them), shuffled them with a fixed seed and went down the list. I kept an advisory when the bug is a flow from a Flask, Django, FastAPI or Starlette request to a sink in the project's own code and I could find the vulnerable and fixed commits, with at most 2 per project. That took 112 advisories. For each one I kept, I wrote down the two commits, the entry function and the sink function before running pysast on any of them. The skipped ones and the reason for each are in `bench/cves.toml`.

A CVE counts as found when pysast reports the right bug class in the sink function, on a trace that goes through the entry function. The finding counts as gone when the fixed commit has no finding of that class coming from the entry function.

On the first run pysast found 7 of the 20. I wrote that number down and then looked at the misses. Most of them came from gaps that are not about one app, like routes built with f-strings, FastAPI parameter types, dataclass constructors, `super()` calls, Django form data, a module resolver that matched `import pandas` to a project file called `pandas.py`, and a fallback that skipped sink checks in helpers with a lot of callers. I fixed those as general features, checked that the OWASP numbers did not change, and ran all 20 again.

| CVE | Project | Bug | Found | Gone after fix | Note |
|---|---|---|---|---|---|
| CVE-2023-46134 | D-Tale | Code injection | no | - | The sink is `DataFrame.query` on a frame from a global store, and pysast does not know it is a pandas frame |
| CVE-2024-45601 | Mesop | Path traversal | yes | no | The fixed code still sends the path to `send_file` through the branch used under Bazel, only for .js and .css files |
| CVE-2023-6831 | MLflow | Path traversal | no | - | Routes come from protobuf descriptors and the artifact store is picked at runtime |
| CVE-2024-32005 | NiceGUI | Path traversal | yes | yes |  |
| CVE-2024-10833 | DB-GPT | Path traversal | yes | yes |  |
| CVE-2023-5002 | pgAdmin 4 | Command injection | yes | no | The fix runs the binary with an argument list, but the user still picks the folder it runs from, and pysast reports that |
| CVE-2022-24840 | django-s3file | Path traversal | no | - | The sink is Django's storage API on S3, which pysast has no model for |
| CVE-2022-0697 | Archivy | Open redirect | yes | no | The fix checks the URL in a helper that returns a bool, and pysast does not carry that check back to the caller |
| CVE-2026-28786 | Open WebUI | Path traversal | no | - | The extension is the text after the last dot, so it has no `..` and the path cannot leave the folder. The advisory's shown impact is the server path in an error message |
| CVE-2023-1176 | MLflow | Path traversal | no | - | Same as the other MLflow one, and the name also goes through protobuf parsing that fills an object in place |
| CVE-2025-55149 | TinyScientist | Path traversal | yes | yes |  |
| CVE-2026-29038 | changedetection.io | XSS | yes | no | The fix is a custom route converter class, and pysast treats unknown converters as any text |
| CVE-2022-1592 | Scout | SSRF | yes | no | The fix checks the URL against a list stored in the user's session |
| CVE-2026-34244 | Weblate | SSRF | no | - | The service class is picked from a registry at runtime |
| CVE-2025-6773 | LightRAG | Path traversal | yes | yes |  |
| CVE-2026-33440 | Weblate | SSRF | yes | no | Under the default setting any host is still allowed after the fix, so this one should stay |
| CVE-2026-24779 | vLLM | SSRF | no | - | The request handler is an object stored on `app.state` at startup |
| CVE-2024-45595 | D-Tale | Code injection | no | - | Same sink as the other D-Tale one |
| CVE-2025-62800 | FastMCP | XSS | yes | yes |  |
| CVE-2026-21892 | Parsl | SQL injection | yes | no | The fix only changed `views.py`. The same `'%s'` SQL in `parsl/monitoring/queries/pandas.py` is still called from the route, after a lookup that checks the workflow exists |

pysast now finds 12 of the 20, and for 5 of those 12 the finding is gone on the fixed commit. For the 7 where a finding stays, the note says why. In some of them the same kind of flow is still there after the fix, and in others the fix is a check pysast cannot follow yet, like a helper that returns a bool or a custom route converter. Most of the 8 misses are code that is wired together at runtime, like a class picked from a registry or a handler stored on `app.state`, which pysast does not follow.

### Speed

The OWASP benchmark takes 5.4 seconds with pysast, 7.1 with Bandit and 86.9 with Semgrep. These are single runs on bigger code, on a 2 core cloud VM. The Django, Werkzeug, Flask and Requests runs include their test folders.

| Project | Files | Lines | Seconds |
|---|---:|---:|---:|
| Django 5.2.7 | 2,816 | 489,379 | 191.4 |
| SQLAlchemy 2.0.35 | 255 | 231,472 | 115.2 |
| Werkzeug 3.1.3 | 138 | 34,809 | 20.1 |
| Flask 3.1.2 | 83 | 17,874 | 1.3 |
| Requests 2.32.5 | 34 | 10,776 | 3.4 |
| FastAPI 0.115.0 | 44 | 17,829 | 2.6 |
| Starlette 0.38.6 | 35 | 6,621 | 0.6 |
| Jinja 3.1.4 | 25 | 14,310 | 31.0 |
| HTTPX 0.27.2 | 24 | 9,159 | 5.3 |

None of these runs hit an internal error. The one file that did not parse is `tests/test_runner_apps/tagged/tests_syntax_error.py` in Django, which is broken on purpose.

## How it works

1. Every `.py` file is parsed with the standard `ast` module and each function gets a control flow graph. `and`, `or`, `not`, `match` and `try` are split into separate branch nodes.
2. An abstract interpreter runs over the graph. A value is a small set of possibilities like constants, strings, numbers, heap objects (lists, dicts, class instances, library objects like a sqlite cursor or a `pathlib.Path`), functions and classes.
3. A string is a sequence of known text and holes. A hole is the part that came from user input. It remembers where the input came from and what is known about its characters, like "no single quotes" or "only letters and digits".
4. Sanitizers are facts about characters, not yes or no flags. `html.escape` removes `< > " '` from a hole, `replace("'", "&apos;")` removes the quote, and an if-check like `if "'" in name: return` does the same on the branch that keeps going. `isalnum()`, `int()` and `re.fullmatch` with a character class narrow the character set too. With `re.match(r"^[a-z]+$")` the hole can still hold a newline, because `$` matches before a trailing newline, and pysast keeps that.
5. Each sink checks the hole in its context. For SQL and XPath it looks at the text before the hole, so a value without quotes is safe inside `'...'` but not in an unquoted spot. For URLs it checks whether a fixed scheme and host come before the input (SSRF, open redirect). For shell strings it checks shell metacharacters unless the hole sits inside single quotes. For paths it checks whether the input can climb out with `..` or start a new absolute path, and a path that was resolved and then checked with `startswith` or `is_relative_to` against the base folder counts as safe.
6. Constant folding drops branches that can never run, like `if 7 * 18 + num > 200`. Dict keys, list positions and configparser options are tracked one by one, so a value that was overwritten or never read does not raise an alert.
7. Calls between project functions are analyzed in context. The callee runs with the real argument values, with input pieces swapped for placeholders, and the result is cached by the shape of the arguments. When the callee hits a sink with a placeholder, the finding is reported with the full path back through the caller. After 32 contexts a function falls back to a shared summary that drops constants but keeps object shapes, and after that to one summary where every argument is a placeholder, so a helper with hundreds of callers still gets its sinks checked.
8. Library behavior lives in `src/pysast/models.toml` (sources, sinks, sanitizers, return types), plus Python models for APIs that need more than a table, like subprocess argv, configparser, StringIO, pathlib, urlparse, XML parser features, hashlib and random.

Taint does not flow through files, databases or caches, so stored XSS is out of scope. Calls into code outside the project pass taint from arguments to the result unless a model says otherwise, which is the safe default.

## Usage

Python 3.12 or newer. From a clone of this repo:

```
pip install .
pysast scan path/to/app
pysast scan path/to/app --format sarif -o pysast.sarif
pysast scan path/to/app --format json
pysast scan path/to/app --rules sqli,cmdi --min-severity high
pysast rules
```

The exit code is 1 when there are findings, 0 when there are none (or with `--exit-zero`), and 2 for a bad path or config.

- Hide one finding with a comment on its line, like `# pysast: ignore[sqli]`.
- To adopt pysast in an old codebase, run once with `--write-baseline baseline.json`, then pass `--baseline baseline.json` so only new findings show up. Fingerprints use the code text, not line numbers, so they survive edits above the finding.
- Settings go in `[tool.pysast]` in your `pyproject.toml` or in a file passed with `--config`. All keys and their defaults are in `src/pysast/config.toml`, and unknown keys or bad values are rejected.
- Extra models (your own sanitizer or sink) go in a TOML file with the same tables as `models.toml`, listed under `models.files`.

### GitHub Action

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: adwitiyashukla/python-sast-taint-analyzer@main
    with:
      path: src
```

This runs a scan and uploads the SARIF file, so findings show up in the Security tab and on pull requests with the full source to sink path. This repo runs it on `example/` in `.github/workflows/scan.yml`.

## Rules

| Rule | CWE | Severity | What it finds |
|---|---|---|---|
| `sqli` | 89 | high | User input is built into a SQL query string. |
| `cmdi` | 78 | high | User input reaches a shell command. |
| `codeinj` | 94 | high | User input is evaluated as Python code. |
| `path-traversal` | 22 | high | User input controls a file system path. |
| `xss` | 79 | medium | User input is written into an HTML response without escaping. |
| `open-redirect` | 601 | medium | User input decides where the response redirects. |
| `ldapi` | 90 | high | User input is built into an LDAP search filter. |
| `xpathi` | 643 | high | User input is built into an XPath expression. |
| `deserialization` | 502 | high | User input is deserialized with a loader that can run code. |
| `xxe` | 611 | high | User input is parsed by an XML parser with external entities turned on. |
| `trust-boundary` | 501 | medium | Unvalidated user input is stored in the session. |
| `ssrf` | 918 | high | User input controls the URL of an outgoing request. |
| `ssti` | 1336 | high | User input is used as template source. |
| `weak-hash` | 328 | medium | MD5 or SHA-1 is used for hashing. |
| `weak-random` | 330 | medium | A non-cryptographic random value ends up in a security-sensitive place. |
| `insecure-cookie` | 614 | medium | A cookie is set without the Secure flag. |

## Running the benchmarks

```
pip install -e ".[bench]"
python bench/owasp.py
python bench/cves.py
```

`bench/owasp.py` fetches the benchmark and the Semgrep rules at the commits pinned in `config.toml`, runs all three tools and prints both score tables. `bench/cves.py` checks out each CVE in `bench/cves.toml` at its vulnerable and fixed commits and scans both. It only reads the code, nothing from those repos is run. CI runs the OWASP benchmark on every push and fails if pysast drops below 100.

## Layout

```
src/pysast/      engine (cfg, values, strings, engine, library, rules), CLI and reports
bench/           OWASP benchmark scorer and the CVE check
example/         small vulnerable Flask app used by the tests and the scan workflow
tests/           unit and end to end tests
```

## License

MIT
