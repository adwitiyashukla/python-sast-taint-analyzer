import json
import shutil
from pathlib import Path

from pysast.cli import main

EXAMPLE = Path(__file__).resolve().parent.parent / "example"


def copy_example(tmp_path):
    target = tmp_path / "example"
    shutil.copytree(EXAMPLE, target)
    return target


def test_example_findings(tmp_path, capsys):
    code = main(["scan", str(copy_example(tmp_path)), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert sorted(f["rule"] for f in data["findings"]) == ["cmdi", "open-redirect", "path-traversal", "sqli", "xss"]
    sqli = [f for f in data["findings"] if f["rule"] == "sqli"][0]
    assert [s["line"] for s in sqli["trace"]] == [21, 22, 15, 16]


def test_exit_zero_and_rule_filter(tmp_path, capsys):
    target = copy_example(tmp_path)
    assert main(["scan", str(target), "--rules", "sqli", "--exit-zero"]) == 0
    out = capsys.readouterr().out
    assert "SQL injection" in out and "Command injection" not in out


def test_sarif_has_rules_and_code_flows(tmp_path):
    out = tmp_path / "out.sarif"
    main(["scan", str(copy_example(tmp_path)), "--format", "sarif", "-o", str(out)])
    doc = json.loads(out.read_text())
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    for res in run["results"]:
        assert ids[res["ruleIndex"]] == res["ruleId"]
        assert res["partialFingerprints"]["pysast/v1"]
    sqli = [r for r in run["results"] if r["ruleId"] == "sqli"][0]
    assert len(sqli["codeFlows"][0]["threadFlows"][0]["locations"]) == 4
    tags = [r for r in run["tool"]["driver"]["rules"] if r["id"] == "sqli"][0]["properties"]["tags"]
    assert "external/cwe/cwe-89" in tags


def test_baseline_hides_known_findings(tmp_path, capsys):
    target = copy_example(tmp_path)
    base = tmp_path / "baseline.json"
    assert main(["scan", str(target), "--write-baseline", str(base)]) == 1
    capsys.readouterr()
    assert main(["scan", str(target), "--baseline", str(base)]) == 0
    app = target / "app.py"
    app.write_text("\n\n" + app.read_text())
    assert main(["scan", str(target), "--baseline", str(base)]) == 0


def test_bad_config_and_missing_path(tmp_path, capsys):
    cfg = tmp_path / "pysast.toml"
    cfg.write_text("[analysis]\nmax_call_depth = 0\n")
    assert main(["scan", str(EXAMPLE), "--config", str(cfg)]) == 2
    assert "max_call_depth" in capsys.readouterr().err
    cfg.write_text("[analysis]\nnot_a_key = 1\n")
    assert main(["scan", str(EXAMPLE), "--config", str(cfg)]) == 2
    assert main(["scan", str(tmp_path / "nope")]) == 2


def test_pyproject_settings_are_read(tmp_path, capsys):
    target = copy_example(tmp_path)
    (target / "pyproject.toml").write_text('[tool.pysast.rules]\ndisable = ["xss", "open-redirect"]\n')
    main(["scan", str(target), "--format", "json"])
    rules = sorted(f["rule"] for f in json.loads(capsys.readouterr().out)["findings"])
    assert rules == ["cmdi", "path-traversal", "sqli"]


def test_rules_command(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "CWE-89" in out and "xpathi" in out
