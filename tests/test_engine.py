import textwrap

import pytest

from pysast import scan
from pysast.config import load

FLASK = "from flask import Flask, request, redirect, session, make_response, jsonify, render_template, render_template_string\napp = Flask(__name__)\n"


def rules(tmp_path, code, files=None, header=FLASK):
    (tmp_path / "app.py").write_text(header + textwrap.dedent(code))
    for name, body in (files or {}).items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(body))
    return sorted({f.rule for f in scan(tmp_path).findings})


def write(tmp_path, text):
    (tmp_path / "app.py").write_text(text)
    return tmp_path


def scan_rules(tmp_path, code, header=""):
    write(tmp_path, header + textwrap.dedent(code))
    return sorted({(f.rule, f.func) for f in scan(tmp_path).findings})


CASES = [
    ("sql concat", """
        import sqlite3
        @app.route("/a")
        def a():
            con = sqlite3.connect("x.db")
            con.cursor().execute("SELECT * FROM t WHERE name = '" + request.args["n"] + "'")
            return "ok"
    """, ["sqli"]),
    ("sql parameterized", """
        import sqlite3
        @app.route("/a")
        def a():
            con = sqlite3.connect("x.db")
            con.cursor().execute("SELECT * FROM t WHERE name = ?", (request.args["n"],))
            return "ok"
    """, []),
    ("sql quote removed", """
        import sqlite3
        @app.route("/a")
        def a():
            n = request.args.get("n", "").replace("'", "")
            sqlite3.connect("x").execute(f"SELECT * FROM t WHERE name = '{n}'")
            return "ok"
    """, []),
    ("sql quote doubling is not trusted", """
        import sqlite3
        @app.route("/a")
        def a():
            n = request.args.get("n", "").replace("'", "''")
            sqlite3.connect("x").execute(f"SELECT * FROM t WHERE name = '{n}'")
            return "ok"
    """, ["sqli"]),
    ("sql int cast", """
        import sqlite3
        @app.route("/a")
        def a():
            n = int(request.args.get("n", "0"))
            sqlite3.connect("x").execute(f"SELECT * FROM t WHERE id = {n}")
            return "ok"
    """, []),
    ("shell string", """
        import os
        @app.route("/a")
        def a():
            os.system("ping -c 1 " + request.args["host"])
            return "ok"
    """, ["cmdi"]),
    ("aliased import", """
        from subprocess import Popen as P
        @app.route("/a")
        def a():
            P("nslookup " + request.args["host"], shell=True)
            return "ok"
    """, ["cmdi"]),
    ("argv list is fine", """
        import subprocess
        @app.route("/a")
        def a():
            subprocess.run(["ping", "-c", "1", request.args["host"]])
            return "ok"
    """, []),
    ("sh -c in argv", """
        import subprocess
        @app.route("/a")
        def a():
            subprocess.run(["sh", "-c", "ping " + request.args["host"]])
            return "ok"
    """, ["cmdi"]),
    ("shlex quote", """
        import os, shlex
        @app.route("/a")
        def a():
            os.system("ping " + shlex.quote(request.args["host"]))
            return "ok"
    """, []),
    ("regex fullmatch guard", """
        import os, re
        @app.route("/a")
        def a():
            host = request.args.get("host", "")
            if not re.fullmatch(r"[a-z0-9.]+", host):
                return "bad"
            os.system("ping " + host)
            return "ok"
    """, []),
    ("regex dollar lets a newline through", """
        import os, re
        @app.route("/a")
        def a():
            host = request.args.get("host", "")
            if not re.match(r"^[a-z0-9.]+$", host):
                return "bad"
            os.system("ping " + host)
            return "ok"
    """, ["cmdi"]),
    ("eval", """
        @app.route("/a")
        def a():
            return str(eval(request.args["expr"]))
    """, ["codeinj", "xss"]),
    ("literal check before eval", """
        @app.route("/a")
        def a():
            v = request.args.get("v", "")
            if not v.startswith("'") or not v.endswith("'") or "'" in v[1:-1]:
                return "no"
            eval(v)
            return "ok"
    """, []),
    ("open with user path", """
        @app.route("/a")
        def a():
            with open("/data/" + request.args["f"]) as fh:
                fh.read()
            return "ok"
    """, ["path-traversal"]),
    ("basename", """
        import os
        @app.route("/a")
        def a():
            open(os.path.join("/data", os.path.basename(request.args["f"])))
            return "ok"
    """, []),
    ("resolve and prefix check", """
        from pathlib import Path
        BASE = Path("/data")
        @app.route("/a")
        def a():
            p = (BASE / request.args["f"]).resolve()
            if not str(p).startswith(str(BASE)):
                return "no"
            return p.read_text()
    """, []),
    ("reflected html", """
        @app.route("/a")
        def a():
            return "<p>" + request.args.get("q", "") + "</p>"
    """, ["xss"]),
    ("escaped html", """
        import html
        @app.route("/a")
        def a():
            return "<p>" + html.escape(request.args.get("q", "")) + "</p>"
    """, []),
    ("json response is not html", """
        @app.route("/a")
        def a():
            return jsonify({"q": request.args.get("q")})
    """, []),
    ("plain text response", """
        @app.route("/a")
        def a():
            return make_response((request.args.get("q", ""), {"Content-Type": "text/plain"}))
    """, []),
    ("open redirect", """
        @app.route("/a")
        def a():
            return redirect(request.args.get("next", "/"))
    """, ["open-redirect"]),
    ("redirect to own path", """
        @app.route("/a")
        def a():
            return redirect("/profile/" + request.args.get("id", ""))
    """, []),
    ("redirect allowlist", """
        from urllib.parse import urlparse
        @app.route("/a")
        def a():
            url = request.args.get("next", "/")
            if urlparse(url).netloc not in ("example.com", ""):
                return "no"
            return redirect(url)
    """, []),
    ("ssrf", """
        import requests
        @app.route("/a")
        def a():
            requests.get(request.args["url"])
            return "ok"
    """, ["ssrf"]),
    ("fixed host", """
        import requests
        @app.route("/a")
        def a():
            requests.get("https://api.example.com/users/" + request.args["id"])
            return "ok"
    """, []),
    ("pickle", """
        import pickle
        @app.route("/a", methods=["POST"])
        def a():
            pickle.loads(request.data)
            return "ok"
    """, ["deserialization"]),
    ("yaml safe loader", """
        import yaml
        @app.route("/a", methods=["POST"])
        def a():
            yaml.load(request.data, Loader=yaml.SafeLoader)
            yaml.safe_load(request.data)
            return "ok"
    """, []),
    ("lxml entities on", """
        from lxml import etree
        @app.route("/a", methods=["POST"])
        def a():
            parser = etree.XMLParser(resolve_entities=True)
            etree.fromstring(request.data, parser)
            return "ok"
    """, ["xxe"]),
    ("lxml default parser", """
        from lxml import etree
        @app.route("/a", methods=["POST"])
        def a():
            etree.fromstring(request.data)
            return "ok"
    """, []),
    ("ldap filter", """
        import ldap3
        @app.route("/a")
        def a():
            conn = ldap3.Connection("ldap://x")
            conn.search("dc=x", "(uid=" + request.args["u"] + ")")
            return "ok"
    """, ["ldapi"]),
    ("ldap escaped", """
        import ldap3
        from ldap3.utils.conv import escape_filter_chars
        @app.route("/a")
        def a():
            conn = ldap3.Connection("ldap://x")
            conn.search("dc=x", "(uid=" + escape_filter_chars(request.args["u"]) + ")")
            return "ok"
    """, []),
    ("xpath string", """
        from lxml import etree
        @app.route("/a")
        def a():
            root = etree.parse("users.xml")
            root.xpath("//user[@name='" + request.args["n"] + "']")
            return "ok"
    """, ["xpathi"]),
    ("xpath variable", """
        from lxml import etree
        @app.route("/a")
        def a():
            root = etree.parse("users.xml")
            root.xpath("//user[@name=$n]", n=request.args["n"])
            return "ok"
    """, []),
    ("template source", """
        @app.route("/a")
        def a():
            return render_template_string("Hi " + request.args.get("name", ""))
    """, ["ssti"]),
    ("template variable", """
        @app.route("/a")
        def a():
            return render_template_string("Hi {{ name }}", name=request.args.get("name", ""))
    """, []),
    ("session store", """
        @app.route("/a")
        def a():
            session["role"] = request.args.get("role")
            return "ok"
    """, ["trust-boundary"]),
    ("weak hash", """
        import hashlib
        def f(pw):
            return hashlib.md5(pw.encode()).hexdigest()
    """, ["weak-hash"]),
    ("hash not for security", """
        import hashlib
        def f(data):
            return hashlib.md5(data, usedforsecurity=False).hexdigest() + hashlib.sha256(data).hexdigest()
    """, []),
    ("weak random token", """
        import random
        def reset_link():
            token = str(random.getrandbits(64))
            return token
    """, ["weak-random"]),
    ("random for sampling", """
        import random
        def pick(items):
            chosen = random.choice(items)
            return chosen
    """, []),
    ("secrets token", """
        import secrets
        def reset_link():
            token = secrets.token_urlsafe(16)
            return token
    """, []),
    ("cookie without secure", """
        @app.route("/a")
        def a():
            r = make_response("ok")
            r.set_cookie("sid", "x", httponly=True)
            return r
    """, ["insecure-cookie"]),
    ("cookie with secure", """
        @app.route("/a")
        def a():
            r = make_response("ok")
            r.set_cookie("sid", "x", secure=True, httponly=True)
            return r
    """, []),
    ("dead branch", """
        import os
        @app.route("/a")
        def a():
            num = 106
            bar = "safe" if 7 * 18 + num > 200 else request.args["x"]
            os.system("echo " + bar)
            return "ok"
    """, []),
    ("dict key precision", """
        import os
        @app.route("/a")
        def a():
            m = {}
            m["a"] = "safe"
            m["b"] = request.args["x"]
            os.system("echo " + m["a"])
            return "ok"
    """, []),
    ("list pop precision", """
        import os
        @app.route("/a")
        def a():
            lst = ["safe", request.args["x"], "other"]
            lst.pop(0)
            os.system("echo " + lst[1])
            return "ok"
    """, []),
    ("slice keeps taint", """
        import os
        @app.route("/a")
        def a():
            s = "abc" + request.args["x"] + "xyz"
            os.system("echo " + s[3:-3])
            return "ok"
    """, ["cmdi"]),
    ("slice of constant part", """
        import os
        @app.route("/a")
        def a():
            s = "abc" + request.args["x"] + "xyz"
            os.system("echo " + s[:3])
            return "ok"
    """, []),
    ("typed query arg", """
        import sqlite3
        @app.route("/a")
        def a():
            page = request.args.get("page", 1, type=int)
            sqlite3.connect("x").execute(f"SELECT * FROM t LIMIT 10 OFFSET {page * 10}")
            return "ok"
    """, []),
    ("static route path is not input", """
        import os
        @app.route("/files/report")
        def a():
            os.system("ls " + request.path.split("/")[1])
            return "ok"
    """, []),
    ("int route converter", """
        import sqlite3
        @app.route("/item/<int:item_id>")
        def a(item_id):
            sqlite3.connect("x").execute(f"SELECT * FROM t WHERE id = {item_id}")
            return "ok"
    """, []),
    ("path route converter", """
        @app.route("/files/<path:name>")
        def a(name):
            return open("/srv/" + name).read()
    """, ["path-traversal"]),
    ("route built with an f-string", """
        PREFIX = "static"
        @app.route(f"/{PREFIX}/<path:name>")
        def a(name):
            return open("/srv/" + name).read()
    """, ["path-traversal"]),
    ("dict comprehension keeps values", """
        import os
        @app.route("/a")
        def a():
            q = {k: v for k, v in request.args.items()}
            os.system(q["c"])
            return "ok"
    """, ["cmdi"]),
    ("dataclass built from a dict", """
        import os
        from dataclasses import dataclass
        @dataclass
        class Opts:
            cmd: str = "ls"
            @classmethod
            def from_dict(cls, data):
                return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})
        @app.route("/a")
        def a():
            os.system(Opts.from_dict(dict(request.args)).cmd)
            return "ok"
    """, ["cmdi"]),
    ("super init stores the value", """
        import os
        class Base:
            def __init__(self, cmd):
                self.cmd = cmd
        class Job(Base):
            def __init__(self, cmd):
                super().__init__(cmd)
        @app.route("/a")
        def a():
            os.system(Job(request.args["c"]).cmd)
            return "ok"
    """, ["cmdi"]),
    ("checked resolved path", """
        from pathlib import Path
        BASE = Path("/srv/files")
        @app.route("/a")
        def a():
            p = BASE / request.args["f"]
            if not p.resolve().is_relative_to(BASE.resolve()):
                return "no", 403
            return p.read_text()
    """, []),
    ("relative_to on a resolved path", """
        from pathlib import Path
        BASE = Path("/srv/files")
        @app.route("/a")
        def a():
            p = BASE / request.args["f"]
            try:
                p.resolve().relative_to(BASE.resolve())
            except ValueError:
                return "no", 403
            return p.read_text()
    """, []),
    ("relative_to without resolve is not trusted", """
        from pathlib import Path
        BASE = Path("/srv/files")
        @app.route("/a")
        def a():
            p = BASE / request.args["f"]
            try:
                p.relative_to(BASE)
            except ValueError:
                return "no", 403
            return p.read_text()
    """, ["path-traversal"]),
    ("input at the start of a path", """
        @app.route("/a")
        def a():
            name = request.args["f"].split(".")[0]
            return open(name).read()
    """, ["path-traversal"]),
    ("joined input can replace the base", """
        import os
        @app.route("/a")
        def a():
            name = request.args["f"].split(".")[0]
            return open(os.path.join("/srv/files", name)).read()
    """, ["path-traversal"]),
    ("extension after the last dot", """
        @app.route("/a", methods=["POST"])
        def a():
            ext = request.files["f"].filename.split(".")[-1]
            return open("/srv/upload/abc." + ext, "wb")
    """, []),
]


@pytest.mark.parametrize("name,code,expected", CASES, ids=[c[0] for c in CASES])
def test_rules(tmp_path, name, code, expected):
    assert rules(tmp_path, code) == expected


def test_interprocedural_flow(tmp_path):
    found = rules(tmp_path, """
        import db
        @app.route("/a")
        def a():
            return str(db.find(request.args["name"]))
    """, {"db.py": """
        import sqlite3
        def find(name):
            q = "SELECT * FROM users WHERE name = '{}'".format(name)
            return sqlite3.connect("x").execute(q).fetchall()
    """})
    assert found == ["sqli"]


def test_trace_crosses_files(tmp_path):
    (tmp_path / "app.py").write_text(FLASK + textwrap.dedent("""
        import db
        @app.route("/a")
        def a():
            name = request.args["name"]
            db.find(name)
            return "ok"
    """))
    (tmp_path / "db.py").write_text("import os\ndef find(name):\n    os.system('grep ' + name)\n")
    [f] = scan(tmp_path).findings
    assert f.file == "db.py" and f.source.file == "app.py"
    notes = [s.note for s in f.trace]
    assert notes[0] == "request.args" and any(n.startswith("call") for n in notes)


def test_wrapper_class_and_dynamic_dispatch(tmp_path):
    found = rules(tmp_path, """
        import os
        import things
        class Wrapper:
            def __init__(self, req):
                self.req = req
            def name(self):
                return self.req.args.get("name")
            def fixed(self):
                return "bar"
        @app.route("/a")
        def a():
            w = Wrapper(request)
            os.system("echo " + w.fixed())
            os.system("echo " + things.make().run(w.name()))
            return "ok"
    """, {"things.py": """
        import things
        def make():
            return getattr(things, NAME)()
        NAME = open("cfg").read()
        class One:
            def run(self, x):
                return x
        class Two:
            def run(self, x):
                return "" + x
    """})
    assert found == ["cmdi"]


def test_django_view(tmp_path):
    found = rules(tmp_path, """
        from django.db import connection
        from django.http import HttpResponse
        def detail(request):
            with connection.cursor() as cur:
                cur.execute("SELECT * FROM t WHERE id = " + request.GET["id"])
            return HttpResponse("<b>" + request.GET.get("q", "") + "</b>")
    """, header="")
    assert found == ["sqli", "xss"]


def test_fastapi_params(tmp_path):
    found = rules(tmp_path, """
        import os
        from fastapi import FastAPI
        api = FastAPI()
        @api.get("/run")
        def run(cmd: str, count: int = 1):
            os.system("echo " + str(count))
            os.system(cmd)
            return {"ok": True}
    """, header="")
    assert found == ["cmdi"]


def test_suppression_comment(tmp_path):
    code = """
        import os
        @app.route("/a")
        def a():
            os.system(request.args["c"])  # pysast: ignore[cmdi]
            return "ok"
    """
    assert rules(tmp_path, code) == []


def test_syntax_error_is_skipped(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n")
    (tmp_path / "good.py").write_text("import os\nfrom flask import request\ndef f():\n    os.system(request.args['c'])\n")
    res = scan(tmp_path)
    assert [f.rule for f in res.findings] == ["cmdi"]
    assert res.project.errors and res.project.errors[0][0] == "bad.py"


def test_fastapi_param_types(tmp_path):
    found = scan_rules(tmp_path, """
        import sqlite3
        from fastapi import Depends, FastAPI, File, UploadFile
        api = FastAPI()
        def current_user():
            return None
        @api.get("/item/{item_id}")
        def item(item_id: int, user=Depends(current_user)):
            sqlite3.connect("x").execute(f"SELECT * FROM t WHERE id = {item_id} AND u = '{user}'")
            return {}
        @api.post("/upload")
        def upload(file: UploadFile = File(...)):
            open("/srv/" + file.filename, "wb")
            return {}
    """)
    assert found == [("path-traversal", "upload")]


def test_starlette_request_annotation(tmp_path):
    found = scan_rules(tmp_path, """
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import HTMLResponse
        from starlette.routing import Route
        def make():
            async def callback(request: Request):
                return HTMLResponse("<p>" + request.query_params.get("e", "") + "</p>")
            return Starlette(routes=[Route("/cb", callback)])
    """)
    assert found == [("xss", "make.callback")]


def test_django_form_cleaned_data(tmp_path):
    found = scan_rules(tmp_path, """
        import requests
        from django import forms
        class ImageForm(forms.Form):
            def clean(self):
                data = super().clean()
                requests.get(data["url"])
                return data
            def save(self):
                requests.get(self.cleaned_data["mirror"])
    """)
    assert found == [("ssrf", "ImageForm.clean"), ("ssrf", "ImageForm.save")]


def test_same_source_text_in_two_views(tmp_path):
    res = scan(write(tmp_path, FLASK + textwrap.dedent("""
        import os
        def run(c):
            os.system(c)
        @app.route("/a")
        def a():
            c = request.args["c"]
            run(c)
            return "ok"
        @app.route("/b")
        def b():
            c = request.args["c"]
            run(c)
            return "ok"
    """)))
    assert len({f.source.line for f in res.findings}) == 2
    assert len({f.fingerprint for f in res.findings}) == 2


def test_module_named_like_a_library(tmp_path):
    (tmp_path / "pkg" / "queries").mkdir(parents=True)
    (tmp_path / "pkg" / "__init__.py").write_text("")
    (tmp_path / "pkg" / "queries" / "__init__.py").write_text("")
    (tmp_path / "pkg" / "queries" / "pandas.py").write_text("def read_sql_query(q, db):\n    return None\n")
    found = rules(tmp_path, """
        import pandas as pd
        @app.route("/w/<wid>")
        def w(wid):
            return pd.read_sql_query("SELECT * FROM t WHERE id = '%s'" % wid, None).to_html()
    """)
    assert "sqli" in found


def test_helper_with_many_callers(tmp_path):
    write(tmp_path, FLASK + textwrap.dedent("""
        import requests
        def fetch(url, headers=None):
            return requests.get(url, headers=headers or {})
        def a1():
            return fetch("https://one.example.com/")
        def a2():
            return fetch("https://two.example.com/" + str(len("ab")), {"k": "v"})
        def a3():
            return fetch(None, [1, 2])
        @app.route("/a")
        def z1():
            fetch("https://api.example.com/" + request.args["u"])
            return "ok"
        @app.route("/b")
        def z2():
            fetch(request.args["u"], {"x": 1})
            return "ok"
        @app.route("/c")
        def z3():
            fetch(request.args["v"])
            return "ok"
    """))
    cfg = load()
    cfg["analysis"]["max_contexts"] = 1
    found = sorted({(f.rule, f.func, f.source.line) for f in scan(tmp_path, cfg).findings})
    assert found == [("ssrf", "fetch", 19), ("ssrf", "fetch", 23)]
