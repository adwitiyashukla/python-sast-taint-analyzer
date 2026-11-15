from __future__ import annotations

import ast
import base64
import builtins
import html
import pathlib
import posixpath
import re
import re._constants as sre_c
import re._parser as sre_parse
import shlex
import tomllib
import urllib.parse
from importlib import resources

from . import strings as S
from .values import (
    BOOL,
    EMPTY,
    FALSE,
    NONE,
    NOTHING,
    NUMERIC,
    TRUE,
    UNKNOWN,
    Cls,
    Const,
    DictObj,
    Fn,
    Hole,
    InstObj,
    LenOf,
    Lib,
    LibObj,
    ListObj,
    Meth,
    Mod,
    Num,
    Props,
    Ref,
    Str,
    Tup,
    Unk,
    Val,
    const,
    items_tuple,
    merge_holes,
    obj_values,
)

B64 = "+/="
B64URL = "-_="
HTML_EXCL = ("<", ">", '"', "'")
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "ash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
WEAK_HASHES = {"md5", "sha1", "md4", "md2", "sha", "md5-sha1", "ripemd160", "mdc2"}
BUILTIN_NAMES = set(dir(builtins))
PURE_STR = {
    "html.escape": html.escape,
    "urllib.parse.quote": urllib.parse.quote,
    "urllib.parse.quote_plus": urllib.parse.quote_plus,
    "urllib.parse.unquote": urllib.parse.unquote,
    "urllib.parse.unquote_plus": urllib.parse.unquote_plus,
    "shlex.quote": shlex.quote,
    "os.path.basename": posixpath.basename,
    "posixpath.basename": posixpath.basename,
    "os.path.dirname": posixpath.dirname,
    "os.path.normpath": posixpath.normpath,
    "markupsafe.escape": html.escape,
}
RESPONSE_TYPES = {"flask.Response", "django.HttpResponse", "starlette.Response"}
URL_SAFE = frozenset("%/:?#[]@!$&'()*+,;=-._~")
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query", "mogrify"}
CLEAN_METHODS = {"fetchone", "fetchall", "fetchmany", "first", "one", "one_or_none", "scalar", "scalars", "all", "count", "exists", "commit", "rollback", "close"}


def arg(args, kwargs, i, name=None, default=None):
    if i is not None and i < len(args):
        return args[i]
    if name is not None and name in kwargs:
        return kwargs[name]
    return default


def short(qn):
    parts = qn.split(".")
    return ".".join(parts[-2:]) if len(parts) > 1 else qn


def load_models(extra):
    text = resources.files("pysast").joinpath("models.toml").read_text(encoding="utf-8")
    data = tomllib.loads(text)
    for path in extra:
        with open(path, "rb") as f:
            more = tomllib.load(f)
        for section, table in more.items():
            if isinstance(table, dict) and isinstance(data.get(section), dict):
                if "names" in table and isinstance(table["names"], list):
                    data[section]["names"] = data[section].get("names", []) + table["names"]
                else:
                    data[section].update(table)
    return data


class Library:
    def __init__(self, config, extra_models=()):
        data = load_models(extra_models)
        self.sources = data.get("source", {})
        self.sinks = data.get("sink", {})
        self.sanitizers = data.get("sanitizer", {})
        self.returns = data.get("returns", {})
        self.clean = set(data.get("clean", {}).get("names", []))
        self.weakrand = set(data.get("weakrand", {}).get("names", []))
        self.consts = data.get("const", {})
        self.call_consts = data.get("call_const", {})
        rules = config["rules"]
        self.weak_mode = rules["weak_random"]
        self.sensitive = [s.lower() for s in rules["sensitive_names"]]
        self.argument_injection = rules["argument_injection"]
        self.qn = ""
        self.hooks = {}
        self.mhooks = {}
        self.ahooks = {}
        self.register()

    def register(self):
        h = self.hooks
        for name in ("subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"):
            h[name] = self.h_subprocess
        for name in ("os.execv", "os.execve", "os.execvp", "os.execvpe", "os.spawnv", "os.spawnve", "os.spawnvp", "asyncio.create_subprocess_exec"):
            h[name] = self.h_exec
        for name in ("os.path.join", "posixpath.join", "ntpath.join"):
            h[name] = self.h_path_join
        for name in ("os.path.abspath", "os.path.realpath", "os.path.normpath"):
            h[name] = self.h_normpath
        h["os.path.dirname"] = self.h_dirname
        h["os.fspath"] = lambda f, a, k, e: f.to_str(arg(a, k, 0, "path", UNKNOWN), e)
        for name in ("pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath", "pathlib.PurePosixPath"):
            h[name] = self.h_path
        for name in ("io.open", "codecs.open", "builtins.open"):
            h[name] = self.h_open
        h["io.StringIO"] = self.h_stringio
        h["io.BytesIO"] = self.h_stringio
        for name in ("configparser.ConfigParser", "configparser.RawConfigParser", "configparser.SafeConfigParser"):
            h[name] = self.h_config
        for name in ("base64.b64encode", "base64.standard_b64encode", "base64.encodebytes", "base64.b32encode", "base64.b16encode", "base64.b85encode"):
            h[name] = self.h_b64encode
        h["base64.urlsafe_b64encode"] = self.h_b64encode_url
        for name in ("base64.b64decode", "base64.standard_b64decode", "base64.urlsafe_b64decode", "base64.decodebytes", "base64.b32decode", "base64.b16decode", "base64.b85decode"):
            h[name] = self.h_decode_reset
        for name in ("urllib.parse.unquote", "urllib.parse.unquote_plus", "html.unescape", "urllib.parse.unquote_to_bytes", "codecs.decode", "binascii.unhexlify", "bytes.fromhex", "json.loads"):
            h[name] = self.h_decode_reset
        h["html.escape"] = self.h_html_escape
        for name in ("urllib.parse.urlparse", "urllib.parse.urlsplit"):
            h[name] = self.h_urlparse
        h["urllib.parse.urljoin"] = self.h_urljoin
        for name in ("yaml.load", "yaml.load_all"):
            h[name] = self.h_yaml
        for name in ("xml.dom.minidom.parseString", "xml.dom.minidom.parse", "xml.dom.pulldom.parseString", "xml.dom.pulldom.parse"):
            h[name] = self.h_minidom
        h["xml.sax.make_parser"] = self.h_sax_parser
        h["lxml.etree.XMLParser"] = self.h_lxml_parser
        for name in ("lxml.etree.fromstring", "lxml.etree.XML", "lxml.etree.parse"):
            h[name] = self.h_lxml_parse
        h["hashlib.new"] = self.h_hash_new
        for name in WEAK_HASHES:
            h["hashlib." + name] = self.h_hash_weak
        for name in ("Crypto.Hash.MD5.new", "Crypto.Hash.SHA1.new", "Cryptodome.Hash.MD5.new", "Cryptodome.Hash.SHA1.new", "cryptography.hazmat.primitives.hashes.MD5", "cryptography.hazmat.primitives.hashes.SHA1"):
            h[name] = self.h_hash_weak
        h["random.SystemRandom"] = lambda f, a, k, e: f.alloc(e, LibObj("random.SystemRandom", ()))
        h["random.Random"] = lambda f, a, k, e: f.alloc(e, LibObj("random.Random", ()))
        h["re.compile"] = self.h_re_compile
        for name in ("re.match", "re.fullmatch", "re.search"):
            h[name] = self.h_re_match
        h["re.sub"] = self.h_re_sub
        h["re.escape"] = self.h_decode_reset
        h["flask.make_response"] = self.h_make_response
        for name in ("flask.Response", "werkzeug.wrappers.Response", "flask.wrappers.Response"):
            h[name] = self.h_response
        for name in ("flask.redirect", "werkzeug.utils.redirect"):
            h[name] = self.h_redirect
        for name in ("flask.render_template", "flask.render_template_string"):
            h[name] = self.h_render
        for name in ("flask.jsonify", "flask.json.jsonify"):
            h[name] = lambda f, a, k, e: f.alloc(e, LibObj("flask.Response", (("html", FALSE),)))
        h["flask.abort"] = lambda f, a, k, e: EMPTY
        for name in ("json.dumps", "json.dump"):
            h[name] = self.h_json_dumps
        for name in ("markupsafe.Markup", "flask.Markup"):
            h[name] = self.h_markup
        h["django.http.HttpResponse"] = self.h_django_response
        h["fastapi.responses.Response"] = self.h_media_response
        h["starlette.responses.Response"] = self.h_media_response
        h["django.utils.html.format_html"] = self.h_format_html
        h["shlex.split"] = self.h_shlex_split
        h["ast.literal_eval"] = lambda f, a, k, e: f.taint_union([arg(a, k, 0, "node_or_string", UNKNOWN)], e)
        m = self.mhooks
        for t in RESPONSE_TYPES:
            m[t + ".set_cookie"] = self.m_set_cookie
        m["io.StringIO.write"] = self.m_sio_write
        m["io.StringIO.getvalue"] = self.m_sio_get
        m["io.StringIO.read"] = self.m_sio_get
        m["io.StringIO.seek"] = lambda f, aid, o, a, k, e: NONE
        m["configparser.ConfigParser.set"] = self.m_cfg_set
        m["configparser.ConfigParser.get"] = self.m_cfg_get
        m["configparser.ConfigParser.getint"] = self.m_cfg_num
        m["configparser.ConfigParser.getfloat"] = self.m_cfg_num
        m["configparser.ConfigParser.getboolean"] = lambda f, aid, o, a, k, e: BOOL
        m["configparser.ConfigParser.add_section"] = lambda f, aid, o, a, k, e: NONE
        m["configparser.ConfigParser.has_section"] = lambda f, aid, o, a, k, e: BOOL
        m["configparser.ConfigParser.has_option"] = lambda f, aid, o, a, k, e: BOOL
        m["configparser.ConfigParser.read"] = self.m_cfg_read
        m["configparser.ConfigParser.read_string"] = self.m_cfg_read_string
        m["xml.sax.XMLReader.setFeature"] = self.m_sax_feature
        m["xml.sax.XMLReader.parse"] = self.m_sax_parse
        m["re.Pattern.match"] = self.m_pattern_match
        m["re.Pattern.fullmatch"] = self.m_pattern_match
        m["re.Pattern.search"] = self.m_pattern_match
        m["re.Pattern.sub"] = self.m_pattern_sub
        m["re.Match.group"] = self.m_match_group
        m["re.Match.groups"] = self.m_match_group
        m["re.Match.groupdict"] = self.m_match_group
        m["io.file.read"] = lambda f, aid, o, a, k, e: Val([S.opaque(raw=True), S.opaque()])
        m["io.file.readline"] = lambda f, aid, o, a, k, e: Val([S.opaque()])
        m["io.file.readlines"] = lambda f, aid, o, a, k, e: f.make_list(Val([S.opaque()]), e)
        m["io.file.write"] = lambda f, aid, o, a, k, e: Val([Num()])
        m["io.file.close"] = lambda f, aid, o, a, k, e: NONE
        m["io.file.__enter__"] = lambda f, aid, o, a, k, e: Val([Ref(aid)])
        for name in ("open", "read_text", "read_bytes", "write_text", "write_bytes", "exists", "is_file", "is_dir", "unlink", "mkdir", "rmdir", "touch", "stat", "iterdir", "glob", "rglob", "chmod", "rename", "replace", "lstat", "symlink_to", "samefile", "readlink"):
            m["pathlib.Path." + name] = self.m_path_sink
        for name in ("resolve", "absolute", "expanduser", "joinpath", "with_name", "with_suffix", "with_stem", "relative_to", "as_posix", "__str__", "__fspath__"):
            m["pathlib.Path." + name] = self.m_path_derive
        m["pathlib.Path.is_relative_to"] = lambda f, aid, o, a, k, e: BOOL
        m["urllib.parse.ParseResult.geturl"] = lambda f, aid, o, a, k, e: o.get("src", UNKNOWN)
        m["random.SystemRandom.random"] = lambda f, aid, o, a, k, e: Val([Num()])
        m["subprocess.Popen.communicate"] = lambda f, aid, o, a, k, e: Val([Tup((Val([S.opaque()]), Val([S.opaque()])))])
        a = self.ahooks
        for name in ("name", "stem", "suffix"):
            a["pathlib.Path." + name] = self.a_path_name
        a["pathlib.Path.parent"] = self.a_path_parent

    def called(self):
        return self.qn.rsplit(".", 1)[-1]

    def builtin(self, name):
        if name in BUILTIN_NAMES:
            return Val([Lib("builtins." + name)])
        return UNKNOWN

    def lib_value(self, frame, qn, e):
        base, _, name = qn.rpartition(".")
        if not base:
            return Val([Lib(qn)])
        return self.attr(frame, base, name, e)

    def attr(self, frame, base, name, e):
        qn = base + "." + name
        if qn == "flask.request.path":
            rule = frame.view_rule()
            if rule is not None and "<" not in rule and "\x00" not in rule:
                return const(rule)
        if qn in ("flask.request.method", "flask.request.endpoint", "flask.request.url_rule", "flask.request.blueprint", "flask.request.scheme", "flask.request.is_secure", "flask.request.is_json"):
            return UNKNOWN
        label = self.sources.get(qn)
        if label is not None:
            return Val([Unk(self.source_hole(frame, label, e))])
        if base.startswith("$request."):
            if name == "session":
                return Val([Lib("$session")])
            return UNKNOWN
        if qn in self.consts:
            return Val([next(iter(const(c).alts)) for c in self.consts[qn]])
        return Val([Lib(qn)])

    def source_hole(self, frame, label, e):
        h = frame.source("input", label, e)
        if label.endswith(("json", "get_json")):
            return h.with_props(Props(flags=frozenset(["json"])))
        if label in ("request.url", "request.base_url", "request.url_root", "request.host_url", "request.full_path"):
            return h.with_props(Props(allowed=URL_SAFE))
        return h

    def unknown_method(self, frame, name, args, kwargs, e):
        if name in SQL_METHODS:
            frame.report_val("sqli", "sql", arg(args, kwargs, 0, "sql", UNKNOWN), e, name)
            return UNKNOWN
        if name in CLEAN_METHODS:
            return UNKNOWN
        return frame.taint_union(list(args) + list(kwargs.values()), e)

    def lib_index(self, frame, name, key, e):
        if name in ("os.environ",):
            return Val([S.opaque()])
        return UNKNOWN

    def store_lib_item(self, frame, name, key, v, e):
        if name in ("flask.session", "$session", "starlette.session"):
            frame.report_val("trust-boundary", "trust", key, e, "session key")
            frame.report_val("trust-boundary", "trust", v, e, "session value")
            self.weak_check(frame, ["session"], v, e)

    def store_obj_item(self, frame, aid, obj, key, v, e):
        if obj.type == "configparser.ConfigParser":
            return
        d = obj.as_dict()
        k = key.single_const()
        if isinstance(k, str):
            d["item:" + k] = v
            frame.put(aid, LibObj(obj.type, items_tuple(d)))

    def call(self, frame, qn, args, kwargs, e):
        if qn.startswith("builtins."):
            return self.call_builtin(frame, qn[9:], args, kwargs, e)
        if qn in self.sources:
            return Val([Unk(self.source_hole(frame, self.sources[qn], e))])
        hook = self.hooks.get(qn)
        if hook is not None:
            self.qn = qn
            return hook(frame, args, kwargs, e)
        return self.generic(frame, qn, args, kwargs, e)

    def generic(self, frame, qn, args, kwargs, e, recv=None):
        spec = self.sinks.get(qn)
        if spec is not None:
            self.check_sink(frame, spec, args, kwargs, e, qn)
        san = self.sanitizers.get(qn)
        if san is not None:
            return self.sanitize(frame, qn, san, arg(args, kwargs, san.get("arg", 0), None, UNKNOWN), e)
        if qn in self.weakrand:
            return self.weak_source(frame, qn, e)
        if qn in self.call_consts:
            vals = self.call_consts[qn]
            return Val([next(iter(const(c).alts)) for c in vals]) if vals else Val([S.opaque()])
        t = self.returns.get(qn)
        if t is not None:
            return frame.alloc(e, LibObj(t, ()))
        if qn in self.clean:
            return UNKNOWN
        if qn.startswith("$request."):
            return UNKNOWN
        last = qn.rsplit(".", 1)[-1]
        if last in SQL_METHODS or last in CLEAN_METHODS:
            return self.unknown_method(frame, last, args, kwargs, e)
        vals = list(args) + list(kwargs.values())
        return frame.taint_union(vals, e)

    def check_sink(self, frame, spec, args, kwargs, e, qn):
        label = short(qn)
        for i in spec.get("args", []):
            if i < len(args):
                frame.report_val(spec["rule"], spec["mode"], args[i], e, label)
        for k in spec.get("kwargs", []):
            if k in kwargs:
                frame.report_val(spec["rule"], spec["mode"], kwargs[k], e, label)

    def sanitize(self, frame, qn, spec, v, e):
        allowed = spec.get("allowed")
        excl = spec.get("excl", ())
        kinds = spec.get("kinds", ())
        fn = PURE_STR.get(qn)
        site = frame.site(e)
        out = []
        for a in v.alts:
            s = a if isinstance(a, Str) else frame.str_alt(a)
            if s is None:
                s = S.opaque()
            if s.is_const():
                if fn is not None and not s.raw:
                    try:
                        out.append(Str.make([fn(s.text())]))
                        continue
                    except Exception:
                        pass
                out.append(s)
                continue
            out.append(S.transform_holes(s, site, lambda p: p.restrict(allowed=allowed, excl=excl, kinds=kinds)))
        return frame.bound(Val(out))

    def weak_source(self, frame, qn, e):
        name = qn.rsplit(".", 1)[-1]
        hole = frame.source("weakrand", short(qn) + "()", e)
        if self.weak_mode == "always":
            frame.report("weak-random", frame.loc(e), hole, short(qn))
        if name in ("randbytes", "bytes"):
            return Val([Str((hole.with_props(Props()),), raw=True)])
        if name in ("choice", "choices", "sample"):
            return Val([Unk(hole)])
        return Val([Num(hole.with_props(NUMERIC))])

    def weak_check(self, frame, names, v, e):
        if self.weak_mode == "off" or not v.tainted("weakrand"):
            return
        if self.weak_mode == "sensitive" and not any(self.is_sensitive(n) for n in names if n):
            return
        for h in v.holes():
            if any(f.kind == "weakrand" for f in h.facts):
                frame.report("weak-random", frame.loc(e), h, "sensitive value")

    def is_sensitive(self, name):
        low = name.lower()
        words = re.split(r"[^a-z0-9]+|(?<=[a-z])(?=[A-Z])", name)
        tokens = {w.lower() for w in words if w}
        for s in self.sensitive:
            if len(s) >= 5 and s in low:
                return True
            if s in tokens:
                return True
        return False

    def weak_store(self, frame, name, key, v, stmt):
        if self.weak_mode == "off" or not v.tainted("weakrand"):
            return
        names = [name]
        if key is not None:
            for c in key.consts() or []:
                if isinstance(c, str):
                    names.append(c)
            for s in key.strs():
                names.extend(p for p in s.parts if isinstance(p, str))
        self.weak_check(frame, names, v, stmt)

    def view_return(self, frame, v, stmt):
        info = frame.info
        if info.framework not in ("flask", None):
            return
        body = EMPTY
        for a in v.alts:
            if isinstance(a, Unk) and a.hole is not None and "json" in a.hole.props.flags and a.hole.hid[0] == "s":
                continue
            if isinstance(a, (Str, Unk)):
                body = body.join(Val([a]))
            elif isinstance(a, Tup) and a.items:
                body = body.join(a.items[0])
            elif isinstance(a, Ref):
                obj = frame.get(a.aid)
                if isinstance(obj, LibObj) and obj.type == "flask.Response":
                    if obj.get("html", TRUE).truth() is False:
                        continue
                    mt = obj.get("mimetype") or obj.get("content_type")
                    c = mt.single_const() if mt is not None else NOTHING
                    if isinstance(c, str) and "html" not in c.lower():
                        continue
                    b = obj.get("body")
                    if b is not None:
                        body = body.join(b)
        if not body.is_empty():
            frame.report_val("xss", "html", body, stmt, "the HTML response")

    def call_builtin(self, frame, name, args, kwargs, e):
        m = getattr(self, "b_" + name, None)
        if m is not None:
            return m(frame, args, kwargs, e)
        if name in ("isinstance", "issubclass", "hasattr", "callable", "any", "all"):
            return BOOL
        if name in ("print", "setattr", "delattr"):
            if name == "setattr" and len(args) >= 3:
                n = args[1].single_const()
                if isinstance(n, str):
                    frame.store_attr(args[0], n, args[2], e)
            return NONE
        if name in ("id", "hash", "abs", "round", "divmod", "pow", "sum"):
            return frame.taint_union(list(args), e, numeric=True)
        if name in ("staticmethod", "classmethod", "property", "iter", "memoryview"):
            return args[0] if args else UNKNOWN
        if name in ("type", "super", "vars", "dir", "globals", "locals", "object", "slice", "input", "__import__", "breakpoint", "help", "quit", "exit"):
            return UNKNOWN
        return frame.taint_union(list(args) + list(kwargs.values()), e)

    def b_str(self, frame, args, kwargs, e):
        if not args:
            return const("")
        if len(args) >= 2 or "encoding" in kwargs:
            return self.retype(args[0], False)
        return frame.to_str(args[0], e)

    def b_repr(self, frame, args, kwargs, e):
        return self.repr_val(frame, args[0] if args else UNKNOWN, e)

    b_ascii = b_repr

    def b_format(self, frame, args, kwargs, e):
        return frame.to_str(args[0], e) if args else const("")

    def b_bytes(self, frame, args, kwargs, e):
        if not args:
            return const(b"")
        v = args[0]
        if any(isinstance(a, Str) for a in v.alts):
            return self.retype(v, True)
        return frame.taint_union([v], e)

    b_bytearray = b_bytes

    def retype(self, v, raw):
        out = []
        for a in v.alts:
            if isinstance(a, Str):
                out.append(Str(a.parts, raw))
            elif isinstance(a, Unk) and a.hole is not None:
                out.append(Str((a.hole,), raw))
            else:
                out.append(S.opaque(raw))
        return Val(out)

    def b_int(self, frame, args, kwargs, e):
        return self.to_number(frame, args, e, int)

    def b_float(self, frame, args, kwargs, e):
        return self.to_number(frame, args, e, float)

    def to_number(self, frame, args, e, kind):
        if not args:
            return const(kind())
        out = []
        for a in args[0].alts:
            if isinstance(a, Const) and isinstance(a.value, (int, float, bool)):
                try:
                    out.append(Const(kind(a.value)))
                except (ValueError, OverflowError):
                    pass
            elif isinstance(a, Str) and a.is_const():
                try:
                    out.append(Const(kind(a.text()) if len(args) < 2 or kind is float else kind(a.text(), args[1].single_const())))
                except (ValueError, TypeError):
                    pass
            else:
                holes = [h for h in Val([a]).holes() if h.facts]
                if holes:
                    h = S.derive(merge_holes(holes), frame.site(e))
                    out.append(Num(h.with_props(h.props.restrict(allowed="-+."))))
                else:
                    out.append(Num())
        return Val(out) if out else EMPTY

    def b_bool(self, frame, args, kwargs, e):
        if not args:
            return FALSE
        t = args[0].truth()
        return BOOL if t is None else const(t)

    def b_len(self, frame, args, kwargs, e):
        if not args:
            return Val([Num()])
        out = []
        for a in args[0].alts:
            if isinstance(a, Str):
                out.append(Const(len(a.text())) if a.is_const() else LenOf(a, 0))
            elif isinstance(a, Tup):
                out.append(Const(len(a.items)))
            elif isinstance(a, Ref):
                obj = frame.get(a.aid)
                if isinstance(obj, ListObj) and obj.elems is not None and obj.summ is None:
                    out.append(Const(len(obj.elems)))
                elif isinstance(obj, DictObj) and obj.rest is None:
                    out.append(Const(len(obj.items)))
                else:
                    out.append(Num())
            else:
                out.append(Num())
        return Val(out)

    def b_ord(self, frame, args, kwargs, e):
        out = []
        for a in (args[0] if args else UNKNOWN).alts:
            if isinstance(a, Str) and a.is_const() and len(a.text()) == 1:
                out.append(Const(ord(a.text())))
            elif isinstance(a, Num):
                out.append(a)
            else:
                holes = [h for h in Val([a]).holes() if h.facts]
                if holes:
                    h = S.derive(merge_holes(holes), frame.site(e))
                    out.append(Num(h.with_props(h.props.restrict(allowed="-+."))))
                else:
                    out.append(Num())
        return Val(out)

    def b_chr(self, frame, args, kwargs, e):
        out = []
        for a in (args[0] if args else UNKNOWN).alts:
            if isinstance(a, Const) and isinstance(a.value, int):
                try:
                    out.append(Str.make([chr(a.value)]))
                except (ValueError, OverflowError):
                    pass
            elif isinstance(a, Num) and a.hole is not None:
                out.append(Str((S.derive(a.hole, frame.site(e), Props()),)))
            else:
                out.append(S.opaque())
        return Val(out)

    def number_text(self, frame, args, e, fn):
        out = []
        for a in (args[0] if args else UNKNOWN).alts:
            if isinstance(a, Const) and isinstance(a.value, int):
                out.append(Str.make([fn(a.value)]))
            elif isinstance(a, Num) and a.hole is not None:
                h = S.derive(a.hole, frame.site(e))
                out.append(Str((h.with_props(h.props.restrict(allowed="-")),)))
            else:
                out.append(S.opaque())
        return Val(out)

    def b_hex(self, frame, args, kwargs, e):
        return self.number_text(frame, args, e, hex)

    def b_oct(self, frame, args, kwargs, e):
        return self.number_text(frame, args, e, oct)

    def b_bin(self, frame, args, kwargs, e):
        return self.number_text(frame, args, e, bin)

    def b_min(self, frame, args, kwargs, e):
        if len(args) == 1:
            return frame.iter_elems(args[0], e)
        out = EMPTY
        for v in args:
            out = out.join(v)
        return frame.bound(out)

    b_max = b_min

    def b_getattr(self, frame, args, kwargs, e):
        if len(args) < 2:
            return UNKNOWN
        obj, name = args[0], args[1]
        n = name.single_const()
        out = EMPTY
        if isinstance(n, str):
            for a in obj.alts:
                out = out.join(frame.get_attr(a, n, e))
        else:
            for a in obj.alts:
                if isinstance(a, Mod) and a.name in frame.an.project.modules:
                    for v in frame.an.module_env(a.name).values():
                        for x in v.alts:
                            if isinstance(x, (Fn, Cls)) and (not isinstance(x, Fn) or frame.an.funcs[x.fid].module.name == a.name):
                                out = out.join(Val([x]))
                            elif isinstance(x, Cls) and x.cid[0] == a.name:
                                out = out.join(Val([x]))
                elif isinstance(a, Ref):
                    o = frame.get(a.aid)
                    if isinstance(o, InstObj):
                        for _, v in o.attrs:
                            out = out.join(v)
                        ci = frame.an.classes.get(o.cid)
                        if ci is not None:
                            for v in ci.attrs.values():
                                out = out.join(frame.bind_method(v, Val([a]), o.cid))
                    else:
                        out = out.join(UNKNOWN)
                else:
                    out = out.join(UNKNOWN)
        if len(args) > 2:
            out = out.join(args[2])
        return frame.bound(out) if not out.is_empty() else UNKNOWN

    def b_list(self, frame, args, kwargs, e):
        return self.collection(frame, args, e, "list")

    def b_set(self, frame, args, kwargs, e):
        return self.collection(frame, args, e, "set")

    b_frozenset = b_set

    def b_sorted(self, frame, args, kwargs, e):
        if args:
            elems = frame.iter_elems(args[0], e)
            consts = elems.consts()
            if consts is not None:
                try:
                    items = [const(c) for c in sorted(consts)]
                    if len(items) <= frame.an.max_items:
                        return frame.alloc(e, ListObj("list", tuple(items), None))
                except TypeError:
                    pass
        return self.collection(frame, args, e, "list", exact=False)

    def b_reversed(self, frame, args, kwargs, e):
        return self.collection(frame, args, e, "list", reverse=True)

    def collection(self, frame, args, e, kind, exact=True, reverse=False):
        if not args:
            return frame.alloc(e, ListObj(kind, () if kind == "list" else None, None if kind == "list" else EMPTY))
        v = args[0]
        if exact and kind == "list" and len(v.alts) == 1:
            items = frame.exact_items(next(iter(v.alts)))
            if items is not None and len(items) <= frame.an.max_items:
                if reverse:
                    items = list(reversed(items))
                return frame.alloc(e, ListObj(kind, tuple(items), None))
        return frame.alloc(e, ListObj(kind, None, frame.iter_elems(v, e)))

    def b_tuple(self, frame, args, kwargs, e):
        if not args:
            return Val([Tup(())])
        v = args[0]
        if len(v.alts) == 1:
            items = frame.exact_items(next(iter(v.alts)))
            if items is not None:
                return Val([Tup(tuple(items))])
        el = frame.iter_elems(v, e)
        holes = [h for h in el.holes() if h.facts]
        return Val([Unk(merge_holes(holes))]) if holes else UNKNOWN

    def b_dict(self, frame, args, kwargs, e):
        d = {}
        rest = None
        if args:
            for a in args[0].alts:
                if isinstance(a, Ref):
                    obj = frame.get(a.aid)
                    if isinstance(obj, DictObj):
                        d.update(obj.as_dict())
                        rest = obj.rest
                        continue
                el = frame.iter_elems(Val([a]), e)
                rest = el if rest is None else rest.join(el)
        for k, v in kwargs.items():
            if k == "**":
                rest = v if rest is None else rest.join(v)
            else:
                d[k] = v
        return frame.alloc(e, DictObj(items_tuple(d), rest))

    def b_enumerate(self, frame, args, kwargs, e):
        el = frame.iter_elems(args[0], e) if args else UNKNOWN
        return frame.alloc(e, ListObj("list", None, Val([Tup((Val([Num()]), el))])))

    def b_zip(self, frame, args, kwargs, e):
        return frame.alloc(e, ListObj("list", None, Val([Tup(tuple(frame.iter_elems(a, e) for a in args))])))

    def b_map(self, frame, args, kwargs, e):
        if len(args) < 2:
            return UNKNOWN
        el = [frame.iter_elems(a, e) for a in args[1:]]
        r = frame.call_val(args[0], el, {}, e)
        return frame.alloc(e, ListObj("list", None, r if not r.is_empty() else UNKNOWN))

    def b_filter(self, frame, args, kwargs, e):
        if len(args) < 2:
            return UNKNOWN
        return frame.alloc(e, ListObj("list", None, frame.iter_elems(args[1], e)))

    def b_range(self, frame, args, kwargs, e):
        return frame.alloc(e, ListObj("list", None, Val([Num()])))

    def b_next(self, frame, args, kwargs, e):
        if not args:
            return UNKNOWN
        out = frame.iter_elems(args[0], e)
        if len(args) > 1:
            out = out.join(args[1])
        return out

    def b_open(self, frame, args, kwargs, e):
        return self.h_open(frame, args, kwargs, e)

    def b_eval(self, frame, args, kwargs, e):
        v = arg(args, kwargs, 0, "source", UNKNOWN)
        frame.report_val("codeinj", "code", v, e, "eval")
        return frame.taint_union([v], e)

    def b_exec(self, frame, args, kwargs, e):
        v = arg(args, kwargs, 0, "source", UNKNOWN)
        frame.report_val("codeinj", "code", v, e, "exec")
        return NONE

    def b_compile(self, frame, args, kwargs, e):
        v = arg(args, kwargs, 0, "source", UNKNOWN)
        frame.report_val("codeinj", "code", v, e, "compile")
        return UNKNOWN

    def str_val(self, frame, v, e, seen=None):
        out = []
        for a in v.alts:
            if isinstance(a, Str):
                out.append(S.to_text(a))
            elif isinstance(a, Ref):
                seen = set() if seen is None else seen
                if a.aid in seen:
                    out.append(S.opaque())
                    continue
                seen.add(a.aid)
                out.extend(self.obj_str(frame, a.aid, e, seen).alts)
            elif isinstance(a, (Fn, Cls, Mod, Lib, Meth)):
                out.append(S.opaque())
            else:
                s = S.as_str(a)
                out.append(s if s is not None else S.opaque())
        return frame.bound(Val(out)) if out else Val([S.opaque()])

    def obj_str(self, frame, aid, e, seen):
        obj = frame.get(aid)
        if isinstance(obj, LibObj):
            for key in ("path", "src"):
                p = obj.get(key)
                if p is not None:
                    return self.str_val(frame, p, e, seen)
            if obj.type == "markup":
                return obj.get("text", Val([S.opaque()]))
            return Val([S.opaque()])
        if isinstance(obj, InstObj):
            if frame.class_attr(obj.cid, "__str__") is not None:
                r = frame.call_method(Val([Ref(aid)]), "__str__", [], {}, e)
                return self.str_val(frame, r, e, seen)
            return Val([S.opaque()])
        if isinstance(obj, (ListObj, DictObj)):
            holes = []
            for v in ([obj.all_values()] if isinstance(obj, ListObj) else [obj.all_values()]):
                holes.extend(h for h in v.holes() if h.facts)
            if holes:
                return Val([Str.make(["[", merge_holes(holes), "]"])])
            return Val([S.opaque()])
        return Val([S.opaque()])

    def repr_val(self, frame, v, e):
        out = []
        for a in v.alts:
            if isinstance(a, Str) and a.is_const():
                out.append(Str.make([repr(a.python())]))
            elif isinstance(a, Str):
                out.append(Str.make(["'"] + list(a.parts) + ["'"]))
            else:
                out.extend(self.str_val(frame, Val([a]), e).alts)
        return Val(out)

    def percent_format(self, frame, fmt, args_val, e):
        site = frame.site(e)
        if not fmt.is_const():
            holes = [h for h in fmt.holes() if h.facts] + [h for h in args_val.holes() if h.facts]
            return Val([Str((S.derive(merge_holes(holes), site),))]) if holes else Val([S.opaque()])
        spec = S.parse_percent(fmt.text())
        if spec is None:
            return Val([S.summarize(fmt, site)])
        out = EMPTY
        for a in args_val.alts:
            items = None
            mapping = None
            if isinstance(a, Tup):
                items = list(a.items)
            elif isinstance(a, Ref) and isinstance(frame.get(a.aid), DictObj):
                mapping = frame.get(a.aid)
                items = []
            else:
                items = [Val([a])]
            parts = [Str.make([""])]
            idx = 0
            for piece in spec:
                if isinstance(piece, str):
                    parts = [S.concat(p, Str.make([piece])) for p in parts]
                    continue
                _, key, conv = piece
                if key is not None and mapping is not None:
                    d = mapping.as_dict()
                    val = d.get(key, mapping.rest if mapping.rest is not None else UNKNOWN)
                else:
                    val = items[idx] if idx < len(items) else UNKNOWN
                    idx += 1
                if conv in "sra":
                    sv = self.str_val(frame, val, e) if conv == "s" else self.repr_val(frame, val, e)
                else:
                    sv = self.str_val(frame, frame.taint_union([val], e, numeric=True), e)
                new = []
                for p in parts:
                    for q in sv.alts:
                        new.append(S.concat(p, q if isinstance(q, Str) else S.opaque()))
                parts = list(frame.collapse(Val(new)).alts)
            out = out.join(Val(parts))
        return frame.bound(out)

    def str_format(self, frame, s, args, kwargs, e):
        site = frame.site(e)
        if not s.is_const():
            vals = list(args) + list(kwargs.values())
            holes = [h for h in s.holes() if h.facts]
            for v in vals:
                holes.extend(h for h in v.holes() if h.facts)
            return Val([Str((S.derive(merge_holes(holes), site),))]) if holes else Val([S.opaque()])
        parsed = S.parse_format(s.text())
        if parsed is None:
            return EMPTY
        parts = [Str.make([""])]
        auto = 0
        for literal, field, _, conv in parsed:
            if literal:
                parts = [S.concat(p, Str.make([literal])) for p in parts]
            if field is None:
                continue
            pf = S.parse_field(field) if field else ("", [])
            if pf is None:
                return EMPTY
            first, rest = pf
            if first == "":
                first = auto
                auto += 1
            if isinstance(first, int):
                val = args[first] if first < len(args) else UNKNOWN
            else:
                val = kwargs.get(first, UNKNOWN)
            for is_attr, key in rest:
                nv = EMPTY
                for alt in val.alts:
                    nv = nv.join(frame.get_attr(alt, key, e) if is_attr else frame.index_alt(alt, const(key), e))
                val = nv if not nv.is_empty() else UNKNOWN
            sv = self.repr_val(frame, val, e) if conv == "r" else self.str_val(frame, val, e)
            new = []
            for p in parts:
                for q in sv.alts:
                    new.append(S.concat(p, q if isinstance(q, Str) else S.opaque()))
            parts = list(frame.collapse(Val(new)).alts)
        return frame.bound(Val(parts))

    def str_method(self, frame, s, name, args, kwargs, e):
        site = frame.site(e)

        def c(i, default=NOTHING, key=None):
            v = arg(args, kwargs, i, key)
            if v is None:
                return default
            return v.single_const()

        if name == "format":
            return self.str_format(frame, s, args, kwargs, e)
        if name == "format_map":
            if args:
                mapping = args[0]
                kw = {}
                for a in mapping.alts:
                    if isinstance(a, Ref) and isinstance(frame.get(a.aid), DictObj):
                        kw.update({k: v for k, v in frame.get(a.aid).items if isinstance(k, str)})
                return self.str_format(frame, s, [], kw, e)
            return Val([S.summarize(s, site)])
        if name == "join":
            return self.str_join(frame, s, args[0] if args else UNKNOWN, e)
        if name == "replace":
            old, new = c(0), c(1)
            count = c(2, -1, "count")
            if isinstance(old, (str, bytes)) and isinstance(new, (str, bytes)) and isinstance(count, int):
                if isinstance(old, bytes):
                    old = old.decode("latin-1")
                if isinstance(new, bytes):
                    new = new.decode("latin-1")
                return Val([S.replace(s, old, new, count, site)])
            return Val([S.summarize(s, site, Props())])
        if name in ("split", "rsplit", "splitlines"):
            if name == "splitlines":
                sep, maxsplit = "\n", -1
            else:
                sep = c(0, None, "sep")
                maxsplit = c(1, -1, "maxsplit")
            if isinstance(sep, bytes):
                sep = sep.decode("latin-1")
            if sep is NOTHING or not (sep is None or isinstance(sep, str)) or not isinstance(maxsplit, int):
                return frame.make_list(Val([S.summarize(s, site)]), e)
            if s.is_const() and name == "rsplit":
                t = s.text()
                pieces = t.rsplit(sep, maxsplit) if sep is not None else t.rsplit(None, maxsplit)
                return frame.alloc(e, ListObj("list", tuple(Val([Str.make([x], s.raw)]) for x in pieces), None))
            if s.is_const() and name == "splitlines":
                return frame.alloc(e, ListObj("list", tuple(Val([Str.make([x], s.raw)]) for x in s.text().splitlines()), None))
            exact, alts = S.split(s, sep, maxsplit, site)
            if exact is not None:
                return frame.alloc(e, ListObj("list", tuple(Val([x]) for x in exact), None))
            return frame.alloc(e, ListObj("list", None, Val(alts)))
        if name in ("partition", "rpartition"):
            sep = c(0)
            if s.is_const() and isinstance(sep, str):
                a, b, d = getattr(s.text(), name)(sep)
                return Val([Tup((const(a), const(b), const(d)))])
            piece = Val([S.summarize(s, site)])
            return Val([Tup((piece, Val([Str.make([sep])]) if isinstance(sep, str) else Val([S.opaque()]), piece))])
        if name in ("strip", "lstrip", "rstrip"):
            chars = c(0, None)
            if chars is NOTHING:
                return Val([S.summarize(s, site)])
            return Val([S.strip_like(s, name, (chars,) if chars is not None else (), site)])
        if name in ("lower", "upper", "casefold", "swapcase", "title", "capitalize"):
            return Val([S.map_const_parts(s, lambda t: getattr(t, name)(), site)])
        if name in ("startswith", "endswith"):
            p = c(0)
            ps = list(p) if isinstance(p, tuple) else [p]
            results = set()
            for x in ps:
                if isinstance(x, bytes):
                    x = x.decode("latin-1")
                if not isinstance(x, str):
                    return BOOL
                results.add(S.startswith(s, x) if name == "startswith" else S.endswith(s, x))
            if True in results:
                return TRUE
            if results == {False}:
                return FALSE
            return BOOL
        if name in ("find", "rfind", "index", "rindex", "count"):
            sub = c(0)
            if s.is_const() and isinstance(sub, str):
                try:
                    return const(getattr(s.text(), name)(sub))
                except ValueError:
                    return EMPTY
            return Val([Num()])
        if name.startswith("is"):
            if s.is_const():
                try:
                    return const(getattr(s.text(), name)())
                except (AttributeError, TypeError):
                    return BOOL
            return BOOL
        if name == "encode":
            return Val([Str(s.parts, True)])
        if name == "decode":
            return Val([Str(s.parts, False)])
        if name in ("zfill", "center", "ljust", "rjust", "expandtabs"):
            if s.is_const():
                try:
                    return const(getattr(s.text(), name)(*[a.single_const() for a in args]))
                except Exception:
                    return Val([S.opaque()])
            return Val([S.transform_holes(s, site)])
        if name in ("removeprefix", "removesuffix"):
            x = c(0)
            if isinstance(x, str):
                if s.is_const():
                    return const(getattr(s.text(), name)(x))
                parts = list(s.parts)
                if name == "removeprefix" and parts and isinstance(parts[0], str) and parts[0].startswith(x):
                    parts[0] = parts[0][len(x):]
                elif name == "removesuffix" and parts and isinstance(parts[-1], str) and parts[-1].endswith(x):
                    parts[-1] = parts[-1][: len(parts[-1]) - len(x)] if x else parts[-1]
                else:
                    return Val([S.transform_holes(s, site)])
                return Val([Str.make(parts, s.raw)])
            return Val([S.summarize(s, site)])
        if name == "hex":
            return Val([S.summarize(s, site, Props(allowed=frozenset()))]) if not s.is_const() else const(s.python().hex() if s.raw else s.text())
        if name == "translate":
            return Val([S.summarize(s, site, Props())])
        if name in ("__len__",):
            return self.b_len(frame, [Val([s])], {}, e)
        return Val([S.summarize(s, site)]) if s.holes() else Val([S.opaque(s.raw)])

    def str_join(self, frame, sep, iterable, e):
        out = EMPTY
        for a in iterable.alts:
            items = frame.exact_items(a)
            if items is not None and len(items) <= frame.an.max_items:
                rows = [[]]
                for it in items:
                    sv = self.str_val(frame, it, e) if not all(isinstance(x, Str) for x in it.alts) else it
                    new = []
                    for r in rows:
                        for q in sv.alts:
                            new.append(r + [q if isinstance(q, Str) else S.opaque()])
                    rows = new[: frame.an.max_alts]
                for r in rows:
                    out = out.join(Val([S.join_strs(sep, r, sep.raw)]))
            else:
                el = frame.iter_elems(Val([a]), e)
                holes = [h for h in el.holes() if h.facts] + [h for h in sep.holes() if h.facts]
                if holes:
                    out = out.join(Val([Str((S.derive(merge_holes(holes), frame.site(e)),), sep.raw)]))
                else:
                    out = out.join(Val([S.opaque(sep.raw)]))
        return frame.bound(out)

    def tainted_method(self, frame, hole, name, args, kwargs, e):
        site = frame.site(e)
        if name in ("resolve", "absolute") and not args:
            v = Val([Str((hole,))])
            return self.new_path(frame, self.normalize(frame, v, e) if name == "resolve" else Val([S.transform_holes(v.strs()[0], site)]), e)
        if name in ("keys", "values", "items", "getlist", "get_all", "split", "to_dict", "lists", "listvalues", "copy", "all"):
            return Val([Unk(S.derive(hole, site))])
        conv = kwargs.get("type") if name in ("get", "getlist") else None
        if conv is not None and any(isinstance(a, Lib) and a.name in ("builtins.int", "builtins.float", "builtins.bool") for a in conv.alts):
            h = S.derive(hole, site)
            out = Val([Num(h.with_props(h.props.restrict(allowed="-+.")))])
            return out.join(args[1]) if len(args) > 1 else out.join(kwargs.get("default", NONE))
        out = Val([Unk(S.derive(hole, site))])
        if name in ("get", "pop", "setdefault", "get_json", "getfirst") and len(args) > 1:
            out = out.join(args[1])
        if name == "get" and "default" in kwargs:
            out = out.join(kwargs["default"])
        if name in ("save",):
            frame.report_val("path-traversal", "path", arg(args, kwargs, 0, "dst", UNKNOWN), e, "file.save")
            return NONE
        return out

    def list_method(self, frame, aid, obj, name, args, kwargs, e):
        kind = obj.kind
        elems = obj.elems
        exact = elems is not None and obj.summ is None
        maxn = frame.an.max_items
        if name in ("append", "add", "appendleft"):
            v = args[0] if args else UNKNOWN
            if exact and kind != "set" and len(elems) < maxn:
                new = (v,) + elems if name == "appendleft" else elems + (v,)
                frame.put(aid, ListObj(kind, new, None))
            else:
                frame.put(aid, ListObj(kind, None, obj.all_values().join(v)))
            return NONE
        if name in ("extend", "update"):
            src = args[0] if args else EMPTY
            items = frame.exact_items(next(iter(src.alts))) if len(src.alts) == 1 else None
            if exact and items is not None and kind != "set" and len(elems) + len(items) <= maxn:
                frame.put(aid, ListObj(kind, elems + tuple(items), None))
            else:
                frame.put(aid, ListObj(kind, None, obj.all_values().join(frame.iter_elems(src, e))))
            return NONE
        if name == "insert":
            i = args[0].single_const() if args else NOTHING
            v = args[1] if len(args) > 1 else UNKNOWN
            if exact and isinstance(i, int) and len(elems) < maxn:
                lst = list(elems)
                lst.insert(i, v)
                frame.put(aid, ListObj(kind, tuple(lst), None))
            else:
                frame.put(aid, ListObj(kind, None, obj.all_values().join(v)))
            return NONE
        if name in ("pop", "popleft"):
            if kind == "set":
                return obj.all_values()
            i = args[0].single_const() if args else (0 if name == "popleft" else -1)
            if exact and isinstance(i, int):
                if not elems or not -len(elems) <= i < len(elems):
                    return EMPTY
                lst = list(elems)
                v = lst.pop(i)
                frame.put(aid, ListObj(kind, tuple(lst), None))
                return v
            return obj.all_values() if not obj.all_values().is_empty() else UNKNOWN
        if name in ("remove", "discard"):
            x = args[0].single_const() if args else NOTHING
            if exact and x is not NOTHING:
                lst = list(elems)
                for i, el in enumerate(lst):
                    if el.single_const() == x and el.consts() is not None:
                        del lst[i]
                        frame.put(aid, ListObj(kind, tuple(lst), None))
                        return NONE
                    if el.consts() is None:
                        break
            if exact:
                frame.put(aid, ListObj(kind, None, obj.all_values()))
            return NONE
        if name == "clear":
            frame.put(aid, ListObj(kind, (), None) if kind != "set" else ListObj(kind, None, EMPTY))
            return NONE
        if name == "copy":
            return frame.alloc(e, ListObj(kind, elems, obj.summ))
        if name == "reverse":
            if exact:
                frame.put(aid, ListObj(kind, tuple(reversed(elems)), None))
            return NONE
        if name == "sort":
            if exact:
                cs = [el.single_const() for el in elems]
                if NOTHING not in cs:
                    try:
                        order = sorted(range(len(cs)), key=lambda i: cs[i])
                        frame.put(aid, ListObj(kind, tuple(elems[i] for i in order), None))
                        return NONE
                    except TypeError:
                        pass
                frame.put(aid, ListObj(kind, None, obj.all_values()))
            return NONE
        if name in ("index", "count"):
            return Val([Num()])
        if name in ("union", "intersection", "difference", "symmetric_difference"):
            out = obj.all_values()
            for a in args:
                out = out.join(frame.iter_elems(a, e))
            return frame.alloc(e, ListObj(kind, None, out))
        if name in ("issubset", "issuperset", "isdisjoint"):
            return BOOL
        return UNKNOWN

    def dict_method(self, frame, aid, obj, name, args, kwargs, e):
        d = obj.as_dict()
        if name in ("get", "pop", "setdefault"):
            key = args[0] if args else UNKNOWN
            default = args[1] if len(args) > 1 else (NONE if name != "pop" else EMPTY)
            ks = key.consts()
            out = EMPTY
            if ks is not None and all(_hashable(k) for k in ks):
                for k in ks:
                    if k in d:
                        out = out.join(d[k])
                    else:
                        if obj.rest is not None:
                            out = out.join(obj.rest)
                        out = out.join(default)
                if name == "pop" and len(ks) == 1 and ks[0] in d:
                    d.pop(ks[0])
                    frame.put(aid, DictObj(items_tuple(d), obj.rest, obj.kind))
                if name == "setdefault" and len(ks) == 1 and ks[0] not in d:
                    d[ks[0]] = default
                    frame.put(aid, DictObj(items_tuple(d), obj.rest, obj.kind))
            else:
                out = obj.all_values().join(default)
            return out if not out.is_empty() else NONE
        if name == "keys":
            keys = [const(k) for k in d]
            if obj.rest is None and len(keys) <= frame.an.max_items:
                return frame.alloc(e, ListObj("list", tuple(keys), None))
            return frame.alloc(e, ListObj("list", None, frame.iter_alt(Ref(aid), e)))
        if name == "values":
            if obj.rest is None and len(d) <= frame.an.max_items:
                return frame.alloc(e, ListObj("list", tuple(d.values()), None))
            return frame.alloc(e, ListObj("list", None, obj.all_values()))
        if name == "items":
            if obj.rest is None and len(d) <= frame.an.max_items:
                return frame.alloc(e, ListObj("list", tuple(Val([Tup((const(k), v))]) for k, v in d.items()), None))
            return frame.alloc(e, ListObj("list", None, Val([Tup((frame.iter_alt(Ref(aid), e), obj.all_values()))])))
        if name == "update":
            for a in args:
                for alt in a.alts:
                    if isinstance(alt, Ref) and isinstance(frame.get(alt.aid), DictObj):
                        d.update(frame.get(alt.aid).as_dict())
            d.update(kwargs)
            frame.put(aid, DictObj(items_tuple(d), obj.rest, obj.kind))
            return NONE
        if name == "copy":
            return frame.alloc(e, DictObj(obj.items, obj.rest, obj.kind))
        if name == "clear":
            frame.put(aid, DictObj((), None, obj.kind))
            return NONE
        if name == "popitem":
            return Val([Tup((frame.iter_alt(Ref(aid), e), obj.all_values()))])
        return UNKNOWN

    def method(self, frame, aid, obj, name, args, kwargs, e):
        qn = obj.type + "." + name
        hook = self.mhooks.get(qn)
        if hook is not None:
            self.qn = qn
            return hook(frame, aid, obj, args, kwargs, e)
        if obj.type in RESPONSE_TYPES or obj.type == "io.file":
            return NONE if name not in ("get_data", "get_json") else UNKNOWN
        if obj.type == "random.Random" and qn in self.weakrand:
            return self.weak_source(frame, qn, e)
        if obj.type == "random.SystemRandom":
            if name in ("randbytes",):
                return Val([S.opaque(raw=True)])
            return Val([Num()]) if name not in ("choice", "sample", "choices") else UNKNOWN
        if obj.type in ("hashlib.hash",):
            if name == "hexdigest":
                return Val([S.opaque()])
            return Val([S.opaque(raw=True)]) if name == "digest" else NONE
        if qn in self.sinks or qn in self.returns or qn in self.sanitizers or qn in self.clean:
            return self.generic(frame, qn, args, kwargs, e)
        if name in ("execute", "executemany", "executescript", "raw") and obj.type not in ("ldap3.Connection",):
            frame.report_val("sqli", "sql", arg(args, kwargs, 0, "sql", UNKNOWN), e, short(qn))
        return frame.taint_union(list(args) + list(kwargs.values()), e)

    def inherited_method(self, frame, aid, base, name, args, kwargs, e):
        return frame.taint_union(list(args) + list(kwargs.values()), e)

    def subclass_init(self, frame, aid, base, args, kwargs, e):
        return None

    def super_method(self, frame, base, me, name, args, kwargs, e):
        if name == "clean" and is_django_form(base):
            return Val([Unk(self.source_hole(frame, "form.cleaned_data", e))])
        return None

    def inherited_attr(self, frame, bases, name, e):
        if name in ("cleaned_data", "data") and any(is_django_form(b) for b in bases):
            return Val([Unk(self.source_hole(frame, "form." + name, e))])
        return UNKNOWN

    def obj_attr(self, frame, aid, obj, name, e):
        v = obj.get(name)
        if v is not None:
            return v
        hook = self.ahooks.get(obj.type + "." + name)
        if hook is not None:
            return hook(frame, aid, obj, e)
        if obj.type == "subprocess.CompletedProcess" and name in ("stdout", "stderr"):
            return Val([S.opaque()])
        if obj.type == "flask.Response" and name == "headers":
            return UNKNOWN
        if obj.type == "io.file" and name == "name":
            return obj.get("path", Val([S.opaque()]))
        return Val([Meth(Val([Ref(aid)]), name)])

    def obj_index(self, frame, aid, obj, key, e):
        if obj.type == "re.Match":
            return self.m_match_group(frame, aid, obj, [key] if key is not None else [], {}, e)
        if obj.type == "configparser.ConfigParser":
            return UNKNOWN
        k = key.single_const() if key is not None else NOTHING
        if isinstance(k, str):
            v = obj.get("item:" + k)
            if v is not None:
                return v
        return UNKNOWN

    def iterate(self, frame, aid, obj, e):
        if obj.type == "io.file":
            return Val([S.opaque()])
        if obj.type == "re.Match":
            return obj.get("group", UNKNOWN)
        return UNKNOWN

    def obj_binop(self, frame, aid, obj, op, other, e):
        if obj.type == "pathlib.Path" and isinstance(op, ast.Div):
            return self.new_path(frame, self.join_paths(frame, [obj.get("path", UNKNOWN), self.path_text(frame, other, e)], e), e)
        return None

    def h_subprocess(self, frame, args, kwargs, e):
        name = self.called()
        cmd = arg(args, kwargs, 0, "args", UNKNOWN)
        shell = kwargs.get("shell")
        shell_t = shell.truth() if shell is not None else False
        executable = kwargs.get("executable")
        if executable is not None:
            frame.report_val("cmdi", "any", executable, e, "subprocess executable")
        for a in cmd.alts:
            if isinstance(a, Ref) and isinstance(frame.get(a.aid), ListObj):
                self.check_argv(frame, frame.get(a.aid), e)
            elif isinstance(a, Tup):
                self.check_argv(frame, ListObj("list", a.items, None), e)
            elif shell_t is not False:
                frame.report_val("cmdi", "shell", Val([a]), e, "subprocess shell=True")
            else:
                frame.report_val("cmdi", "any", Val([a]), e, "subprocess program")
        if name == "Popen":
            return frame.alloc(e, LibObj("subprocess.Popen", (("stdout", Val([S.opaque()])), ("stderr", Val([S.opaque()])))))
        if name == "check_output":
            return Val([S.opaque(), S.opaque(raw=True)])
        if name in ("call", "check_call"):
            return Val([Num()])
        return frame.alloc(e, LibObj("subprocess.CompletedProcess", (("stdout", Val([S.opaque()])), ("stderr", Val([S.opaque()])), ("returncode", Val([Num()])))))

    def check_argv(self, frame, lst, e):
        if lst.elems is None or lst.summ is not None:
            vals = lst.all_values()
            consts = [c for c in (vals.consts() or []) if isinstance(c, str)]
            shells = any(posixpath.basename(c.replace("\\", "/")).lower() in SHELLS for c in consts)
            if shells or consts == []:
                frame.report_val("cmdi", "shell" if shells else "any", vals, e, "subprocess argv")
            return
        elems = list(lst.elems)
        if not elems:
            return
        frame.report_val("cmdi", "any", elems[0], e, "subprocess program")
        prog = elems[0].consts() or []
        is_shell = any(isinstance(p, str) and posixpath.basename(p.replace("\\", "/")).lower() in SHELLS for p in prog)
        if is_shell:
            for i, el in enumerate(elems[1:], start=1):
                flag = el.single_const()
                if isinstance(flag, str) and flag.lower() in ("-c", "/c", "/k", "-command", "-encodedcommand"):
                    for rest in elems[i + 1:]:
                        frame.report_val("cmdi", "shell", rest, e, "shell -c")
                    break
        elif self.argument_injection:
            for el in elems[1:]:
                frame.report_val("cmdi", "any", el, e, "argument")

    def h_exec(self, frame, args, kwargs, e):
        if args:
            frame.report_val("cmdi", "any", args[0], e, "exec program")
        if len(args) > 1:
            for a in args[1].alts:
                if isinstance(a, Ref) and isinstance(frame.get(a.aid), ListObj):
                    self.check_argv(frame, frame.get(a.aid), e)
        return NONE

    def path_text(self, frame, v, e, seen=None):
        out = []
        seen = set() if seen is None else seen
        for a in v.alts:
            if isinstance(a, Str):
                out.append(a if not a.raw else Str(a.parts, False))
            elif isinstance(a, Ref):
                if a.aid in seen:
                    out.append(S.opaque())
                    continue
                seen.add(a.aid)
                obj = frame.get(a.aid)
                if isinstance(obj, LibObj) and obj.get("path") is not None:
                    out.extend(self.path_text(frame, obj.get("path"), e, seen).alts)
                else:
                    out.extend(x for x in self.str_val(frame, Val([a]), e, seen).alts if isinstance(x, Str))
            else:
                s = S.as_str(a)
                out.append(s if s is not None else S.opaque())
        return Val(out) if out else Val([S.opaque()])

    def join_paths(self, frame, parts, e):
        cur = None
        for v in parts:
            v = self.path_text(frame, v, e)
            if cur is None:
                cur = v
                continue
            new = []
            for base in cur.alts:
                for p in v.alts:
                    if isinstance(p, Str) and p.is_const():
                        t = p.text()
                        if t.startswith("/"):
                            new.append(p)
                        elif base.is_const() and base.text() in ("", "."):
                            new.append(p)
                        else:
                            sep = "" if (base.is_const() and base.text().endswith("/")) else "/"
                            new.append(S.concat(base, Str.make([sep + t])))
                        continue
                    first = p.parts[0] if p.parts else ""
                    if isinstance(first, str) and not first.startswith("/"):
                        new.append(S.concat(base, S.concat(Str.make(["/"]), p)))
                        continue
                    if isinstance(first, Hole) and first.facts and first.props.excludes("/") and first.props.excludes("\\"):
                        new.append(S.concat(base, S.concat(Str.make(["/"]), p)))
                        continue
                    new.append(S.concat(base, S.concat(Str.make(["/"]), p)))
                    new.append(p)
            cur = frame.collapse(Val(new))
        return cur if cur is not None else Val([S.opaque()])

    def h_path_join(self, frame, args, kwargs, e):
        return frame.bound(self.join_paths(frame, list(args), e))

    def h_normpath(self, frame, args, kwargs, e):
        v = self.path_text(frame, arg(args, kwargs, 0, "path", UNKNOWN), e)
        return self.normalize(frame, v, e)

    def normalize(self, frame, v, e):
        out = []
        site = frame.site(e)
        for a in v.alts:
            if a.is_const():
                out.append(Str.make([posixpath.normpath(a.text())]))
                continue
            holes = [h for h in a.holes() if h.facts]
            if not holes:
                out.append(S.opaque())
                continue
            h = S.derive(merge_holes(holes), site)
            out.append(Str((h.with_props(Props(h.props.allowed, frozenset(x for x in h.props.excl if len(x) == 1), h.props.kinds, h.props.flags | {"norm"})),)))
        return Val(out)

    def h_dirname(self, frame, args, kwargs, e):
        v = self.path_text(frame, arg(args, kwargs, 0, "p", UNKNOWN), e)
        out = []
        for a in v.alts:
            if a.is_const():
                out.append(Str.make([posixpath.dirname(a.text())]))
            else:
                out.append(S.transform_holes(a, frame.site(e)))
        return Val(out)

    def new_path(self, frame, path, e):
        return frame.alloc(e, LibObj("pathlib.Path", (("path", path),)))

    def h_path(self, frame, args, kwargs, e):
        if not args:
            return self.new_path(frame, const("."), e)
        joined = self.join_paths(frame, list(args), e)
        out = []
        for a in joined.alts:
            if isinstance(a, Str) and a.is_const():
                t = a.text()
                out.append(Str.make([str(pathlib.PurePosixPath(t)) if t else "."]))
            else:
                out.append(a)
        return self.new_path(frame, Val(out), e)

    def m_path_sink(self, frame, aid, obj, args, kwargs, e):
        name = self.called()
        frame.report_val("path-traversal", "path", obj.get("path", UNKNOWN), e, "Path." + name)
        if name in ("rename", "replace", "symlink_to") and args:
            frame.report_val("path-traversal", "path", self.path_text(frame, args[0], e), e, "Path." + name)
        if name in ("read_text",):
            return Val([S.opaque()])
        if name == "read_bytes":
            return Val([S.opaque(raw=True)])
        if name == "open":
            return frame.alloc(e, LibObj("io.file", (("path", obj.get("path", UNKNOWN)),)))
        if name in ("exists", "is_file", "is_dir", "samefile"):
            return BOOL
        if name in ("iterdir", "glob", "rglob"):
            return frame.alloc(e, ListObj("list", None, Val([Ref(aid)])))
        return NONE

    def m_path_derive(self, frame, aid, obj, args, kwargs, e):
        name = self.called()
        path = obj.get("path", UNKNOWN)
        if name == "resolve":
            return self.new_path(frame, self.normalize(frame, path, e), e)
        if name == "joinpath":
            return self.new_path(frame, self.join_paths(frame, [path] + list(args), e), e)
        if name in ("as_posix", "__str__", "__fspath__"):
            return path
        if name == "relative_to" and args and not any(a.tainted() for a in args) and isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute):
            frame.st = frame.contained(e.func.value, Val([Ref(aid)]), frame.st)
        if name in ("absolute", "expanduser", "with_name", "with_suffix", "with_stem", "relative_to"):
            out = []
            for a in path.alts:
                out.append(a if a.is_const() and name == "absolute" else S.transform_holes(a, frame.site(e)))
            return self.new_path(frame, Val(out), e)
        return UNKNOWN

    def a_path_name(self, frame, aid, obj, e):
        path = obj.get("path", UNKNOWN)
        out = []
        for a in path.alts:
            if a.is_const():
                out.append(Str.make([posixpath.basename(a.text())]))
            else:
                out.append(S.transform_holes(a, frame.site(e), lambda p: p.restrict(excl=["/"], kinds=["path-traversal"])))
        return Val(out)

    def a_path_parent(self, frame, aid, obj, e):
        path = obj.get("path", UNKNOWN)
        return self.new_path(frame, Val([S.transform_holes(a, frame.site(e)) for a in path.alts]), e)

    def h_open(self, frame, args, kwargs, e):
        p = arg(args, kwargs, 0, "file", UNKNOWN)
        name = "open"
        if isinstance(e.func, ast.Attribute):
            name = e.func.attr if not isinstance(e.func.value, ast.Name) else e.func.value.id + "." + e.func.attr
        frame.report_val("path-traversal", "path", self.path_text(frame, p, e), e, name)
        return frame.alloc(e, LibObj("io.file", (("path", p),)))

    def h_stringio(self, frame, args, kwargs, e):
        init = arg(args, kwargs, 0, "initial_value", const(""))
        return frame.alloc(e, LibObj("io.StringIO", (("buf", init),)))

    def m_sio_write(self, frame, aid, obj, args, kwargs, e):
        buf = obj.get("buf", const(""))
        v = args[0] if args else UNKNOWN
        new = frame.binop(ast.Add(), buf, frame.to_str(v, e), e)
        frame.put(aid, LibObj(obj.type, items_tuple({**obj.as_dict(), "buf": new})))
        return Val([Num()])

    def m_sio_get(self, frame, aid, obj, args, kwargs, e):
        return obj.get("buf", const(""))

    def h_config(self, frame, args, kwargs, e):
        return frame.alloc(e, LibObj("configparser.ConfigParser", ()))

    def m_cfg_set(self, frame, aid, obj, args, kwargs, e):
        if len(args) < 3:
            return NONE
        sec, key = args[0].single_const(), args[1].single_const()
        d = obj.as_dict()
        if isinstance(sec, str) and isinstance(key, str):
            k = "opt:" + sec + "\x00" + key.lower()
            d[k] = args[2]
        else:
            d["opt:*"] = args[2].join(d.get("opt:*", EMPTY))
        frame.put(aid, LibObj(obj.type, items_tuple(d)))
        return NONE

    def m_cfg_get(self, frame, aid, obj, args, kwargs, e):
        sec = args[0].single_const() if args else NOTHING
        key = args[1].single_const() if len(args) > 1 else NOTHING
        fallback = kwargs.get("fallback")
        d = obj.as_dict()
        out = EMPTY
        if isinstance(sec, str) and isinstance(key, str):
            k = "opt:" + sec + "\x00" + key.lower()
            if k in d:
                out = d[k]
            else:
                for kk, v in d.items():
                    if kk.startswith("opt:") and kk.endswith("\x00" + key.lower()) and sec == "DEFAULT":
                        out = out.join(v)
                if "loaded" in d:
                    out = out.join(Val([S.opaque()]))
                if fallback is not None:
                    out = out.join(fallback)
        else:
            for kk, v in d.items():
                if kk.startswith("opt:"):
                    out = out.join(v)
            out = out.join(Val([S.opaque()]))
            if fallback is not None:
                out = out.join(fallback)
        return out if not out.is_empty() else Val([S.opaque()])

    def m_cfg_num(self, frame, aid, obj, args, kwargs, e):
        v = self.m_cfg_get(frame, aid, obj, args, kwargs, e)
        return self.to_number(frame, [v], e, int)

    def m_cfg_read(self, frame, aid, obj, args, kwargs, e):
        d = obj.as_dict()
        d["loaded"] = TRUE
        if args:
            frame.report_val("path-traversal", "path", self.path_text(frame, args[0], e), e, "ConfigParser.read")
        frame.put(aid, LibObj(obj.type, items_tuple(d)))
        return UNKNOWN

    def m_cfg_read_string(self, frame, aid, obj, args, kwargs, e):
        d = obj.as_dict()
        d["loaded"] = TRUE
        if args and args[0].tainted():
            d["opt:*"] = args[0]
        frame.put(aid, LibObj(obj.type, items_tuple(d)))
        return NONE

    def coded(self, frame, v, e, allowed, raw):
        site = frame.site(e)
        out = []
        for a in v.alts:
            s = a if isinstance(a, Str) else frame.str_alt(a)
            if s is None:
                s = S.opaque(True)
            if s.is_const() and allowed is not None:
                try:
                    data = s.python()
                    if isinstance(data, str):
                        data = data.encode("utf-8")
                    enc = base64.urlsafe_b64encode(data) if allowed == B64URL else base64.b64encode(data)
                    out.append(Str.make([enc.decode("ascii")], raw=True))
                    continue
                except Exception:
                    pass
            if s.is_const():
                out.append(S.opaque(raw))
                continue
            props = None
            holes = [h for h in s.holes() if h.facts]
            if not holes:
                out.append(S.opaque(raw))
                continue
            h = S.derive(merge_holes(holes), site)
            if allowed is not None:
                props = Props(frozenset(allowed), frozenset(), frozenset(), frozenset())
            else:
                props = Props()
            out.append(Str((h.with_props(props),), raw))
        return frame.bound(Val(out))

    def h_b64encode(self, frame, args, kwargs, e):
        return self.coded(frame, arg(args, kwargs, 0, "s", UNKNOWN), e, B64, True)

    def h_b64encode_url(self, frame, args, kwargs, e):
        return self.coded(frame, arg(args, kwargs, 0, "s", UNKNOWN), e, B64URL, True)

    def h_decode_reset(self, frame, args, kwargs, e):
        v = arg(args, kwargs, 0, "s", UNKNOWN)
        name = self.called()
        raw = name in ("b64decode", "standard_b64decode", "urlsafe_b64decode", "decodebytes", "b32decode", "b16decode", "b85decode", "unhexlify", "fromhex", "unquote_to_bytes")
        if name in ("loads",):
            holes = [h for h in v.holes() if h.facts]
            return Val([Unk(S.derive(merge_holes(holes), frame.site(e)))]) if holes else UNKNOWN
        out = []
        site = frame.site(e)
        fn = None
        if name in ("unquote", "unquote_plus", "unescape"):
            fn = {"unquote": urllib.parse.unquote, "unquote_plus": urllib.parse.unquote_plus, "unescape": html.unescape}[name]
        for a in v.alts:
            s = a if isinstance(a, Str) else frame.str_alt(a)
            if s is None:
                out.append(S.opaque(raw))
                continue
            if s.is_const():
                if fn is not None:
                    out.append(Str.make([fn(s.text())]))
                else:
                    try:
                        if name.endswith("b64decode") or name == "decodebytes":
                            dec = base64.urlsafe_b64decode(s.text()) if "urlsafe" in name else base64.b64decode(s.text())
                            out.append(Str.make([dec.decode("latin-1")], raw=True))
                        else:
                            out.append(S.opaque(raw))
                    except Exception:
                        pass
                continue
            out.append(S.summarize(Str(s.parts, raw), site, Props()))
        return frame.bound(Val(out)) if out else EMPTY

    def h_html_escape(self, frame, args, kwargs, e):
        v = arg(args, kwargs, 0, "s", UNKNOWN)
        quote = arg(args, kwargs, 1, "quote", TRUE).truth()
        excl = HTML_EXCL if quote is not False else ("<", ">")
        site = frame.site(e)
        out = []
        for a in v.alts:
            s = a if isinstance(a, Str) else frame.str_alt(a)
            if s is None:
                s = S.opaque()
            if s.is_const():
                out.append(Str.make([html.escape(s.text(), quote is not False)]))
            else:
                out.append(S.transform_holes(s, site, lambda p: p.restrict(excl=excl)))
        return frame.bound(Val(out))

    def h_urlparse(self, frame, args, kwargs, e):
        v = arg(args, kwargs, 0, "url", UNKNOWN)
        s = self.path_text(frame, v, e)
        fields = {}
        p = None
        if len(s.alts) == 1 and next(iter(s.alts)).is_const():
            try:
                p = urllib.parse.urlparse(next(iter(s.alts)).text())
                host = p.hostname
            except ValueError:
                p = None
        if p is not None:
            for name in ("scheme", "netloc", "path", "params", "query", "fragment"):
                fields[name] = const(getattr(p, name))
            fields["hostname"] = const(host)
        else:
            site = frame.site(e)
            holes = [h for h in s.holes() if h.facts]
            for name in ("scheme", "netloc", "path", "params", "query", "fragment", "hostname", "username", "password"):
                if holes:
                    fields[name] = Val([Str((S.derive(merge_holes(holes), site + (name,)),))])
                else:
                    fields[name] = Val([S.opaque()])
        fields["src"] = v
        fields["port"] = Val([Num()])
        return frame.alloc(e, LibObj("urllib.parse.ParseResult", items_tuple(fields)))

    def h_urljoin(self, frame, args, kwargs, e):
        base = arg(args, kwargs, 0, "base", UNKNOWN)
        url = arg(args, kwargs, 1, "url", UNKNOWN)
        if not url.tainted():
            return frame.taint_union([base], e)
        return Val([S.summarize(Str((merge_holes([h for h in url.holes() if h.facts]),)), frame.site(e))])

    def h_yaml(self, frame, args, kwargs, e):
        loader = arg(args, kwargs, 1, "Loader", None)
        unsafe = True
        if loader is not None:
            names = [a.name for a in loader.alts if isinstance(a, Lib)]
            if names and all(n.endswith(("SafeLoader", "CSafeLoader", "BaseLoader", "FullLoader")) for n in names):
                unsafe = False
        v = arg(args, kwargs, 0, "stream", UNKNOWN)
        if unsafe:
            frame.report_val("deserialization", "any", v, e, "yaml.load")
        return frame.taint_union([v], e)

    def h_minidom(self, frame, args, kwargs, e):
        data = arg(args, kwargs, 0, "string", None) or arg(args, kwargs, 0, "file", UNKNOWN)
        parser = arg(args, kwargs, 1, "parser", None)
        if parser is not None and self.parser_unsafe(frame, parser):
            frame.report_val("xxe", "any", data, e, "minidom with external entities")
        return frame.alloc(e, LibObj("xml.dom.minidom.Document", ()))

    def parser_unsafe(self, frame, parser):
        for a in parser.alts:
            if isinstance(a, Ref):
                obj = frame.get(a.aid)
                if isinstance(obj, LibObj):
                    ext = obj.get("external")
                    if ext is not None and ext.truth() is not False:
                        return True
        return False

    def h_sax_parser(self, frame, args, kwargs, e):
        return frame.alloc(e, LibObj("xml.sax.XMLReader", (("external", FALSE),)))

    def m_sax_feature(self, frame, aid, obj, args, kwargs, e):
        if len(args) < 2:
            return NONE
        name = args[0].single_const()
        if name in ("http://xml.org/sax/features/external-general-entities", "http://xml.org/sax/features/external-parameter-entities"):
            d = obj.as_dict()
            d["external"] = args[1]
            frame.put(aid, LibObj(obj.type, items_tuple(d)))
        return NONE

    def m_sax_parse(self, frame, aid, obj, args, kwargs, e):
        if self.parser_unsafe(frame, Val([Ref(aid)])) and args:
            frame.report_val("xxe", "any", args[0], e, "sax parser with external entities")
        return NONE

    def h_lxml_parser(self, frame, args, kwargs, e):
        resolve = kwargs.get("resolve_entities")
        unsafe = resolve is not None and resolve.truth() is True and resolve.single_const() is True
        no_network = kwargs.get("no_network")
        if no_network is not None and no_network.truth() is False and resolve is not None and resolve.single_const() is not False:
            unsafe = True
        return frame.alloc(e, LibObj("lxml.etree.XMLParser", (("external", TRUE if unsafe else FALSE),)))

    def h_lxml_parse(self, frame, args, kwargs, e):
        data = arg(args, kwargs, 0, "text", None) or arg(args, kwargs, 0, "source", UNKNOWN)
        parser = arg(args, kwargs, 1, "parser", None)
        if parser is not None and self.parser_unsafe(frame, parser):
            frame.report_val("xxe", "any", data, e, "lxml parser with entity resolution")
        name = self.called()
        t = "lxml.etree._ElementTree" if name == "parse" else "lxml.etree._Element"
        return frame.alloc(e, LibObj(t, ()))

    def h_hash_new(self, frame, args, kwargs, e):
        name = arg(args, kwargs, 0, "name", UNKNOWN)
        names = [c.lower() for c in (name.consts() or []) if isinstance(c, str)]
        safe = kwargs.get("usedforsecurity")
        if any(n in WEAK_HASHES for n in names) and (safe is None or safe.truth() is not False):
            frame.an.add_plain("weak-hash", frame.loc(e), f"hashlib.new('{names[0]}')")
        return frame.alloc(e, LibObj("hashlib.hash", ()))

    def h_hash_weak(self, frame, args, kwargs, e):
        safe = kwargs.get("usedforsecurity")
        if safe is None or safe.truth() is not False:
            label = func_name(e)
            frame.an.add_plain("weak-hash", frame.loc(e), label)
        return frame.alloc(e, LibObj("hashlib.hash", ()))

    def h_re_compile(self, frame, args, kwargs, e):
        return frame.alloc(e, LibObj("re.Pattern", (("pattern", arg(args, kwargs, 0, "pattern", UNKNOWN)),)))

    def match_obj(self, frame, pattern, subject, mode, e):
        p = pattern.single_const() if pattern is not None else NOTHING
        allowed = self.regex_alphabet(p, mode) if isinstance(p, str) else None
        holes = [h for h in subject.holes() if h.facts]
        if holes:
            h = S.derive(merge_holes(holes), frame.site(e))
            if allowed is not None:
                h = h.with_props(h.props.restrict(allowed=allowed))
            group = Val([Str((h,))])
        else:
            group = Val([S.opaque()])
        return frame.alloc(e, LibObj("re.Match", (("group", group),))).join(NONE)

    def h_re_match(self, frame, args, kwargs, e):
        return self.match_obj(frame, arg(args, kwargs, 0, "pattern"), arg(args, kwargs, 1, "string", UNKNOWN), self.called(), e)

    def m_pattern_match(self, frame, aid, obj, args, kwargs, e):
        return self.match_obj(frame, obj.get("pattern"), arg(args, kwargs, 0, "string", UNKNOWN), self.called(), e)

    def m_match_group(self, frame, aid, obj, args, kwargs, e):
        g = obj.get("group", UNKNOWN)
        name = self.called() if self.qn.startswith("re.Match.") else "group"
        if name == "groups":
            return Val([Unk(merge_holes([h for h in g.holes() if h.facts]))]) if g.tainted() else UNKNOWN
        if name == "groupdict":
            return frame.alloc(e, DictObj((), g))
        return g

    def sub(self, frame, pattern, repl, subject, e):
        p = pattern.single_const() if pattern is not None else NOTHING
        r = repl.single_const() if repl is not None else NOTHING
        site = frame.site(e)
        cls = self.char_class(p) if isinstance(p, str) else None
        props_fn = None
        if cls is not None and isinstance(r, str):
            neg, chars = cls
            added = frozenset(c for c in r if not c.isalnum())
            if neg:
                keep = frozenset(c for c in chars if not c.isalnum()) | added

                def props_fn(pr):
                    allowed = keep if pr.allowed is None else (pr.allowed & keep) | added
                    return Props(allowed, frozenset(), pr.kinds, frozenset())
            else:
                gone = [c for c in chars if not c.isalnum() and c not in r]

                def props_fn(pr):
                    return pr.restrict(excl=gone)
        out = []
        for a in subject.alts:
            s = a if isinstance(a, Str) else frame.str_alt(a)
            if s is None:
                out.append(S.opaque())
                continue
            if s.is_const() and isinstance(p, str) and isinstance(r, str):
                try:
                    out.append(Str.make([re.sub(p, r, s.text())]))
                    continue
                except re.error:
                    pass
            if props_fn is not None:
                out.append(S.transform_holes(s, site, props_fn))
            else:
                out.append(S.summarize(s, site, Props()))
        return frame.bound(Val(out))

    def h_re_sub(self, frame, args, kwargs, e):
        return self.sub(frame, arg(args, kwargs, 0, "pattern"), arg(args, kwargs, 1, "repl"), arg(args, kwargs, 2, "string", UNKNOWN), e)

    def m_pattern_sub(self, frame, aid, obj, args, kwargs, e):
        return self.sub(frame, obj.get("pattern"), arg(args, kwargs, 0, "repl"), arg(args, kwargs, 1, "string", UNKNOWN), e)

    def char_class(self, pattern):
        try:
            parsed = sre_parse.parse(pattern)
        except Exception:
            return None
        if len(parsed) != 1:
            return None
        op, av = parsed[0]
        if op is sre_c.MAX_REPEAT or op is sre_c.MIN_REPEAT:
            lo, hi, sub = av
            if len(sub) != 1:
                return None
            op, av = sub[0]
        if op is sre_c.LITERAL:
            return (False, chr(av))
        if op is not sre_c.IN:
            return None
        neg = False
        chars = set()
        for kind, val in av:
            if kind is sre_c.NEGATE:
                neg = True
            elif kind is sre_c.LITERAL:
                chars.add(chr(val))
            elif kind is sre_c.RANGE:
                lo, hi = val
                if hi - lo > 300:
                    return None
                chars.update(chr(c) for c in range(lo, hi + 1))
            elif kind is sre_c.CATEGORY:
                if val is sre_c.CATEGORY_DIGIT:
                    chars.update("0123456789")
                elif val is sre_c.CATEGORY_WORD:
                    chars.update("_")
                elif val is sre_c.CATEGORY_SPACE:
                    chars.update(" \t\n\r\x0b\x0c")
                else:
                    return None
            else:
                return None
        return (neg, "".join(sorted(chars)))

    def regex_alphabet(self, pattern, mode):
        try:
            parsed = sre_parse.parse(pattern)
        except Exception:
            return None
        items = list(parsed)
        newline = False
        if mode != "fullmatch":
            if mode == "search":
                if not items or items[0] != (sre_c.AT, sre_c.AT_BEGINNING) and items[0] != (sre_c.AT, sre_c.AT_BEGINNING_STRING):
                    return None
            if not items:
                return None
            last = items[-1]
            if last == (sre_c.AT, sre_c.AT_END):
                newline = True
            elif last != (sre_c.AT, sre_c.AT_END_STRING):
                return None
        chars = self.alphabet(items)
        if chars is None:
            return None
        allowed = {c for c in chars if not c.isalnum()}
        if newline:
            allowed.add("\n")
        return frozenset(allowed)

    def alphabet(self, items):
        out = set()
        for op, av in items:
            if op is sre_c.AT:
                continue
            if op is sre_c.LITERAL:
                out.add(chr(av))
            elif op is sre_c.IN:
                r = self.char_class_items(av)
                if r is None:
                    return None
                out |= r
            elif op in (sre_c.MAX_REPEAT, sre_c.MIN_REPEAT, sre_c.POSSESSIVE_REPEAT):
                r = self.alphabet(av[2])
                if r is None:
                    return None
                out |= r
            elif op is sre_c.SUBPATTERN:
                r = self.alphabet(av[-1])
                if r is None:
                    return None
                out |= r
            elif op is sre_c.BRANCH:
                for b in av[1]:
                    r = self.alphabet(b)
                    if r is None:
                        return None
                    out |= r
            elif op is sre_c.ATOMIC_GROUP:
                r = self.alphabet(av)
                if r is None:
                    return None
                out |= r
            else:
                return None
        return out

    def char_class_items(self, av):
        out = set()
        for kind, val in av:
            if kind is sre_c.NEGATE:
                return None
            if kind is sre_c.LITERAL:
                out.add(chr(val))
            elif kind is sre_c.RANGE:
                lo, hi = val
                if hi - lo > 300:
                    out.update(chr(c) for c in range(lo, min(hi, lo + 300) + 1) if not chr(c).isalnum())
                    if hi > 0x7F:
                        return None
                else:
                    out.update(chr(c) for c in range(lo, hi + 1))
            elif kind is sre_c.CATEGORY:
                if val is sre_c.CATEGORY_DIGIT:
                    out.update("0123456789")
                elif val is sre_c.CATEGORY_WORD:
                    out.update("_")
                elif val is sre_c.CATEGORY_SPACE:
                    out.update(" \t\n\r\x0b\x0c")
                else:
                    return None
            else:
                return None
        return out

    def h_make_response(self, frame, args, kwargs, e):
        body = EMPTY
        html_flag = TRUE
        if len(args) == 1:
            for a in args[0].alts:
                if isinstance(a, Tup) and a.items:
                    body = body.join(a.items[0])
                    for extra in a.items[1:]:
                        if self.plain_content_type(frame, extra):
                            html_flag = FALSE
                elif isinstance(a, Ref) and isinstance(frame.get(a.aid), LibObj) and frame.get(a.aid).type == "flask.Response":
                    return Val([a])
                else:
                    body = body.join(Val([a]))
        elif args:
            body = args[0]
            for extra in args[1:]:
                if self.plain_content_type(frame, extra):
                    html_flag = FALSE
        return frame.alloc(e, LibObj("flask.Response", (("body", body if not body.is_empty() else const("")), ("html", html_flag))))

    def plain_content_type(self, frame, v):
        for a in v.alts:
            if isinstance(a, Ref):
                obj = frame.get(a.aid)
                if isinstance(obj, DictObj):
                    for k, val in obj.items:
                        if isinstance(k, str) and k.lower() == "content-type":
                            c = val.single_const()
                            if isinstance(c, str) and "html" not in c.lower():
                                return True
        return False

    def h_response(self, frame, args, kwargs, e):
        body = arg(args, kwargs, 0, "response", const(""))
        mt = kwargs.get("mimetype") or kwargs.get("content_type")
        html_flag = TRUE
        if mt is not None:
            c = mt.single_const()
            if isinstance(c, str) and "html" not in c.lower():
                html_flag = FALSE
        return frame.alloc(e, LibObj("flask.Response", (("body", body), ("html", html_flag))))

    def h_redirect(self, frame, args, kwargs, e):
        frame.report_val("open-redirect", "redirect", arg(args, kwargs, 0, "location", UNKNOWN), e, "redirect")
        return frame.alloc(e, LibObj("flask.Response", (("body", const("")), ("html", FALSE))))

    def h_render(self, frame, args, kwargs, e):
        if self.called() == "render_template_string":
            frame.report_val("ssti", "template", arg(args, kwargs, 0, "source", UNKNOWN), e, "render_template_string")
        return Val([S.opaque()])

    def h_json_dumps(self, frame, args, kwargs, e):
        v = arg(args, kwargs, 0, "obj", UNKNOWN)
        holes = [h for h in v.holes() if h.facts]
        for r in _refs(v):
            obj = frame.get(r)
            if obj is not None:
                for x in obj_values(obj):
                    holes.extend(h for h in x.holes() if h.facts)
        if holes:
            return Val([Str((S.derive(merge_holes(holes), frame.site(e)),))])
        return Val([S.opaque()])

    def h_markup(self, frame, args, kwargs, e):
        v = arg(args, kwargs, 0, "base", const(""))
        frame.report_val("xss", "html", v, e, "Markup")
        return frame.to_str(v, e)

    def h_django_response(self, frame, args, kwargs, e):
        body = arg(args, kwargs, 0, "content", const(""))
        ct = kwargs.get("content_type")
        c = ct.single_const() if ct is not None else NOTHING
        if not (isinstance(c, str) and "html" not in c.lower()):
            frame.report_val("xss", "html", body, e, "HttpResponse")
        return frame.alloc(e, LibObj("django.HttpResponse", ()))

    def h_media_response(self, frame, args, kwargs, e):
        body = arg(args, kwargs, 0, "content", const(""))
        mt = kwargs.get("media_type")
        c = mt.single_const() if mt is not None else NOTHING
        if isinstance(c, str) and "html" in c.lower():
            frame.report_val("xss", "html", body, e, "Response")
        return frame.alloc(e, LibObj("starlette.Response", ()))

    def h_format_html(self, frame, args, kwargs, e):
        fmt = args[0] if args else const("")
        rest = [self.h_html_escape(frame, [a], {}, e) for a in args[1:]]
        out = EMPTY
        for a in fmt.alts:
            if isinstance(a, Str):
                out = out.join(self.str_format(frame, a, rest, kwargs, e))
        return out if not out.is_empty() else Val([S.opaque()])

    def h_shlex_split(self, frame, args, kwargs, e):
        v = arg(args, kwargs, 0, "s", UNKNOWN)
        holes = [h for h in v.holes() if h.facts]
        el = Val([Str((S.derive(merge_holes(holes), frame.site(e)),))]) if holes else Val([S.opaque()])
        return frame.alloc(e, ListObj("list", None, el))

    def m_set_cookie(self, frame, aid, obj, args, kwargs, e):
        secure = kwargs.get("secure")
        if secure is None and len(args) > 6:
            secure = args[6]
        if secure is None or secure.truth() is False:
            key = arg(args, kwargs, 0, "key", UNKNOWN).single_const()
            frame.an.add_plain("insecure-cookie", frame.loc(e), f"cookie {key!r}" if isinstance(key, str) else "cookie")
        value = arg(args, kwargs, 1, "value", None)
        if value is not None:
            self.weak_check(frame, ["cookie"], value, e)
        return NONE


def _refs(v):
    out = []
    for a in v.alts:
        if isinstance(a, Ref):
            out.append(a.aid)
    return out


def _hashable(k):
    try:
        hash(k)
        return True
    except TypeError:
        return False


def is_django_form(name):
    return name.startswith("django.forms.") and name.rpartition(".")[2].endswith("Form")


def func_name(e):
    try:
        return ast.unparse(e.func)
    except (AttributeError, ValueError, TypeError):
        return "hash"
