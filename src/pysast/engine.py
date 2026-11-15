from __future__ import annotations

import ast
import heapq
import operator
from collections import Counter

from . import strings as S
from .cfg import build
from .rules import MODES, RULES, unsafe_parts
from .values import (
    BOOL,
    EMPTY,
    FALSE,
    NONE,
    NOTHING,
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
    Source,
    Step,
    Str,
    Tup,
    Unk,
    Val,
    const,
    items_tuple,
    join_obj,
    map_obj,
    merge_holes,
    obj_values,
    remap_obj,
)

BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.BitOr: operator.or_,
    ast.BitAnd: operator.and_,
    ast.BitXor: operator.xor,
}

CMPOPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
}

GUARD_METHODS = {
    "isalnum": frozenset(),
    "isdigit": frozenset(),
    "isdecimal": frozenset(),
    "isnumeric": frozenset(),
    "isalpha": frozenset(),
    "isidentifier": frozenset("_"),
}

PURE_CALLS = {"str", "repr", "len", "urlparse", "urlsplit", "basename", "normpath", "realpath", "abspath"}


class FuncInfo:
    def __init__(self, fid, module, node, qualname, parent, kind):
        self.fid = fid
        self.module = module
        self.node = node
        self.qualname = qualname
        self.parent = parent
        self.kind = kind
        self.locals = set()
        self.free = set()
        self.is_gen = False
        self.view = None
        self.framework = None
        self.tainted = {}
        self.reads_path = False
        self.cfg = None
        self.cid = None


class ClassInfo:
    def __init__(self, cid, module, node, qualname):
        self.cid = cid
        self.module = module
        self.node = node
        self.qualname = qualname
        self.bases = []
        self.attrs = {}
        self.fields = []
        self.record = False


class State:
    __slots__ = ("vars", "heap")

    def __init__(self, vars=None, heap=None):
        self.vars = {} if vars is None else vars
        self.heap = {} if heap is None else heap

    def copy(self):
        return State(dict(self.vars), dict(self.heap))

    def __eq__(self, other):
        return self.vars == other.vars and self.heap == other.heap


def join_states(a, b):
    if a is None or a is b:
        return b
    if b is None:
        return a
    vars = dict(a.vars)
    for k, v in b.vars.items():
        old = vars.get(k)
        if old is None:
            vars[k] = v
        elif old is not v:
            vars[k] = old.join(v)
    heap = dict(a.heap)
    for k, o in b.heap.items():
        old = heap.get(k)
        if old is not o:
            heap[k] = join_obj(old, o)
    return State(vars, heap)


def scope_names(node):
    assigned, globals_, nonlocals, loads = set(), set(), set(), set()
    args = node.args
    for a in args.posonlyargs + args.args + args.kwonlyargs:
        assigned.add(a.arg)
    if args.vararg:
        assigned.add(args.vararg.arg)
    if args.kwarg:
        assigned.add(args.kwarg.arg)
    stack = list(node.body) if isinstance(node.body, list) else [node.body]
    gen = False
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            assigned.add(n.name)
            stack.extend(n.decorator_list)
            if isinstance(n, ast.ClassDef):
                stack.extend(n.bases)
            else:
                stack.extend(d for d in n.args.defaults + n.args.kw_defaults if d is not None)
            stack.extend(_free_loads(n))
            continue
        if isinstance(n, ast.Lambda):
            stack.extend(d for d in n.args.defaults + n.args.kw_defaults if d is not None)
            stack.extend(_free_loads(n))
            continue
        if isinstance(n, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            for sub in ast.walk(n):
                if isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name):
                    assigned.add(sub.target.id)
                if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                    loads.add(sub.id)
            continue
        if isinstance(n, (ast.Yield, ast.YieldFrom)):
            gen = True
        if isinstance(n, ast.Global):
            globals_.update(n.names)
        elif isinstance(n, ast.Nonlocal):
            nonlocals.update(n.names)
        elif isinstance(n, ast.Name):
            if isinstance(n.ctx, (ast.Store, ast.Del)):
                assigned.add(n.id)
            else:
                loads.add(n.id)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            assigned.add(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for alias in n.names:
                if alias.name != "*":
                    assigned.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            assigned.add(n.name)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            assigned.add(n.rest)
        stack.extend(ast.iter_child_nodes(n))
    return assigned - globals_ - nonlocals, globals_, loads, gen


def _free_loads(fn):
    out = []
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
            out.append(sub)
    return out


CONVERTERS = {
    "int": Props(allowed=frozenset("-")),
    "float": Props(allowed=frozenset("-.")),
    "uuid": Props(allowed=frozenset("-")),
    "string": Props(excl=frozenset("/")),
    "path": Props(),
    "default": Props(excl=frozenset("/")),
}


PARAM_PROPS = {
    "int": Props(allowed=frozenset("-")),
    "float": Props(allowed=frozenset("-+.")),
    "bool": Props(allowed=frozenset()),
    "uuid": Props(allowed=frozenset("-")),
    "date": Props(allowed=frozenset("-")),
    "datetime": Props(allowed=frozenset("-+.: ")),
}
PARAM_TYPES = {"str": "str", "Any": "str", "EmailStr": "str", "AnyUrl": "str", "HttpUrl": "str", "SecretStr": "str", "int": "int", "float": "float", "Decimal": "float", "bool": "bool", "UUID": "uuid", "UUID4": "uuid", "date": "date", "datetime": "datetime"}


def param_kind(a):
    if a is None:
        return "str"
    if isinstance(a, ast.Constant) and isinstance(a.value, str):
        try:
            return param_kind(ast.parse(a.value, mode="eval").body)
        except SyntaxError:
            return "obj"
    options = None
    if isinstance(a, ast.BinOp) and isinstance(a.op, ast.BitOr):
        options = [a.left, a.right]
    elif isinstance(a, ast.Subscript):
        base = ast.unparse(a.value).rpartition(".")[2]
        elts = list(a.slice.elts) if isinstance(a.slice, ast.Tuple) else [a.slice]
        if base == "Annotated":
            return param_kind(elts[0])
        if base in ("Optional", "Union"):
            options = elts
        else:
            return "obj"
    if options is not None:
        kinds = {param_kind(x) for x in options if not (isinstance(x, ast.Constant) and x.value is None)}
        return kinds.pop() if len(kinds) == 1 else "obj"
    return PARAM_TYPES.get(ast.unparse(a).rpartition(".")[2], "obj")


RECORD_DECORATORS = {"dataclass", "define", "frozen", "mutable"}
RECORD_BASES = {"pydantic.BaseModel", "pydantic.main.BaseModel", "typing.NamedTuple", "msgspec.Struct", "sqlmodel.SQLModel"}


def rule_text(e):
    if isinstance(e, ast.Constant) and isinstance(e.value, str):
        return e.value
    if isinstance(e, ast.JoinedStr):
        parts = []
        for v in e.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                parts.append("\x00")
        return "".join(parts)
    if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
        a, b = rule_text(e.left), rule_text(e.right)
        if a is not None and b is not None:
            return a + b
    if isinstance(e, ast.Name):
        return "\x00"
    return None


def route_rule(dec):
    if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
        return None
    if dec.func.attr not in ("route", "get", "post", "put", "delete", "patch", "api_route", "websocket"):
        return None
    if dec.args:
        text = rule_text(dec.args[0])
        if text is not None:
            return text
    for k in dec.keywords:
        if k.arg in ("rule", "path"):
            text = rule_text(k.value)
            if text is not None:
                return text
    return None


def rule_params(rule):
    out = []
    i = 0
    while True:
        a = rule.find("<", i)
        if a < 0:
            break
        b = rule.find(">", a)
        if b < 0:
            break
        inner = rule[a + 1:b]
        conv, _, name = inner.rpartition(":")
        conv = conv.split("(")[0] or "default"
        out.append((name, conv))
        i = b + 1
    return out


class Pending:
    __slots__ = ("rule", "loc", "hole", "label", "check")

    def __init__(self, rule, loc, hole, label, check=None):
        self.rule = rule
        self.loc = loc
        self.hole = hole
        self.label = label
        self.check = check


class Summary:
    __slots__ = ("ret", "heap", "pending")

    def __init__(self, ret, heap, pending):
        self.ret = ret
        self.heap = heap
        self.pending = pending


class Canon:
    def __init__(self, frame, abstract=False):
        self.frame = frame
        self.abstract = abstract
        self.universal = False
        self.actuals = []
        self.map = {}
        self.inv = []
        self.amap = {}
        self.ainv = []
        self.heap = {}

    def hole(self, h):
        if not h.facts:
            return h
        p = self.map.get(h)
        if p is None:
            i = len(self.inv)
            self.inv.append(h)
            p = Hole(("p", i), frozenset([Source("param", "", index=i)]), h.props, ())
            self.map[h] = p
        return p

    def ref(self, aid):
        c = self.amap.get(aid)
        if c is not None:
            return c
        heap = self.frame.st.heap
        if aid not in heap:
            return aid
        order = []
        queue = [aid]
        while queue:
            cur = queue.pop(0)
            if cur in self.amap or cur not in heap:
                continue
            self.amap[cur] = ("c", len(self.ainv))
            self.ainv.append(cur)
            order.append(cur)
            for v in obj_values(heap[cur]):
                queue.extend(collect_refs(v))
        look = self.lookup
        for cur in order:
            obj = remap_obj(heap[cur], self.hole, look)
            if self.abstract:
                obj = map_vals(obj, abstract_val)
            self.heap[self.amap[cur]] = obj
        return self.amap[aid]

    def lookup(self, aid):
        return self.amap.get(aid, aid)

    def val(self, v):
        v = v.remap(self.hole, self.ref)
        return abstract_val(v) if self.abstract else v

    def key_heap(self):
        return tuple(sorted(((k, v) for k, v in self.heap.items()), key=lambda kv: repr(kv[0])))

    def instantiate(self, summary, caller, node, name):
        step = Step(caller.module.rel, getattr(node, "lineno", 0), getattr(node, "col_offset", 0) + 1, f"call {name}")
        limit = caller.an.max_trace
        inv = self.inv
        ainv = self.ainv
        cache = {}

        def ref(aid):
            if isinstance(aid, tuple) and len(aid) == 2 and aid[0] == "c" and aid[1] < len(ainv):
                return ainv[aid[1]]
            return aid

        def inst(h):
            if not h.facts:
                return h
            got = cache.get(h)
            if got is not None:
                return got
            params = [f for f in h.facts if f.kind == "param"]
            if not params:
                cache[h] = h
                return h
            facts = {f for f in h.facts if f.kind != "param"}
            first = None
            for f in sorted(params, key=lambda x: x.index):
                if f.index >= len(inv):
                    continue
                act = inv[f.index]
                facts |= act.facts
                if first is None:
                    first = act
            hid = h.hid
            if isinstance(hid, tuple) and len(hid) == 2 and hid[0] == "p" and hid[1] < len(inv):
                hid = inv[hid[1]].hid
            elif isinstance(hid, tuple) and len(hid) == 3 and hid[0] == "d" and isinstance(hid[2], tuple) and len(hid[2]) == 2 and hid[2][0] == "p" and hid[2][1] < len(inv):
                hid = ("d", hid[1], S.root_hid(inv[hid[2][1]].hid))
            trace = (first.trace if first is not None else ()) + (step,) + h.trace
            if len(trace) > limit:
                trace = trace[:1] + trace[len(trace) - limit + 1:]
            props = h.props.meet(first.props) if self.universal and first is not None else h.props
            out = Hole(hid, frozenset(facts), props, trace)
            cache[h] = out
            return out

        for aid, obj in summary.heap.items():
            real = ref(aid)
            new = remap_obj(obj, inst, ref)
            if real is aid:
                old = caller.get(real)
                if old is not None and old != new:
                    new = join_obj(old, new)
            caller.st.heap[real] = new
        for p in summary.pending:
            h = inst(p.hole)
            if self.universal and p.check is not None:
                mode, before, after = p.check
                hid = p.hole.hid
                if isinstance(hid, tuple) and len(hid) == 2 and hid[0] == "p" and hid[1] < len(self.actuals):
                    self.splice(caller, p, self.actuals[hid[1]], step, limit)
                    continue
                if MODES[mode](h.props, before, after):
                    continue
            caller.report(p.rule, p.loc, h, p.label, p.check)
        return summary.ret.remap(inst, ref)

    def splice(self, caller, p, actual, step, limit):
        mode, before, after = p.check
        fact = RULES[p.rule].fact
        for alt in actual.alts:
            s = caller.str_alt(alt)
            if s is None:
                continue
            for part, b, a in unsafe_parts(mode, Str.make([before, *s.parts, after]), fact):
                trace = part.trace + (step,) + p.hole.trace
                if len(trace) > limit:
                    trace = trace[:1] + trace[len(trace) - limit + 1:]
                caller.report(p.rule, p.loc, Hole(part.hid, part.facts, part.props.meet(p.hole.props), trace), p.label, (mode, b, a))


def _drop_params(h):
    if not h.facts or not any(f.kind == "param" for f in h.facts):
        return h
    return Hole(h.hid, frozenset(f for f in h.facts if f.kind != "param"), h.props, h.trace)


def globalize(v):
    out = []
    for a in v.alts:
        if isinstance(a, Ref) and isinstance(a.aid, tuple) and len(a.aid) == 2 and a.aid[0] == "c":
            out.append(Unk())
        else:
            out.append(a)
    return Val(out).map_holes(_drop_params)


def abstract_val(v):
    out = []
    changed = False
    for a in v.alts:
        if isinstance(a, Str) and a.is_const():
            out.append(S.opaque(a.raw))
            changed = True
        elif isinstance(a, Const) and isinstance(a.value, (int, float, complex)) and not isinstance(a.value, bool):
            out.append(Num())
            changed = True
        elif isinstance(a, Tup):
            out.append(Tup(tuple(abstract_val(x) for x in a.items)))
            changed = True
        else:
            out.append(a)
    return Val(out) if changed else v


def map_vals(obj, fn):
    if isinstance(obj, ListObj):
        return ListObj(obj.kind, None if obj.elems is None else tuple(fn(v) for v in obj.elems), None if obj.summ is None else fn(obj.summ))
    if isinstance(obj, DictObj):
        return DictObj(tuple((k, fn(v)) for k, v in obj.items), None if obj.rest is None else fn(obj.rest), obj.kind)
    if isinstance(obj, InstObj):
        return InstObj(obj.cid, tuple((k, fn(v)) for k, v in obj.attrs))
    if isinstance(obj, LibObj):
        return LibObj(obj.type, tuple((k, fn(v)) for k, v in obj.attrs))
    return obj


def collect_refs(v, out=None):
    if out is None:
        out = []
    for a in v.alts:
        if isinstance(a, Ref):
            out.append(a.aid)
        elif isinstance(a, Tup):
            for x in a.items:
                collect_refs(x, out)
        elif isinstance(a, Fn) and a.recv is not None:
            collect_refs(a.recv, out)
        elif isinstance(a, Meth) and isinstance(a.recv, Val):
            collect_refs(a.recv, out)
    return out


class Analyzer:
    def __init__(self, project, config, library):
        self.project = project
        a = config["analysis"]
        self.max_depth = a["max_call_depth"]
        self.max_contexts = a["max_contexts"]
        self.max_alts = a["max_alternatives"]
        self.max_parts = a["max_string_parts"]
        self.max_items = a["max_list_items"]
        self.max_chars = a["max_chars"]
        self.widen_after = a["widen_after"]
        self.budget = a["function_budget"]
        self.max_trace = config["report"]["max_trace_steps"]
        self.config = config
        self.lib = library
        self.funcs = {}
        self.func_by_node = {}
        self.classes = {}
        self.envs = {}
        self.loading = set()
        self.static_heap = {}
        self.memo = {}
        self.contexts = Counter()
        self.stack = []
        self.stack_keys = set()
        self.findings = {}
        self.closures = {}
        self.truncated = set()
        self.internal = []
        for mod in project.modules.values():
            self.register(mod)

    def register(self, mod):
        def visit(node, parent, cls_node, prefix):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    kind = "function"
                    if cls_node is not None:
                        kind = "method"
                        for d in child.decorator_list:
                            if isinstance(d, ast.Name) and d.id in ("staticmethod", "classmethod"):
                                kind = d.id
                    info = self.make_func(mod, child, parent, prefix + child.name, kind)
                    if cls_node is not None:
                        info.cid = (mod.name, cls_node.lineno, cls_node.col_offset)
                    visit(child, info, None, info.qualname + ".")
                elif isinstance(child, ast.Lambda):
                    info = self.make_func(mod, child, parent, prefix + "<lambda>", "lambda")
                    visit(child, info, None, prefix)
                elif isinstance(child, ast.ClassDef):
                    visit(child, parent, child, prefix + child.name + ".")
                else:
                    visit(child, parent, cls_node if isinstance(node, ast.ClassDef) or cls_node is None else cls_node, prefix)

        visit(mod.tree, None, None, "")

    def make_func(self, mod, node, parent, qualname, kind):
        fid = (mod.name, node.lineno, node.col_offset)
        info = FuncInfo(fid, mod, node, qualname, parent, kind)
        info.locals, _, loads, info.is_gen = scope_names(node)
        enclosing = set()
        p = parent
        while p is not None:
            enclosing |= p.locals
            p = p.parent
        info.free = {n for n in loads if n not in info.locals and n in enclosing}
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute) and sub.attr in ("path", "full_path", "url", "base_url"):
                info.reads_path = True
                break
        if kind != "lambda":
            for d in node.decorator_list:
                rule = route_rule(d)
                if rule is not None:
                    info.view = rule
                    info.framework = "fastapi" if "fastapi" in mod.imports else "flask"
            self.mark_tainted(info, mod)
        self.funcs[fid] = info
        self.func_by_node[id(node)] = fid
        return info

    def mark_tainted(self, info, mod):
        args = info.node.args
        names = [a.arg for a in args.posonlyargs + args.args + args.kwonlyargs]
        if info.framework == "flask" and info.view:
            for p, conv in rule_params(info.view):
                if p in names and conv != "any":
                    info.tainted[p] = ("input", f"route parameter {p}", CONVERTERS.get(conv, Props()))
        elif info.framework == "fastapi":
            pos = args.posonlyargs + args.args
            defaults = dict(zip([a.arg for a in pos][len(pos) - len(args.defaults):], args.defaults, strict=False))
            defaults.update({a.arg: d for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=False) if d is not None})
            for a in pos + args.kwonlyargs:
                n = a.arg
                d = defaults.get(n)
                dname = ast.unparse(d.func).rpartition(".")[2] if isinstance(d, ast.Call) else ""
                text = ast.unparse(a.annotation) if a.annotation is not None else ""
                last = text.rpartition(".")[2]
                if last in ("Request", "WebSocket", "HTTPConnection"):
                    info.tainted[n] = ("request", "starlette")
                elif dname in ("Depends", "Security") or "Depends(" in text or last in ("BackgroundTasks", "Response", "Session", "AsyncSession") or n in ("self", "cls", "db", "session"):
                    continue
                else:
                    kind = param_kind(a.annotation)
                    info.tainted[n] = ("input", f"request parameter {n}", PARAM_PROPS.get(kind, Props()), kind)
        for a in args.posonlyargs + args.args + args.kwonlyargs:
            if a.annotation is None or a.arg in info.tainted:
                continue
            last = ast.unparse(a.annotation).rpartition(".")[2]
            if last == "Request" and ("starlette" in mod.imports or "fastapi" in mod.imports):
                info.tainted[a.arg] = ("request", "starlette")
            elif last in ("HttpRequest", "WSGIRequest", "ASGIRequest") and "django" in mod.imports:
                info.tainted[a.arg] = ("request", "django")
        if "django" in mod.imports and names and names[0] == "request" and info.kind == "function":
            info.framework = info.framework or "django"
            info.tainted["request"] = ("request", "django")
        if info.kind == "method" and len(names) > 1 and names[1] == "request" and "django" in mod.imports:
            info.tainted["request"] = ("request", "django")

    def cfg_of(self, info):
        if info.cfg is None:
            body = info.node.body
            if isinstance(info.node, ast.Lambda):
                ret = ast.Return(value=body)
                ast.copy_location(ret, body)
                body = [ret]
            info.cfg = build(body)
        return info.cfg

    def module_env(self, name):
        env = self.envs.get(name)
        if env is not None:
            return env
        mod = self.project.modules.get(name)
        if mod is None:
            return {}
        if name in self.loading:
            return {}
        self.loading.add(name)
        self.envs[name] = {}
        frame = Frame(self, None, mod, build(mod.tree.body))
        frame.run(State())
        exit_state = frame.exit_state
        if exit_state is not None:
            self.envs[name] = exit_state.vars
            self.static_heap.update(exit_state.heap)
        self.loading.discard(name)
        return self.envs[name]

    def module_attr(self, name, attr):
        full = f"{name}.{attr}"
        if full in self.project.prefixes:
            return Val([Mod(full)])
        if name in self.project.modules:
            env = self.module_env(name)
            v = env.get(attr)
            if v is not None:
                return v
        return UNKNOWN

    def run(self):
        for name in sorted(self.project.modules):
            try:
                self.module_env(name)
            except RecursionError:
                self.internal.append((name, "recursion limit"))
            except Exception as exc:
                self.internal.append((name, f"{type(exc).__name__}: {exc}"))
                self.envs.setdefault(name, {})
                self.loading.discard(name)
        done = set()
        while True:
            todo = [fid for fid in self.funcs if fid not in done]
            if not todo:
                break
            for fid in sorted(todo, key=repr):
                done.add(fid)
                info = self.funcs[fid]
                if info.kind == "lambda":
                    continue
                try:
                    self.root(info)
                except RecursionError:
                    self.internal.append((info.qualname, "recursion limit"))
                except Exception as exc:
                    self.internal.append((info.qualname, f"{type(exc).__name__}: {exc}"))
                finally:
                    self.stack.clear()
                    self.stack_keys.clear()
        return self.findings

    def root(self, info):
        frame = Frame(self, info, info.module, self.cfg_of(info))
        st = State()
        args = info.node.args
        params = [a.arg for a in args.posonlyargs + args.args + args.kwonlyargs]
        for i, p in enumerate(params):
            spec = info.tainted.get(p)
            if spec is not None:
                if spec[0] == "request":
                    st.vars[p] = Val([Lib("$request." + spec[1])])
                else:
                    props = spec[2] if len(spec) > 2 else Props()
                    kind = spec[3] if len(spec) > 3 else "str"
                    h = Hole(("s", info.fid, p), frozenset([Source("input", spec[1], info.module.rel, info.node.lineno, info.node.col_offset + 1)]), props, (Step(info.module.rel, info.node.lineno, info.node.col_offset + 1, spec[1]),))
                    st.vars[p] = Val([Unk(h)]) if kind == "obj" else Val([Num(h)]) if kind in ("int", "float") else Val([Str((h,))])
            elif i == 0 and info.kind == "method":
                aid = ("self", info.fid)
                cid = self.class_of(info)
                st.heap[aid] = InstObj(cid, ())
                st.vars[p] = Val([Ref(aid)])
            elif i == 0 and info.kind == "classmethod":
                cid = self.class_of(info)
                st.vars[p] = Val([Cls(cid)]) if cid else UNKNOWN
            else:
                st.vars[p] = UNKNOWN
        if args.vararg:
            st.vars[args.vararg.arg] = UNKNOWN
        if args.kwarg:
            st.vars[args.kwarg.arg] = UNKNOWN
        frame.run(st)

    def class_of(self, info):
        return info.cid

    def call_function(self, caller, info, args, kwargs, node):
        binding = caller.bind(info, args, kwargs, node)
        if binding is None:
            return UNKNOWN
        canon = Canon(caller)
        cvars = {k: canon.val(v) for k, v in binding.items()}
        extra = caller.view_rule() if info.reads_path else None
        key = (info.fid, items_tuple(cvars), canon.key_heap(), extra)
        summary = self.memo.get(key)
        if summary is None:
            if key in self.stack_keys:
                return self.conservative(binding)
            if len(self.stack) >= self.max_depth or self.contexts[info.fid] >= self.max_contexts:
                summary, canon = self.generic(caller, info, binding, extra)
                if summary is None:
                    summary, canon = self.universal(caller, info, binding)
                if summary is None:
                    return self.conservative(binding)
            else:
                self.contexts[info.fid] += 1
                summary = self.analyze(info, key, cvars, {k: v for k, v in canon.heap.items() if v is not None}, extra)
        return canon.instantiate(summary, caller, node, info.qualname)

    def analyze(self, info, key, cvars, heap, extra):
        self.stack.append(key)
        self.stack_keys.add(key)
        frame = Frame(self, info, info.module, self.cfg_of(info), parent_view=extra)
        entry = State(dict(cvars), dict(heap))
        try:
            frame.run(entry)
        finally:
            self.stack.pop()
            self.stack_keys.discard(key)
        ret = frame.returns
        if info.is_gen:
            aid = ("gen", info.fid)
            out_heap = dict(frame.exit_state.heap) if frame.exit_state is not None else {}
            out_heap[aid] = ListObj("list", None, frame.yields)
            ret = Val([Ref(aid)])
        else:
            out_heap = frame.exit_state.heap if frame.exit_state is not None else entry.heap
        summary = Summary(ret, self.prune(ret, out_heap, heap), frame.pending)
        self.memo[key] = summary
        return summary

    def prune(self, ret, out_heap, entry_heap):
        keep = {}
        stack = collect_refs(ret)
        for aid, obj in out_heap.items():
            if isinstance(aid, tuple) and len(aid) == 2 and aid[0] == "c":
                if entry_heap.get(aid) != obj:
                    keep[aid] = obj
                stack.extend(r for v in obj_values(obj) for r in collect_refs(v))
            elif aid in self.static_heap and self.static_heap[aid] != obj:
                keep[aid] = obj
        seen = set(keep)
        while stack:
            aid = stack.pop()
            if aid in seen:
                continue
            seen.add(aid)
            obj = out_heap.get(aid)
            if obj is None:
                continue
            if not (isinstance(aid, tuple) and len(aid) == 2 and aid[0] == "c"):
                keep[aid] = obj
            for v in obj_values(obj):
                stack.extend(collect_refs(v))
        return keep

    def generic(self, caller, info, binding, extra):
        canon = Canon(caller, abstract=True)
        cvars = {k: canon.val(v) for k, v in binding.items()}
        key = ("generic", info.fid, items_tuple(cvars), canon.key_heap(), extra)
        summary = self.memo.get(key)
        if summary is None:
            if key in self.stack_keys or len(self.stack) >= self.max_depth + 4 or self.contexts[("generic", info.fid)] >= self.max_contexts:
                return None, None
            self.contexts[("generic", info.fid)] += 1
            summary = self.analyze(info, key, cvars, {k: v for k, v in canon.heap.items() if v is not None}, extra)
        return summary, canon

    def universal(self, caller, info, binding):
        key = ("universal", info.fid)
        summary = self.memo.get(key)
        if summary is None:
            if key in self.stack_keys or len(self.stack) >= self.max_depth + 12:
                return None, None
            cvars = {}
            heap = {}
            for i, name in enumerate(binding):
                if i == 0 and info.kind == "method":
                    aid = ("self", info.fid)
                    heap[aid] = InstObj(self.class_of(info), ())
                    cvars[name] = Val([Ref(aid)])
                elif i == 0 and info.kind == "classmethod" and self.class_of(info):
                    cvars[name] = Val([Cls(self.class_of(info))])
                else:
                    cvars[name] = Val([Unk(Hole(("p", i), frozenset([Source("param", "", index=i)]), Props(), ()))])
            summary = self.analyze(info, key, cvars, heap, None)
        canon = Canon(caller)
        canon.universal = True
        canon.actuals = list(binding.values())
        for i, v in enumerate(binding.values()):
            h = merge_holes([x for x in v.holes() if x.facts])
            canon.inv.append(h if h is not None else Hole(("u", i), frozenset(), Props(), ()))
        return summary, canon

    def conservative(self, binding):
        holes = []
        for v in binding.values():
            holes.extend(h for h in v.holes() if h.facts)
        h = merge_holes(holes)
        return Val([Unk(h)]) if h is not None else UNKNOWN

    def add_finding(self, rule, loc, source, trace, label):
        key = (rule, loc[0], loc[1], loc[2], source.label, source.file, source.line)
        old = self.findings.get(key)
        if old is None or len(trace) < len(old["trace"]):
            self.findings[key] = {"rule": rule, "loc": loc, "source": source, "trace": trace, "label": label}

    def add_plain(self, rule, loc, label):
        key = (rule, loc[0], loc[1], loc[2], "", "", 0)
        if key not in self.findings:
            self.findings[key] = {"rule": rule, "loc": loc, "source": None, "trace": (), "label": label}


class Frame:
    def __init__(self, an, info, module, cfg, parent_view=None):
        self.an = an
        self.info = info
        self.module = module
        self.cfg = cfg
        self.st = None
        self.node = None
        self.returns = EMPTY
        self.yields = EMPTY
        self.pending = []
        self.exit_state = None
        self.parent_view = parent_view
        self.lib = an.lib
        self.comp = set()

    def view_rule(self):
        if self.info is not None and self.info.view is not None and self.info.framework == "flask":
            return self.info.view
        return self.parent_view

    def loc(self, e):
        line = getattr(e, "lineno", 0)
        col = getattr(e, "col_offset", 0) + 1
        end_line = getattr(e, "end_lineno", line) or line
        end_col = (getattr(e, "end_col_offset", col - 1) or 0) + 1
        func = self.info.qualname if self.info is not None else "<module>"
        return (self.module.rel, line, col, end_line, end_col, func)

    def site(self, e):
        return (self.module.name, getattr(e, "lineno", 0), getattr(e, "col_offset", 0), getattr(e, "end_col_offset", 0))

    def step(self, e, note):
        return Step(self.module.rel, getattr(e, "lineno", 0), getattr(e, "col_offset", 0) + 1, note)

    def source(self, kind, label, e):
        loc = self.loc(e)
        src = Source(kind, label, loc[0], loc[1], loc[2])
        return Hole(("s",) + self.site(e), frozenset([src]), trace=(self.step(e, label),))

    def report(self, rule, loc, hole, label, check=None):
        want = RULES[rule].fact
        has_param = False
        for f in hole.facts:
            if f.kind == "param":
                has_param = True
            elif f.kind == want:
                self.an.add_finding(rule, loc, f, hole.trace, label)
        if has_param and self.info is not None:
            self.pending.append(Pending(rule, loc, hole, label, check))

    def report_val(self, rule, mode, v, e, label):
        loc = None
        for alt in v.alts:
            s = self.str_alt(alt)
            if s is None:
                continue
            for h, before, after in unsafe_parts(mode, s, RULES[rule].fact):
                if loc is None:
                    loc = self.loc(e)
                self.report(rule, loc, h.add_step(self.step(e, label), self.an.max_trace + 1), label, (mode, before, after))

    def str_alt(self, alt):
        if isinstance(alt, Ref):
            obj = self.get(alt.aid)
            if isinstance(obj, LibObj):
                if obj.type not in ("pathlib.Path", "urllib.parse.ParseResult", "io.StringIO"):
                    return None
                p = obj.get("path")
                if p is None:
                    p = obj.get("src")
                if p is None:
                    p = obj.get("buf")
                if p is not None:
                    holes = [h for h in p.holes() if h.facts]
                    strs = p.strs()
                    if len(strs) == 1 and len(p.alts) == 1:
                        return strs[0]
                    if holes:
                        return Str((merge_holes(holes),))
                return None
            if obj is not None:
                holes = []
                for v in obj_values(obj):
                    holes.extend(h for h in v.holes() if h.facts)
                if holes:
                    return Str((merge_holes(holes),))
            return None
        if isinstance(alt, Str):
            return alt
        return S.as_str(alt)

    def get(self, aid):
        obj = self.st.heap.get(aid)
        if obj is None:
            obj = self.an.static_heap.get(aid)
        return obj

    def put(self, aid, obj):
        self.st.heap[aid] = obj

    def alloc(self, e, obj, tag="a"):
        aid = (tag,) + self.site(e)
        old = self.get(aid)
        if old is not None and old != obj:
            obj = join_obj(old, obj)
            if isinstance(obj, ListObj) and obj.elems is not None and old != obj:
                obj = ListObj(obj.kind, None, obj.all_values())
        self.put(aid, obj)
        return Val([Ref(aid)])

    def run(self, entry):
        cfg = self.cfg
        inn = {cfg.entry.nid: entry}
        queue = [(cfg.entry.order, cfg.entry.nid)]
        queued = {cfg.entry.nid}
        visits = Counter()
        steps = 0
        while queue:
            _, nid = heapq.heappop(queue)
            queued.discard(nid)
            node = cfg.nodes[nid]
            st = inn[nid]
            steps += 1
            if steps > self.an.budget:
                self.an.truncated.add(self.info.qualname if self.info else self.module.rel)
                break
            for succ, out in self.transfer(node, st):
                if out is None:
                    continue
                prev = inn.get(succ.nid)
                new = out if prev is None else join_states(prev, out)
                visits[succ.nid] += 1
                if prev is not None and visits[succ.nid] > self.an.widen_after:
                    new = self.widen(prev, new)
                if prev is None or new != prev:
                    inn[succ.nid] = new
                    if succ.nid not in queued:
                        queued.add(succ.nid)
                        heapq.heappush(queue, (succ.order, succ.nid))
        self.exit_state = inn.get(cfg.exit.nid)

    def widen(self, prev, st):
        vars = dict(st.vars)
        for k, v in st.vars.items():
            if prev.vars.get(k) != v:
                vars[k] = self.collapse(v, force=True)
        heap = dict(st.heap)
        for k, o in st.heap.items():
            old = prev.heap.get(k)
            if old == o:
                continue
            if isinstance(o, ListObj) and o.elems is not None:
                o = ListObj(o.kind, None, self.collapse(o.all_values(), force=True))
            else:
                o = map_vals(o, lambda v: self.collapse(v, force=True))
            heap[k] = o
        return State(vars, heap)

    def collapse(self, v, force=False):
        limit = self.an.max_alts
        if not force and len(v.alts) <= limit:
            return v
        out, texts, strs, nums, unks = [], [], [], [], []
        for a in v.alts:
            if isinstance(a, (Ref, Fn, Cls, Mod, Lib, Meth)):
                out.append(a)
            elif isinstance(a, Str):
                (texts if a.is_const() else strs).append(a)
            elif isinstance(a, Const) and not (isinstance(a.value, (int, float, complex)) and not isinstance(a.value, bool)):
                out.append(a)
            elif isinstance(a, (Const, Num, LenOf)):
                nums.append(a)
            else:
                unks.append(a)
        if len(texts) > limit:
            strs.extend(texts)
        else:
            out.extend(texts)
        if strs:
            holes = [h for s in strs for h in s.holes() if h.facts]
            raw = all(s.raw for s in strs)
            if holes:
                out.append(Str((merge_holes(holes, hid=min((h.hid for h in holes), key=repr)),), raw))
            else:
                out.append(S.opaque(raw))
        if nums:
            if not force and len(nums) <= limit and all(isinstance(n, Const) for n in nums):
                out.extend(nums)
            else:
                holes = [n.hole for n in nums if isinstance(n, Num) and n.hole is not None and n.hole.facts]
                out.append(Num(merge_holes(holes)) if holes else Num())
        if unks:
            holes = []
            for u in unks:
                holes.extend(h for h in Val([u]).holes() if h.facts)
            out.append(Unk(merge_holes(holes)) if holes else Unk())
        return Val(out)

    def bound(self, v):
        if len(v.alts) > self.an.max_alts:
            return self.collapse(v)
        for a in v.alts:
            if isinstance(a, Str) and len(a.parts) > self.an.max_parts:
                return Val([S.summarize(a, ("cap",)) if isinstance(x, Str) and len(x.parts) > self.an.max_parts else x for x in v.alts])
        return v

    def transfer(self, node, st):
        kind = node.kind
        self.node = node
        out = []
        if kind in ("entry", "nop", "exit"):
            return [(s, st) for s, _ in node.succs]
        if kind == "test":
            t, f = self.branch(node.ast, st)
            for s, label in node.succs:
                if label is True:
                    out.append((s, t))
                elif label is False:
                    out.append((s, f))
                else:
                    out.append((s, st))
            return out
        if kind == "for_next":
            self.st = st.copy()
            it = self.st.vars.get(node.data, UNKNOWN)
            elems = self.iter_elems(it, node.ast.iter)
            body = None
            if not elems.is_empty():
                self.assign(node.ast.target, elems, node.ast)
                body = self.st
            for s, label in node.succs:
                if label is True:
                    out.append((s, body))
                else:
                    out.append((s, st))
            return out
        if kind == "case":
            t, f = self.case(node, st)
            for s, label in node.succs:
                if label is True:
                    out.append((s, t))
                elif label is False:
                    out.append((s, f))
                else:
                    out.append((s, st))
            return out
        self.st = st.copy()
        if self.info is None:
            self.an.envs[self.module.name] = self.st.vars
        self.exec_node(node)
        after = self.st
        for s, label in node.succs:
            out.append((s, st if label == "exc" else after))
        return out

    def exec_node(self, node):
        kind = node.kind
        s = node.ast
        if kind == "stmt":
            self.exec_stmt(s)
        elif kind == "return":
            v = self.ev(s.value) if s.value is not None else NONE
            if self.info is not None and self.info.view is not None:
                self.lib.view_return(self, v, s)
            self.returns = self.bound(self.returns.join(v))
        elif kind == "raise":
            if s.exc is not None:
                self.ev(s.exc)
        elif kind == "for_init":
            self.st.vars[node.data] = self.ev(s.iter)
        elif kind == "with":
            for item in s.items:
                v = self.ev(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, self.enter(v, item.context_expr), item.context_expr)
        elif kind == "handler":
            if s.type is not None:
                self.ev(s.type)
            if s.name:
                self.st.vars[s.name] = UNKNOWN
        elif kind == "match_subject":
            self.st.vars[node.data] = self.ev(s.subject)

    def enter(self, v, e):
        out = EMPTY
        for a in v.alts:
            if isinstance(a, Ref):
                obj = self.get(a.aid)
                if isinstance(obj, InstObj):
                    r = self.call_method(Val([a]), "__enter__", [], {}, e, quiet=True)
                    out = out.join(r if not r.is_empty() else Val([a]))
                    continue
            out = out.join(Val([a]))
        return out

    def exec_stmt(self, s):
        t = type(s)
        if t is ast.Assign:
            v = self.ev(s.value)
            for target in s.targets:
                self.assign(target, v, s)
        elif t is ast.AugAssign:
            cur = self.ev(self.as_load(s.target))
            rhs = self.ev(s.value)
            lists = [a for a in cur.alts if isinstance(a, Ref) and isinstance(self.get(a.aid), ListObj)]
            if isinstance(s.op, ast.Add) and lists:
                for a in lists:
                    self.lib.list_method(self, a.aid, self.get(a.aid), "extend", [rhs], {}, s)
                rest = Val([a for a in cur.alts if a not in lists])
                if rest.is_empty():
                    return
                self.assign(s.target, Val(lists).join(self.binop(s.op, rest, rhs, s)), s)
                return
            self.assign(s.target, self.binop(s.op, cur, rhs, s), s)
        elif t is ast.AnnAssign:
            if s.value is not None:
                self.assign(s.target, self.ev(s.value), s)
        elif t is ast.Expr:
            self.ev(s.value)
        elif t is ast.Import:
            for alias in s.names:
                if alias.asname:
                    self.st.vars[alias.asname] = self.import_value(alias.name)
                else:
                    top = alias.name.split(".")[0]
                    self.st.vars[top] = self.import_value(top)
        elif t is ast.ImportFrom:
            self.exec_import_from(s)
        elif t in (ast.FunctionDef, ast.AsyncFunctionDef):
            fid = self.an.func_by_node.get(id(s))
            if fid is not None:
                info = self.an.funcs[fid]
                self.capture(info)
                self.st.vars[s.name] = Val([Fn(fid)])
        elif t is ast.ClassDef:
            self.exec_class(s)
        elif t is ast.Delete:
            for target in s.targets:
                self.delete(target)

    def import_value(self, name):
        resolved = self.an.project.resolve(name, self.module)
        if resolved is not None:
            return Val([Mod(resolved)])
        return Val([Lib(name)])

    def exec_import_from(self, s):
        if s.level:
            base = self.an.project.relative(self.module, s.level, s.module)
        else:
            base = s.module or ""
        resolved = base if s.level else self.an.project.resolve(base, self.module)
        for alias in s.names:
            if alias.name == "*":
                if resolved in self.an.project.modules:
                    for k, v in self.an.module_env(resolved).items():
                        if not k.startswith("_"):
                            self.st.vars[k] = v
                continue
            target = alias.asname or alias.name
            if resolved is not None:
                self.st.vars[target] = self.an.module_attr(resolved, alias.name)
            else:
                self.st.vars[target] = self.lib.lib_value(self, f"{base}.{alias.name}", s)

    def exec_class(self, s):
        cid = (self.module.name, s.lineno, s.col_offset)
        ci = self.an.classes.get(cid)
        if ci is None:
            prefix = (self.info.qualname + ".") if self.info is not None else ""
            ci = ClassInfo(cid, self.module, s, prefix + s.name)
            self.an.classes[cid] = ci
        ci.bases = [self.ev(b) for b in s.bases]
        ci.fields = [st.target.id for st in s.body if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and "ClassVar" not in ast.unparse(st.annotation)]
        names = [ast.unparse(d.func if isinstance(d, ast.Call) else d) for d in s.decorator_list]
        ci.record = any(n.rpartition(".")[2] in RECORD_DECORATORS or n in ("attr.s", "attr.attrs") for n in names)
        ci.record = ci.record or any(isinstance(alt, Lib) and alt.name in RECORD_BASES for b in ci.bases for alt in b.alts)
        for stmt in s.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fid = self.an.func_by_node.get(id(stmt))
                if fid is not None:
                    ci.attrs[stmt.name] = Val([Fn(fid)])
            elif isinstance(stmt, ast.Assign):
                v = self.ev(stmt.value)
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        ci.attrs[target.id] = v
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None and isinstance(stmt.target, ast.Name):
                ci.attrs[stmt.target.id] = self.ev(stmt.value)
        self.st.vars[s.name] = Val([Cls(cid)])

    def as_load(self, target):
        if isinstance(target, ast.Name):
            return ast.copy_location(ast.Name(id=target.id, ctx=ast.Load()), target)
        if isinstance(target, ast.Attribute):
            return ast.copy_location(ast.Attribute(value=target.value, attr=target.attr, ctx=ast.Load()), target)
        if isinstance(target, ast.Subscript):
            return ast.copy_location(ast.Subscript(value=target.value, slice=target.slice, ctx=ast.Load()), target)
        return target

    def delete(self, target):
        if isinstance(target, ast.Name):
            self.st.vars.pop(target.id, None)
        elif isinstance(target, ast.Subscript):
            container = self.ev(target.value)
            key = self.ev(target.slice)
            k = key.single_const()
            for a in container.alts:
                if isinstance(a, Ref):
                    obj = self.get(a.aid)
                    if isinstance(obj, DictObj) and k is not NOTHING and len(container.alts) == 1:
                        d = obj.as_dict()
                        d.pop(k, None)
                        self.put(a.aid, DictObj(items_tuple(d), obj.rest, obj.kind))

    def assign(self, target, v, stmt):
        t = type(target)
        if t is ast.Name:
            if v.tainted():
                v = v.map_holes(lambda h: h.add_step(self.step(target, target.id), self.an.max_trace) if h.facts else h)
            self.st.vars[target.id] = self.bound(v)
            self.lib.weak_store(self, target.id, None, v, stmt)
        elif t in (ast.Tuple, ast.List):
            self.unpack(target.elts, v, stmt)
        elif t is ast.Attribute:
            obj = self.ev(target.value)
            self.store_attr(obj, target.attr, v, target)
            self.lib.weak_store(self, target.attr, None, v, stmt)
        elif t is ast.Subscript:
            container = self.ev(target.value)
            if isinstance(target.slice, ast.Slice):
                self.store_slice(container, v, target)
                return
            key = self.ev(target.slice)
            self.store_item(container, key, v, target)
            name = ast.unparse(target.value)
            self.lib.weak_store(self, name, key, v, stmt)
        elif t is ast.Starred:
            self.assign(target.value, self.make_list(self.iter_elems(v, target), target), stmt)

    def unpack(self, elts, v, stmt):
        n = len(elts)
        star = [i for i, e in enumerate(elts) if isinstance(e, ast.Starred)]
        rows = []
        whole = EMPTY
        for a in v.alts:
            items = self.exact_items(a)
            if items is not None and (len(items) == n or (star and len(items) >= n - 1)):
                rows.append(items)
            else:
                whole = whole.join(self.iter_elems(Val([a]), stmt))
        values = [EMPTY] * n
        for items in rows:
            if star:
                si = star[0]
                before = items[:si]
                after = items[len(items) - (n - si - 1):] if n - si - 1 else []
                middle = items[si:len(items) - (n - si - 1)] if n - si - 1 else items[si:]
                for i, x in enumerate(before):
                    values[i] = values[i].join(x)
                for j, x in enumerate(after):
                    values[si + 1 + j] = values[si + 1 + j].join(x)
                values[si] = values[si].join(self.make_list(None, stmt, middle))
            else:
                for i, x in enumerate(items):
                    values[i] = values[i].join(x)
        if not whole.is_empty():
            for i in range(n):
                values[i] = values[i].join(self.make_list(whole, stmt) if i in star else whole)
        for e, val in zip(elts, values, strict=False):
            target = e.value if isinstance(e, ast.Starred) else e
            self.assign(target, val if not val.is_empty() else UNKNOWN, stmt)

    def exact_items(self, a):
        if isinstance(a, Tup):
            return list(a.items)
        if isinstance(a, Ref):
            obj = self.get(a.aid)
            if isinstance(obj, ListObj) and obj.elems is not None and obj.summ is None:
                return list(obj.elems)
        if isinstance(a, Str) and a.is_const() and len(a.text()) <= self.an.max_items:
            return [const(c) for c in a.text()]
        return None

    def make_list(self, summ, e, elems=None, kind="list"):
        if elems is not None:
            return self.alloc(e, ListObj(kind, tuple(elems), None))
        return self.alloc(e, ListObj(kind, None, summ))

    def store_attr(self, obj, name, v, e):
        single = len(obj.alts) == 1
        for a in obj.alts:
            if isinstance(a, Ref):
                o = self.get(a.aid)
                if isinstance(o, InstObj):
                    d = o.as_dict()
                    d[name] = v if single or name not in d else d[name].join(v)
                    self.put(a.aid, InstObj(o.cid, items_tuple(d)))
                elif isinstance(o, LibObj):
                    d = o.as_dict()
                    d[name] = v if single or name not in d else d[name].join(v)
                    self.put(a.aid, LibObj(o.type, items_tuple(d)))
            elif isinstance(a, Cls):
                ci = self.an.classes.get(a.cid)
                if ci is not None:
                    ci.attrs[name] = self.collapse(globalize(v).join(ci.attrs.get(name, EMPTY)))

    def store_item(self, container, key, v, e):
        single = len(container.alts) == 1
        k = key.single_const()
        for a in container.alts:
            if isinstance(a, Lib):
                self.lib.store_lib_item(self, a.name, key, v, e)
                continue
            if not isinstance(a, Ref):
                continue
            obj = self.get(a.aid)
            if isinstance(obj, DictObj):
                d = obj.as_dict()
                if k is not NOTHING and _hashable(k):
                    d[k] = v if single else (d[k].join(v) if k in d else v)
                    self.put(a.aid, DictObj(items_tuple(d), obj.rest, obj.kind))
                else:
                    self.put(a.aid, DictObj(obj.items, v if obj.rest is None else obj.rest.join(v), obj.kind))
            elif isinstance(obj, ListObj):
                if obj.elems is not None and isinstance(k, int) and -len(obj.elems) <= k < len(obj.elems) and single:
                    elems = list(obj.elems)
                    elems[k] = v
                    self.put(a.aid, ListObj(obj.kind, tuple(elems), obj.summ))
                else:
                    self.put(a.aid, ListObj(obj.kind, None, obj.all_values().join(v)))
            elif isinstance(obj, LibObj):
                self.lib.store_obj_item(self, a.aid, obj, key, v, e)
            elif isinstance(obj, InstObj):
                self.call_method(Val([a]), "__setitem__", [key, v], {}, e, quiet=True)

    def store_slice(self, container, v, e):
        for a in container.alts:
            if isinstance(a, Ref):
                obj = self.get(a.aid)
                if isinstance(obj, ListObj):
                    self.put(a.aid, ListObj(obj.kind, None, obj.all_values().join(self.iter_elems(v, e))))

    def iter_elems(self, v, e):
        out = EMPTY
        for a in v.alts:
            out = out.join(self.iter_alt(a, e))
        return self.bound(out)

    def iter_alt(self, a, e):
        if isinstance(a, Str):
            return Val(S.chars(a, self.site(e), self.an.max_chars))
        if isinstance(a, Tup):
            out = EMPTY
            for x in a.items:
                out = out.join(x)
            return out
        if isinstance(a, Ref):
            obj = self.get(a.aid)
            if isinstance(obj, ListObj):
                return obj.all_values()
            if isinstance(obj, DictObj):
                keys = Val([Const(k) if not isinstance(k, str) else Str.make([k]) for k, _ in obj.items])
                if obj.rest is not None:
                    keys = keys.join(Val([Unk(merge_holes([h for h in obj.rest.holes() if h.facts]))]) if obj.rest.tainted() else UNKNOWN)
                return keys
            if isinstance(obj, LibObj):
                return self.lib.iterate(self, a.aid, obj, e)
            if isinstance(obj, InstObj):
                r = self.call_method(Val([a]), "__iter__", [], {}, e, quiet=True)
                if not r.is_empty() and r != Val([a]):
                    return self.iter_elems(r, e)
                return UNKNOWN
            return UNKNOWN
        if isinstance(a, Unk):
            if a.hole is not None:
                return Val([Unk(S.derive(a.hole, self.site(e)))])
            return UNKNOWN
        if isinstance(a, Num):
            return Val([Num(a.hole)])
        return UNKNOWN

    def bind(self, info, args, kwargs, node):
        a = info.node.args
        names = [p.arg for p in a.posonlyargs + a.args]
        kwargs = dict(kwargs)
        star = kwargs.pop("**", None)
        binding = {}
        defaults = a.defaults
        first_default = len(names) - len(defaults)
        for i, n in enumerate(names):
            if i < len(args):
                binding[n] = args[i]
            elif n in kwargs:
                binding[n] = kwargs.pop(n)
            elif i >= first_default:
                binding[n] = self.default(defaults[i - first_default])
                if star is not None:
                    binding[n] = binding[n].join(star)
            else:
                binding[n] = UNKNOWN if star is None else star
        extra = args[len(names):]
        if a.vararg:
            binding[a.vararg.arg] = Val([Tup(tuple(extra))])
        for p, d in zip(a.kwonlyargs, a.kw_defaults, strict=False):
            if p.arg in kwargs:
                binding[p.arg] = kwargs.pop(p.arg)
            else:
                binding[p.arg] = self.default(d) if d is not None else UNKNOWN
                if star is not None:
                    binding[p.arg] = binding[p.arg].join(star) if d is not None else star
        if a.kwarg:
            binding[a.kwarg.arg] = self.alloc(node, DictObj(items_tuple(kwargs), star), tag="kw")
        return binding

    def default(self, d):
        try:
            return const(ast.literal_eval(d))
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return UNKNOWN

    def load_name(self, name, e):
        info = self.info
        if info is None:
            v = self.st.vars.get(name)
            if v is not None:
                return v
        elif name in info.locals or name in self.comp:
            v = self.st.vars.get(name)
            return v if v is not None else UNKNOWN
        else:
            if name in info.free:
                v = self.an.closures.get((info.fid, name))
                return v if v is not None else UNKNOWN
            env = self.an.envs.get(self.module.name)
            if env is None:
                env = self.an.module_env(self.module.name)
            v = env.get(name)
            if v is not None:
                return v
        return self.lib.builtin(name)

    def ev(self, e):
        m = getattr(self, "ev_" + type(e).__name__, None)
        if m is None:
            for c in ast.iter_child_nodes(e):
                if isinstance(c, ast.expr):
                    self.ev(c)
            return UNKNOWN
        return m(e)

    def ev_Constant(self, e):
        return const(e.value)

    def ev_Name(self, e):
        return self.load_name(e.id, e)

    def ev_NamedExpr(self, e):
        v = self.ev(e.value)
        self.assign(e.target, v, e)
        return v

    def ev_Await(self, e):
        return self.ev(e.value)

    def ev_Yield(self, e):
        if e.value is not None:
            self.yields = self.bound(self.yields.join(self.ev(e.value)))
        return UNKNOWN

    def ev_YieldFrom(self, e):
        self.yields = self.bound(self.yields.join(self.iter_elems(self.ev(e.value), e)))
        return UNKNOWN

    def ev_Starred(self, e):
        return self.ev(e.value)

    def ev_Lambda(self, e):
        fid = self.an.func_by_node.get(id(e))
        if fid is None:
            return UNKNOWN
        self.capture(self.an.funcs[fid])
        return Val([Fn(fid)])

    def capture(self, info):
        for name in info.free:
            v = self.st.vars.get(name)
            if v is None:
                continue
            out = []
            for a in v.alts:
                if isinstance(a, Ref) and self.st.heap.get(a.aid) is not None:
                    holes = [h for x in obj_values(self.st.heap[a.aid]) for h in x.holes() if h.facts]
                    out.append(Unk(merge_holes(holes)) if holes else Unk())
                elif isinstance(a, (Fn, Meth)) and collect_refs(Val([a])):
                    out.append(Unk())
                else:
                    out.append(a)
            key = (info.fid, name)
            self.an.closures[key] = self.collapse(globalize(Val(out)).join(self.an.closures.get(key, EMPTY)))

    def ev_Attribute(self, e):
        recv = self.ev(e.value)
        out = EMPTY
        for a in recv.alts:
            out = out.join(self.get_attr(a, e.attr, e))
        return self.bound(out) if not out.is_empty() else UNKNOWN

    def get_attr(self, a, name, e):
        if isinstance(a, Mod):
            return self.an.module_attr(a.name, name)
        if isinstance(a, Lib):
            return self.lib.attr(self, a.name, name, e)
        if isinstance(a, Ref):
            obj = self.get(a.aid)
            if isinstance(obj, InstObj):
                d = obj.as_dict()
                if name in d:
                    return d[name]
                v = self.class_attr(obj.cid, name)
                if v is None:
                    return self.lib.inherited_attr(self, self.lib_bases(obj.cid), name, e)
                return self.bind_method(v, Val([a]), obj.cid)
            if isinstance(obj, LibObj):
                return self.lib.obj_attr(self, a.aid, obj, name, e)
            if isinstance(obj, (ListObj, DictObj)):
                return Val([Meth(Val([a]), name)])
            return UNKNOWN
        if isinstance(a, (Str, Const, Tup)):
            return Val([Meth(Val([a]), name)])
        if isinstance(a, Unk):
            if a.hole is not None:
                return Val([Unk(S.derive(a.hole, self.site(e)))])
            return UNKNOWN
        if isinstance(a, Num):
            return Val([Num(a.hole)])
        if isinstance(a, Cls):
            v = self.class_attr(a.cid, name)
            if v is None:
                return UNKNOWN
            out = EMPTY
            for x in v.alts:
                if isinstance(x, Fn) and self.an.funcs[x.fid].kind == "classmethod":
                    out = out.join(Val([Fn(x.fid, Val([a]))]))
                else:
                    out = out.join(Val([x]))
            return out
        return UNKNOWN

    def bind_method(self, v, recv, cid):
        out = EMPTY
        for x in v.alts:
            if isinstance(x, Fn) and x.recv is None:
                kind = self.an.funcs[x.fid].kind
                if kind == "method":
                    out = out.join(Val([Fn(x.fid, recv)]))
                elif kind == "classmethod":
                    out = out.join(Val([Fn(x.fid, Val([Cls(cid)]))]))
                else:
                    out = out.join(Val([x]))
            else:
                out = out.join(Val([x]))
        return out

    def class_attr(self, cid, name, depth=0):
        ci = self.an.classes.get(cid)
        if ci is None or depth > 10:
            return None
        if name in ci.attrs:
            return ci.attrs[name]
        for b in ci.bases:
            for alt in b.alts:
                if isinstance(alt, Cls):
                    v = self.class_attr(alt.cid, name, depth + 1)
                    if v is not None:
                        return v
        return None

    def ev_Subscript(self, e):
        container = self.ev(e.value)
        if isinstance(e.slice, ast.Slice):
            lo = self.ev(e.slice.lower) if e.slice.lower is not None else NONE
            hi = self.ev(e.slice.upper) if e.slice.upper is not None else NONE
            st = self.ev(e.slice.step) if e.slice.step is not None else NONE
            out = EMPTY
            for a in container.alts:
                out = out.join(self.slice_alt(a, lo, hi, st, e))
            return self.bound(out) if not out.is_empty() else UNKNOWN
        key = self.ev(e.slice)
        out = EMPTY
        for a in container.alts:
            out = out.join(self.index_alt(a, key, e))
        return self.bound(out) if not out.is_empty() else UNKNOWN

    def idx_values(self, v):
        out = []
        for a in v.alts:
            if isinstance(a, Const) and (a.value is None or isinstance(a.value, int)):
                out.append(a.value)
            elif isinstance(a, LenOf):
                out.append(a)
            else:
                out.append(Ellipsis)
        return out

    def slice_alt(self, a, lo, hi, st, e):
        if isinstance(a, Str):
            out = EMPTY
            for x in self.idx_values(lo):
                for y in self.idx_values(hi):
                    for z in self.idx_values(st):
                        if z is Ellipsis or isinstance(z, LenOf):
                            z = 2
                        out = out.join(Val([S.slice_str(a, x, y, z, self.site(e))]))
            return out
        if isinstance(a, Tup):
            x, y, z = (lo.single_const(), hi.single_const(), st.single_const())
            if all(q is None or isinstance(q, int) for q in (x, y, z)) and x is not NOTHING and y is not NOTHING and z is not NOTHING:
                return Val([Tup(a.items[x:y:z])])
            return Val([Tup(())]) if not a.items else Val([Unk(merge_holes([h for v in a.items for h in v.holes() if h.facts]))])
        if isinstance(a, Ref):
            obj = self.get(a.aid)
            if isinstance(obj, ListObj):
                x, y, z = (lo.single_const(), hi.single_const(), st.single_const())
                if obj.elems is not None and obj.summ is None and all(q is None or isinstance(q, int) for q in (x, y, z)) and NOTHING not in (x, y, z):
                    return self.alloc(e, ListObj(obj.kind, obj.elems[x:y:z], None))
                return self.alloc(e, ListObj(obj.kind, None, obj.all_values()))
            if isinstance(obj, LibObj):
                return self.lib.obj_index(self, a.aid, obj, None, e)
            return UNKNOWN
        if isinstance(a, Unk):
            return Val([Unk(S.derive(a.hole, self.site(e)))]) if a.hole is not None else UNKNOWN
        return UNKNOWN

    def index_alt(self, a, key, e):
        if isinstance(a, Str):
            out = EMPTY
            for k in self.idx_values(key):
                r = S.index_str(a, k, self.site(e))
                if r is not None:
                    out = out.join(Val([r]))
            return out
        if isinstance(a, Tup):
            k = key.single_const()
            if isinstance(k, int) and not isinstance(k, bool) and -len(a.items) <= k < len(a.items):
                return a.items[k]
            out = EMPTY
            for x in a.items:
                out = out.join(x)
            return out
        if isinstance(a, Ref):
            obj = self.get(a.aid)
            if isinstance(obj, ListObj):
                k = key.single_const()
                if obj.elems is not None and obj.summ is None and isinstance(k, int) and not isinstance(k, bool):
                    if -len(obj.elems) <= k < len(obj.elems):
                        return obj.elems[k]
                    return EMPTY
                return obj.all_values() if not obj.all_values().is_empty() else UNKNOWN
            if isinstance(obj, DictObj):
                d = obj.as_dict()
                ks = key.consts()
                if ks is not None and all(_hashable(k) for k in ks):
                    out = EMPTY
                    for k in ks:
                        if k in d:
                            out = out.join(d[k])
                        elif obj.rest is not None:
                            out = out.join(obj.rest)
                    return out
                return obj.all_values() if not obj.all_values().is_empty() else UNKNOWN
            if isinstance(obj, LibObj):
                return self.lib.obj_index(self, a.aid, obj, key, e)
            if isinstance(obj, InstObj):
                return self.call_method(Val([a]), "__getitem__", [key], {}, e, quiet=True) or UNKNOWN
            return UNKNOWN
        if isinstance(a, Lib):
            return self.lib.lib_index(self, a.name, key, e)
        if isinstance(a, Unk):
            return Val([Unk(S.derive(a.hole, self.site(e)))]) if a.hole is not None else UNKNOWN
        if isinstance(a, Cls):
            return Val([a])
        return UNKNOWN

    def ev_List(self, e):
        return self.display(e, "list")

    def ev_Set(self, e):
        return self.display(e, "set")

    def ev_Tuple(self, e):
        items = []
        for x in e.elts:
            if isinstance(x, ast.Starred):
                v = self.ev(x.value)
                ex = None
                if len(v.alts) == 1:
                    ex = self.exact_items(next(iter(v.alts)))
                if ex is None:
                    return Val([Unk(merge_holes([h for h in v.holes() if h.facts]))]) if v.tainted() else UNKNOWN
                items.extend(ex)
            else:
                items.append(self.ev(x))
        return Val([Tup(tuple(items))])

    def display(self, e, kind):
        items = []
        exact = True
        summ = EMPTY
        for x in e.elts:
            if isinstance(x, ast.Starred):
                v = self.ev(x.value)
                ex = self.exact_items(next(iter(v.alts))) if len(v.alts) == 1 else None
                if ex is None:
                    exact = False
                    summ = summ.join(self.iter_elems(v, x))
                else:
                    items.extend(ex)
            else:
                items.append(self.ev(x))
        if kind == "set" or not exact or len(items) > self.an.max_items:
            for v in items:
                summ = summ.join(v)
            return self.alloc(e, ListObj(kind, None, self.bound(summ)))
        return self.alloc(e, ListObj(kind, tuple(items), None))

    def ev_Dict(self, e):
        d = {}
        rest = None
        for k, v in zip(e.keys, e.values, strict=False):
            if k is None:
                src = self.ev(v)
                for a in src.alts:
                    if isinstance(a, Ref):
                        obj = self.get(a.aid)
                        if isinstance(obj, DictObj):
                            for kk, vv in obj.items:
                                d[kk] = vv
                            if obj.rest is not None:
                                rest = obj.rest if rest is None else rest.join(obj.rest)
                continue
            kv = self.ev(k)
            vv = self.ev(v)
            c = kv.single_const()
            if c is not NOTHING and _hashable(c):
                d[c] = vv
            else:
                rest = vv if rest is None else rest.join(vv)
        return self.alloc(e, DictObj(items_tuple(d), rest))

    def comp_elements(self, e, elt_fn):
        saved = dict(self.st.vars)
        names = {n.id for g in e.generators for n in ast.walk(g.target) if isinstance(n, ast.Name)}
        added = names - self.comp
        self.comp |= added
        try:
            for gen in e.generators:
                it = self.ev(gen.iter)
                elems = self.iter_elems(it, gen)
                self.assign(gen.target, elems if not elems.is_empty() else UNKNOWN, gen)
                for cond in gen.ifs:
                    self.ev(cond)
            out = elt_fn()
        finally:
            self.comp -= added
        for n in names:
            if n in saved:
                self.st.vars[n] = saved[n]
            else:
                self.st.vars.pop(n, None)
        return out

    def ev_ListComp(self, e):
        v = self.comp_elements(e, lambda: self.ev(e.elt))
        return self.alloc(e, ListObj("list", None, v))

    def ev_SetComp(self, e):
        v = self.comp_elements(e, lambda: self.ev(e.elt))
        return self.alloc(e, ListObj("set", None, v))

    def ev_GeneratorExp(self, e):
        v = self.comp_elements(e, lambda: self.ev(e.elt))
        return self.alloc(e, ListObj("list", None, v))

    def ev_DictComp(self, e):
        def pair():
            return (self.ev(e.key), self.ev(e.value))

        k, v = self.comp_elements(e, pair)
        return self.alloc(e, DictObj((), k.join(v) if k.tainted() else v))

    def ev_IfExp(self, e):
        t = self.ev(e.test).truth()
        if t is True:
            return self.ev(e.body)
        if t is False:
            return self.ev(e.orelse)
        return self.bound(self.ev(e.body).join(self.ev(e.orelse)))

    def ev_BoolOp(self, e):
        result = EMPTY
        for i, x in enumerate(e.values):
            v = self.ev(x)
            t = v.truth()
            last = i == len(e.values) - 1
            if isinstance(e.op, ast.Or):
                if t is True:
                    return self.bound(result.join(v))
                if t is None and not last:
                    result = result.join(v)
                    continue
                if last:
                    return self.bound(result.join(v))
            else:
                if t is False:
                    return self.bound(result.join(v))
                if t is None and not last:
                    result = result.join(v)
                    continue
                if last:
                    return self.bound(result.join(v))
        return self.bound(result)

    def ev_UnaryOp(self, e):
        v = self.ev(e.operand)
        if isinstance(e.op, ast.Not):
            t = v.truth()
            if t is None:
                return BOOL
            return FALSE if t else TRUE
        out = EMPTY
        for a in v.alts:
            if isinstance(a, Const) and isinstance(a.value, (int, float, complex)):
                try:
                    if isinstance(e.op, ast.USub):
                        out = out.join(const(-a.value))
                    elif isinstance(e.op, ast.UAdd):
                        out = out.join(const(+a.value))
                    else:
                        out = out.join(const(~a.value))
                except TypeError:
                    out = out.join(Val([Num()]))
            elif isinstance(a, Num):
                out = out.join(Val([a]))
            else:
                out = out.join(Val([Num()]))
        return out

    def ev_BinOp(self, e):
        left = self.ev(e.left)
        right = self.ev(e.right)
        return self.binop(e.op, left, right, e)

    def binop(self, op, left, right, e):
        out = EMPTY
        n = 0
        for a in left.alts:
            for b in right.alts:
                n += 1
                if n > 64:
                    return self.collapse(out.join(self.taint_union([left, right], e)), force=True)
                out = out.join(self.binop_alt(op, a, b, e))
        return self.bound(out) if not out.is_empty() else UNKNOWN

    def taint_union(self, vals, e, numeric=False):
        holes = []
        for v in vals:
            holes.extend(h for h in v.holes() if h.facts)
        if not holes:
            return Val([Num()]) if numeric else UNKNOWN
        h = S.derive(merge_holes(holes), self.site(e))
        h = h.with_props(h.props.restrict(flags=["via-call"]))
        if numeric:
            return Val([Num(h.with_props(h.props.restrict(allowed="-+.")))])
        return Val([Unk(h)])

    def binop_alt(self, op, a, b, e):
        site = self.site(e)
        opt = type(op)
        if isinstance(a, Ref):
            obj = self.get(a.aid)
            if isinstance(obj, LibObj):
                r = self.lib.obj_binop(self, a.aid, obj, op, Val([b]), e)
                if r is not None:
                    return r
            if isinstance(obj, ListObj) and opt is ast.Add and isinstance(b, Ref):
                other = self.get(b.aid)
                if isinstance(other, ListObj):
                    if obj.elems is not None and other.elems is not None and obj.summ is None and other.summ is None:
                        return self.alloc(e, ListObj("list", obj.elems + other.elems, None))
                    return self.alloc(e, ListObj("list", None, obj.all_values().join(other.all_values())))
            if isinstance(obj, ListObj) and opt is ast.Mult:
                return self.alloc(e, ListObj(obj.kind, None, obj.all_values()))
            if isinstance(obj, (ListObj, DictObj)) and opt is ast.BitOr and isinstance(b, Ref):
                other = self.get(b.aid)
                if isinstance(obj, DictObj) and isinstance(other, DictObj):
                    d = obj.as_dict()
                    d.update(other.as_dict())
                    return self.alloc(e, DictObj(items_tuple(d), obj.rest if other.rest is None else other.rest.join(obj.rest or EMPTY)))
            if isinstance(obj, InstObj):
                name = {ast.Add: "__add__", ast.Mod: "__mod__", ast.Div: "__truediv__"}.get(opt)
                if name and self.class_attr(obj.cid, name) is not None:
                    return self.call_method(Val([a]), name, [Val([b])], {}, e)
            return UNKNOWN
        if isinstance(a, Str) and opt is ast.Add:
            sb = S.as_str(b) if not isinstance(b, Str) else b
            if sb is None:
                return Val([S.summarize(a, site)]) if a.holes() else Val([S.opaque()])
            return Val([S.concat(a, sb)])
        if isinstance(a, Str) and opt is ast.Mod:
            return self.lib.percent_format(self, a, Val([b]), e)
        if isinstance(a, Str) and opt is ast.Mult:
            if isinstance(b, Const) and isinstance(b.value, int):
                return Val([S.repeat(a, b.value, site)])
            return Val([S.summarize(a, site)])
        if isinstance(b, Str) and opt is ast.Mult and isinstance(a, Const) and isinstance(a.value, int):
            return Val([S.repeat(b, a.value, site)])
        if isinstance(a, Unk) and isinstance(b, Str) and opt is ast.Add:
            sa = S.as_str(a)
            return Val([S.concat(sa, b)])
        if isinstance(a, Tup) and isinstance(b, Tup) and opt is ast.Add:
            return Val([Tup(a.items + b.items)])
        if isinstance(a, LenOf) and isinstance(b, Const) and isinstance(b.value, int):
            if opt is ast.Sub:
                return Val([LenOf(a.target, a.offset - b.value)])
            if opt is ast.Add:
                return Val([LenOf(a.target, a.offset + b.value)])
        if isinstance(a, Const) and isinstance(b, Const):
            f = BINOPS.get(opt)
            if f is not None:
                try:
                    if opt is ast.Pow and isinstance(b.value, (int, float)) and abs(b.value) > 256:
                        return Val([Num()])
                    if opt in (ast.LShift, ast.Mult) and isinstance(b.value, int) and b.value > 4096:
                        return Val([Num()])
                    return const(f(a.value, b.value))
                except Exception:
                    return EMPTY
        if isinstance(a, (Const, Num, LenOf)) and isinstance(b, (Const, Num, LenOf)):
            return self.taint_union([Val([a]), Val([b])], e, numeric=True)
        return self.taint_union([Val([a]), Val([b])], e)

    def ev_Compare(self, e):
        vals = [self.ev(e.left)] + [self.ev(c) for c in e.comparators]
        result = True
        for i, op in enumerate(e.ops):
            r = self.compare(op, vals[i], vals[i + 1])
            if r is False:
                return FALSE
            if r is None:
                result = None
        return TRUE if result else BOOL

    def compare(self, op, left, right):
        opt = type(op)
        if opt in (ast.In, ast.NotIn):
            r = self.contains(right, left)
            if r is None:
                return None
            return r if opt is ast.In else not r
        lc = left.consts()
        rc = right.consts()
        f = CMPOPS.get(opt)
        if lc is not None and rc is not None and f is not None:
            seen = set()
            for x in lc:
                for y in rc:
                    try:
                        if opt in (ast.Is, ast.IsNot):
                            r = (x is None and y is None) or (x is y) or (isinstance(x, bool) and x == y and type(x) is type(y))
                            r = r if opt is ast.Is else not r
                        else:
                            r = bool(f(x, y))
                    except Exception:
                        return None
                    seen.add(r)
                    if len(seen) > 1:
                        return None
            if len(seen) == 1:
                return seen.pop()
        if opt in (ast.Is, ast.IsNot) and (lc == [None] or rc == [None]):
            other = right if lc == [None] else left
            if all(isinstance(a, (Str, Ref, Fn, Cls, Mod, Tup)) for a in other.alts):
                return opt is ast.IsNot
        return None

    def contains(self, container, item):
        ic = item.consts()
        result = None
        first = True
        for a in container.alts:
            r = self.contains_alt(a, item, ic)
            if r is None:
                return None
            if first:
                result = r
                first = False
            elif r != result:
                return None
        return result

    def contains_alt(self, a, item, ic):
        if isinstance(a, Str):
            if ic is None or not all(isinstance(x, (str, bytes)) for x in ic):
                return None
            rs = set()
            for x in ic:
                x = x.decode("latin-1") if isinstance(x, bytes) else x
                rs.add(S.contains(a, x))
            return rs.pop() if len(rs) == 1 else None
        if isinstance(a, Ref):
            obj = self.get(a.aid)
            elems = None
            if isinstance(obj, ListObj) and obj.elems is not None and obj.summ is None:
                elems = obj.elems
            elif isinstance(obj, DictObj) and obj.rest is None:
                keys = [k for k, _ in obj.items]
                if ic is None:
                    return None
                return _all_same([x in keys for x in ic])
            if elems is None or ic is None:
                return None
            cs = []
            for el in elems:
                c = el.consts()
                if c is None:
                    return None
                cs.extend(c)
            return _all_same([x in cs for x in ic])
        if isinstance(a, Tup):
            if ic is None:
                return None
            cs = []
            for el in a.items:
                c = el.consts()
                if c is None:
                    return None
                cs.extend(c)
            return _all_same([x in cs for x in ic])
        return None

    def ev_JoinedStr(self, e):
        parts = [Str.make([""])]
        for v in e.values:
            if isinstance(v, ast.Constant):
                piece = Val([Str.make([v.value])])
            elif isinstance(v, ast.FormattedValue):
                piece = self.formatted(v)
            else:
                piece = self.to_str(self.ev(v), v)
            new = []
            for p in parts:
                for q in piece.alts:
                    q = q if isinstance(q, Str) else S.opaque()
                    new.append(S.concat(p, S.to_text(q)))
            if len(new) > self.an.max_alts:
                new = list(self.collapse(Val(new)).alts)
            parts = new
        return self.bound(Val(parts))

    def formatted(self, v):
        val = self.ev(v.value)
        if v.format_spec is not None:
            self.ev(v.format_spec)
        if v.conversion == ord("r"):
            return self.lib.repr_val(self, val, v)
        if v.conversion == ord("a"):
            return self.lib.repr_val(self, val, v)
        return self.to_str(val, v)

    def to_str(self, v, e):
        return self.lib.str_val(self, v, e)

    def ev_Call(self, e):
        args, kwargs = self.eval_args(e)
        if isinstance(e.func, ast.Attribute):
            v = e.func.value
            if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "super" and len(v.args) in (0, 2):
                out = self.super_call(e.func.attr, args, kwargs, e)
                if out is not None:
                    return out
            recv = self.ev(e.func.value)
            return self.call_method(recv, e.func.attr, args, kwargs, e)
        f = self.ev(e.func)
        return self.call_val(f, args, kwargs, e)

    def super_call(self, name, args, kwargs, e):
        info = self.info
        if info is None or info.kind not in ("method", "classmethod"):
            return None
        ci = self.an.classes.get(info.cid)
        params = info.node.args.posonlyargs + info.node.args.args
        if ci is None or not params:
            return None
        me = self.st.vars.get(params[0].arg, UNKNOWN)
        for b in ci.bases:
            for alt in b.alts:
                if isinstance(alt, Cls):
                    m = self.class_attr(alt.cid, name)
                    if m is not None:
                        return self.call_val(self.bind_method(m, me, alt.cid), args, kwargs, e)
        for b in ci.bases:
            for alt in b.alts:
                if isinstance(alt, Lib):
                    out = self.lib.super_method(self, alt.name, me, name, args, kwargs, e)
                    if out is not None:
                        return out
        for b in ci.bases:
            for alt in b.alts:
                if isinstance(alt, Cls):
                    out = self.super_lib(alt.cid, me, name, args, kwargs, e)
                    if out is not None:
                        return out
        return None

    def super_lib(self, cid, me, name, args, kwargs, e, depth=0):
        ci = self.an.classes.get(cid)
        if ci is None or depth > 10:
            return None
        for b in ci.bases:
            for alt in b.alts:
                if isinstance(alt, Lib):
                    out = self.lib.super_method(self, alt.name, me, name, args, kwargs, e)
                    if out is not None:
                        return out
                elif isinstance(alt, Cls):
                    out = self.super_lib(alt.cid, me, name, args, kwargs, e, depth + 1)
                    if out is not None:
                        return out
        return None

    def lib_bases(self, cid, depth=0):
        ci = self.an.classes.get(cid)
        if ci is None or depth > 10:
            return set()
        out = set()
        for b in ci.bases:
            for alt in b.alts:
                if isinstance(alt, Lib):
                    out.add(alt.name)
                elif isinstance(alt, Cls):
                    out |= self.lib_bases(alt.cid, depth + 1)
        return out

    def eval_args(self, e):
        args = []
        kwargs = {}
        for a in e.args:
            if isinstance(a, ast.Starred):
                v = self.ev(a.value)
                ex = self.exact_items(next(iter(v.alts))) if len(v.alts) == 1 else None
                if ex is None:
                    args.append(self.iter_elems(v, a))
                else:
                    args.extend(ex)
            else:
                args.append(self.ev(a))
        star = None
        for k in e.keywords:
            v = self.ev(k.value)
            if k.arg is None:
                for alt in v.alts:
                    if isinstance(alt, Ref):
                        obj = self.get(alt.aid)
                        if isinstance(obj, DictObj):
                            for kk, vv in obj.items:
                                if isinstance(kk, str):
                                    kwargs[kk] = vv if kk not in kwargs or len(v.alts) == 1 else kwargs[kk].join(vv)
                                else:
                                    star = vv if star is None else star.join(vv)
                            if obj.rest is not None:
                                star = obj.rest if star is None else star.join(obj.rest)
                    elif isinstance(alt, Unk) and alt.hole is not None and alt.hole.facts:
                        star = Val([alt]) if star is None else star.join(Val([alt]))
            else:
                kwargs[k.arg] = v
        if star is not None:
            kwargs["**"] = star
        return args, kwargs

    def call_val(self, f, args, kwargs, e):
        out = EMPTY
        for a in f.alts:
            out = out.join(self.call_alt(a, args, kwargs, e))
        return self.bound(out) if not out.is_empty() else EMPTY

    def call_alt(self, a, args, kwargs, e):
        if isinstance(a, Fn):
            info = self.an.funcs.get(a.fid)
            if info is None:
                return UNKNOWN
            if a.recv is not None:
                args = [a.recv] + list(args)
            return self.an.call_function(self, info, args, kwargs, e)
        if isinstance(a, Cls):
            return self.instantiate(a.cid, args, kwargs, e)
        if isinstance(a, Lib):
            return self.lib.call(self, a.name, args, kwargs, e)
        if isinstance(a, Meth):
            return self.call_method(a.recv, a.name, args, kwargs, e)
        if isinstance(a, Unk):
            return self.taint_union([Val([a])] + list(args) + list(kwargs.values()), e)
        if isinstance(a, Ref):
            obj = self.get(a.aid)
            if isinstance(obj, LibObj):
                return self.lib.method(self, a.aid, obj, "__call__", args, kwargs, e)
            if isinstance(obj, InstObj):
                return self.call_method(Val([a]), "__call__", args, kwargs, e)
        return self.taint_union(list(args) + list(kwargs.values()), e)

    def instantiate(self, cid, args, kwargs, e):
        ci = self.an.classes.get(cid)
        aid = ("obj",) + self.site(e)
        if self.get(aid) is None:
            self.put(aid, InstObj(cid, ()))
        ref = Val([Ref(aid)])
        init = self.class_attr(cid, "__init__")
        if init is not None:
            for x in init.alts:
                if isinstance(x, Fn):
                    info = self.an.funcs.get(x.fid)
                    if info is not None:
                        self.an.call_function(self, info, [ref] + list(args), kwargs, e)
            return ref
        fields = self.record_fields(cid)
        if fields:
            star = kwargs.get("**")
            o = self.get(aid)
            d = o.as_dict() if isinstance(o, InstObj) else {}
            for i, name in enumerate(fields):
                if i < len(args):
                    d[name] = args[i]
                elif name in kwargs:
                    d[name] = kwargs[name]
                elif star is not None:
                    dv = self.class_attr(cid, name)
                    d[name] = star if dv is None else star.join(dv)
            self.put(aid, InstObj(cid, items_tuple(d)))
        if ci is not None:
            for b in ci.bases:
                for alt in b.alts:
                    if isinstance(alt, Lib):
                        self.lib.subclass_init(self, aid, alt.name, args, kwargs, e)
        return ref

    def record_fields(self, cid, depth=0):
        ci = self.an.classes.get(cid)
        if ci is None or depth > 10:
            return None
        out = []
        found = ci.record
        for b in ci.bases:
            for alt in b.alts:
                if isinstance(alt, Cls):
                    sub = self.record_fields(alt.cid, depth + 1)
                    if sub is not None:
                        found = True
                        out.extend(f for f in sub if f not in out)
        if not found:
            return None
        out.extend(f for f in ci.fields if f not in out)
        return out

    def call_method(self, recv, name, args, kwargs, e, quiet=False):
        out = EMPTY
        for a in recv.alts:
            out = out.join(self.method_alt(a, name, args, kwargs, e, quiet))
        if out.is_empty():
            return EMPTY if quiet else UNKNOWN
        return self.bound(out)

    def method_alt(self, a, name, args, kwargs, e, quiet):
        if isinstance(a, Str):
            return self.lib.str_method(self, a, name, args, kwargs, e)
        if isinstance(a, Unk):
            if a.hole is not None and name in S_METHODS:
                return self.lib.str_method(self, Str((a.hole,)), name, args, kwargs, e)
            if a.hole is not None:
                return self.lib.tainted_method(self, a.hole, name, args, kwargs, e)
            return self.lib.unknown_method(self, name, args, kwargs, e)
        if isinstance(a, Ref):
            obj = self.get(a.aid)
            if isinstance(obj, ListObj):
                return self.lib.list_method(self, a.aid, obj, name, args, kwargs, e)
            if isinstance(obj, DictObj):
                return self.lib.dict_method(self, a.aid, obj, name, args, kwargs, e)
            if isinstance(obj, LibObj):
                return self.lib.method(self, a.aid, obj, name, args, kwargs, e)
            if isinstance(obj, InstObj):
                d = obj.as_dict()
                if name in d:
                    return self.call_val(d[name], args, kwargs, e)
                v = self.class_attr(obj.cid, name)
                if v is None:
                    ci = self.an.classes.get(obj.cid)
                    if ci is not None:
                        for b in ci.bases:
                            for alt in b.alts:
                                if isinstance(alt, Lib):
                                    return self.lib.inherited_method(self, a.aid, alt.name, name, args, kwargs, e)
                    return EMPTY if quiet else self.taint_union(list(args) + list(kwargs.values()), e)
                return self.call_val(self.bind_method(v, Val([a]), obj.cid), args, kwargs, e)
            return UNKNOWN
        if isinstance(a, Lib):
            return self.lib.call(self, a.name + "." + name, args, kwargs, e)
        if isinstance(a, Mod):
            return self.call_val(self.an.module_attr(a.name, name), args, kwargs, e)
        if isinstance(a, Cls):
            v = self.get_attr(a, name, e)
            return self.call_val(v, args, kwargs, e)
        if isinstance(a, Num):
            return Val([Num(a.hole)]) if name not in ("to_bytes", "hex") else self.lib.str_val(self, Val([a]), e)
        if isinstance(a, Const):
            if isinstance(a.value, (int, float)) and name in ("to_bytes", "hex", "real", "imag", "conjugate", "bit_length"):
                try:
                    return const(getattr(a.value, name)(*[x.single_const() for x in args]))
                except Exception:
                    return UNKNOWN
            return UNKNOWN
        if isinstance(a, Tup):
            if name == "index" or name == "count":
                return Val([Num()])
            return UNKNOWN
        if isinstance(a, Fn):
            return UNKNOWN
        return UNKNOWN

    def branch(self, expr, st):
        self.st = st.copy()
        v = self.ev(expr)
        t = v.truth()
        after = self.st
        ts = None if t is False else self.refine(expr, after.copy(), True)
        fs = None if t is True else self.refine(expr, after.copy(), False)
        return ts, fs

    def peek(self, e, st):
        if not is_pure(e):
            return None
        saved = self.st
        self.st = st
        try:
            return self.ev(e)
        finally:
            self.st = saved

    def refine(self, e, st, outcome):
        if isinstance(e, ast.Compare) and len(e.ops) == 1:
            return self.refine_compare(e, st, outcome)
        if isinstance(e, ast.Call):
            return self.refine_call(e, st, outcome)
        return st

    def refine_holes(self, st, hids, fn):
        if not hids:
            return st

        def m(h):
            if h.hid in hids and h.facts:
                return fn(h)
            return h

        st.vars = {k: v.map_holes(m) for k, v in st.vars.items()}
        st.heap = {k: map_obj(o, m) for k, o in st.heap.items()}
        return st

    def contained(self, expr, rv, st):
        hids = set()
        for a in rv.alts:
            s = self.str_alt(a) if isinstance(a, Ref) else a if isinstance(a, Str) else None
            if s is not None:
                hids |= {h.hid for h in s.holes() if h.facts and "norm" in h.props.flags}
        if not hids:
            return st

        def fn(h):
            return h.with_props(h.props.restrict(kinds=["path-traversal"]))

        st = self.refine_holes(st, hids, fn)
        base = expr
        while isinstance(base, ast.Call):
            f = base.func
            if isinstance(f, ast.Attribute) and f.attr in ("resolve", "absolute", "as_posix", "__str__", "__fspath__") and not base.args:
                base = f.value
            elif base.args and (isinstance(f, ast.Name) and f.id in ("str", "realpath", "abspath", "normpath", "Path") or isinstance(f, ast.Attribute) and f.attr in ("realpath", "abspath", "normpath", "fspath", "Path")):
                base = base.args[0]
            else:
                break
        if not isinstance(base, ast.Name) or base.id not in st.vars:
            return st
        roots = {S.root_hid(h) for h in hids}

        def m(h):
            if h.facts and S.root_hid(h.hid) in roots:
                return fn(h)
            return h

        v = st.vars[base.id]
        st.vars[base.id] = v.map_holes(m)
        for a in v.alts:
            if isinstance(a, Ref) and a.aid in st.heap:
                st.heap[a.aid] = map_obj(st.heap[a.aid], m)
        return st

    def refine_compare(self, e, st, outcome):
        op = e.ops[0]
        left, right = e.left, e.comparators[0]
        opt = type(op)
        if opt in (ast.In, ast.NotIn):
            holds = (opt is ast.In) == outcome
            lv = self.peek(left, st)
            rv = self.peek(right, st)
            if lv is None or rv is None:
                return st
            lc = lv.single_const()
            if not holds and isinstance(lc, str) and lc:
                hids = {h.hid for h in rv.holes() if h.facts}
                return self.refine_holes(st, hids, lambda h: h.with_props(h.props.restrict(excl=[lc])))
            if holds:
                consts = self.const_members(rv, st)
                if consts is not None and isinstance(left, ast.Name):
                    st.vars[left.id] = Val([Str.make([c]) if isinstance(c, str) else Const(c) for c in consts])
                    return st
                if consts is not None:
                    parse = self.parse_attr_of(left, st)
                    if parse is not None and left.attr in ("netloc", "hostname", "host"):
                        return self.refine_holes(st, parse, lambda h: h.with_props(h.props.restrict(kinds=["open-redirect", "ssrf"])))
            return st
        if opt in (ast.Eq, ast.NotEq, ast.Is, ast.IsNot):
            holds = (opt in (ast.Eq, ast.Is)) == outcome
            if not holds:
                return st
            lv = self.peek(left, st)
            rv = self.peek(right, st)
            if lv is None or rv is None:
                return st
            for var, otherv in ((left, rv), (right, lv)):
                c = otherv.single_const()
                if c is NOTHING:
                    continue
                if isinstance(var, ast.Name):
                    st.vars[var.id] = otherv
                    return st
                if isinstance(var, ast.Attribute) and var.attr in ("netloc", "hostname", "host"):
                    parse = self.parse_attr_of(var, st)
                    if parse is not None:
                        return self.refine_holes(st, parse, lambda h: h.with_props(h.props.restrict(kinds=["open-redirect", "ssrf"])))
            return st
        return st

    def parse_attr_of(self, e, st):
        if not isinstance(e, ast.Attribute):
            return None
        base = self.peek(e.value, st)
        if base is None:
            return None
        hids = set()
        for a in base.alts:
            if isinstance(a, Ref):
                obj = st.heap.get(a.aid) or self.an.static_heap.get(a.aid)
                if isinstance(obj, LibObj) and obj.type == "urllib.parse.ParseResult":
                    src = obj.get("src")
                    if src is not None:
                        hids |= {h.hid for h in src.holes() if h.facts}
        return hids or None

    def const_members(self, v, st):
        out = []
        for a in v.alts:
            if isinstance(a, Tup):
                for x in a.items:
                    c = x.consts()
                    if c is None:
                        return None
                    out.extend(c)
            elif isinstance(a, Ref):
                obj = st.heap.get(a.aid) or self.an.static_heap.get(a.aid)
                if isinstance(obj, ListObj) and obj.elems is not None and obj.summ is None:
                    for x in obj.elems:
                        c = x.consts()
                        if c is None:
                            return None
                        out.extend(c)
                elif isinstance(obj, ListObj) and obj.summ is not None and obj.elems is None:
                    c = obj.summ.consts()
                    if c is None:
                        return None
                    out.extend(c)
                elif isinstance(obj, DictObj) and obj.rest is None:
                    out.extend(k for k, _ in obj.items)
                else:
                    return None
            else:
                return None
        if not out or len(out) > 64:
            return None
        return out

    def refine_call(self, e, st, outcome):
        func = e.func
        if isinstance(func, ast.Attribute):
            name = func.attr
            if name in GUARD_METHODS and outcome and not e.args:
                rv = self.peek(func.value, st)
                if rv is None:
                    return st
                allowed = GUARD_METHODS[name]
                hids = {h.hid for h in rv.holes() if h.facts}
                return self.refine_holes(st, hids, lambda h: h.with_props(h.props.restrict(allowed=allowed)))
            if name in ("startswith", "endswith") and outcome and len(e.args) == 1:
                rv = self.peek(func.value, st)
                av = self.peek(e.args[0], st)
                if rv is None or av is None:
                    return st
                c = av.single_const()
                if any("norm" in h.props.flags for h in rv.holes() if h.facts) and name == "startswith" and not av.tainted():
                    st = self.contained(func.value, rv, st)
                if isinstance(c, str) and c and isinstance(func.value, ast.Name):
                    cur = st.vars.get(func.value.id)
                    if cur is not None:
                        new = self.refine_affix(cur, c, name, e)
                        if new is None:
                            return None
                        st.vars[func.value.id] = new
                return st
            if name in ("match", "fullmatch", "search") and outcome:
                return self.refine_regex(e, st)
            if name == "is_relative_to" and outcome and len(e.args) == 1:
                rv = self.peek(func.value, st)
                av = self.peek(e.args[0], st)
                if rv is not None and av is not None and not av.tainted():
                    return self.contained(func.value, rv, st)
        if isinstance(func, ast.Name) and func.id == "isinstance" and outcome and len(e.args) == 2:
            t = e.args[1]
            names = [t] if not isinstance(t, ast.Tuple) else list(t.elts)
            if all(isinstance(n, ast.Name) and n.id in ("int", "float", "bool") for n in names):
                rv = self.peek(e.args[0], st)
                if rv is not None:
                    hids = {h.hid for h in rv.holes() if h.facts}
                    return self.refine_holes(st, hids, lambda h: h.with_props(h.props.restrict(allowed="-+.")))
        return st

    def refine_regex(self, e, st):
        func = e.func
        pattern = None
        subject = None
        if isinstance(func.value, ast.Name) and func.value.id == "re" and len(e.args) >= 2:
            pv = self.peek(e.args[0], st)
            pattern = pv.single_const() if pv is not None else NOTHING
            subject = e.args[1]
            mode = func.attr
        else:
            pv = self.peek(func.value, st)
            if pv is None:
                return st
            for a in pv.alts:
                if isinstance(a, Ref):
                    obj = st.heap.get(a.aid) or self.an.static_heap.get(a.aid)
                    if isinstance(obj, LibObj) and obj.type == "re.Pattern":
                        p = obj.get("pattern")
                        if p is not None:
                            pattern = p.single_const()
            if not e.args:
                return st
            subject = e.args[0]
            mode = func.attr
        if not isinstance(pattern, str):
            return st
        allowed = self.lib.regex_alphabet(pattern, mode)
        if allowed is None:
            return st
        sv = self.peek(subject, st)
        if sv is None:
            return st
        hids = {h.hid for h in sv.holes() if h.facts}
        return self.refine_holes(st, hids, lambda h: h.with_props(h.props.restrict(allowed=allowed)))

    def refine_affix(self, cur, c, name, e):
        out = []
        site = self.site(e)
        for a in cur.alts:
            if not isinstance(a, Str):
                if isinstance(a, Unk) and a.hole is not None:
                    a = Str((a.hole,))
                else:
                    out.append(a)
                    continue
            r = S.startswith(a, c) if name == "startswith" else S.endswith(a, c)
            if r is False:
                continue
            if r is True:
                out.append(a)
                continue
            parts = list(a.parts)
            if name == "startswith" and isinstance(parts[0], Hole) and parts[0].facts:
                parts = [c, S.derive(parts[0], site + ("pre",))] + parts[1:]
            elif name == "endswith" and isinstance(parts[-1], Hole) and parts[-1].facts:
                parts = parts[:-1] + [S.derive(parts[-1], site + ("suf",)), c]
            out.append(Str.make(parts, a.raw))
        if not out:
            return None
        return Val(out)

    def case(self, node, st):
        tmp, subject_expr = node.data
        self.st = st.copy()
        subject = self.st.vars.get(tmp, UNKNOWN)
        pattern = node.ast.pattern
        r, binds = self.match_pattern(pattern, subject, node.ast)
        base = self.st
        t = None
        f = None
        if r is not False:
            t = base.copy()
            for name, v in binds.items():
                t.vars[name] = v
            if isinstance(pattern, (ast.MatchValue, ast.MatchSingleton)) and isinstance(subject_expr, ast.Name):
                pv = self.peek(pattern.value, t) if isinstance(pattern, ast.MatchValue) else const(pattern.value)
                if pv is not None:
                    t.vars[subject_expr.id] = pv
        if r is not True:
            f = base
        return t, f

    def match_pattern(self, p, subject, e):
        if isinstance(p, ast.MatchValue):
            pv = self.ev(p.value)
            return self.compare(ast.Eq(), subject, pv), {}
        if isinstance(p, ast.MatchSingleton):
            return self.compare(ast.Is(), subject, const(p.value)), {}
        if isinstance(p, ast.MatchAs):
            if p.pattern is None:
                return True, ({p.name: subject} if p.name else {})
            r, b = self.match_pattern(p.pattern, subject, e)
            if p.name:
                b = dict(b)
                b[p.name] = subject
            return r, b
        if isinstance(p, ast.MatchOr):
            results = []
            binds = {}
            for sub in p.patterns:
                r, b = self.match_pattern(sub, subject, e)
                results.append(r)
                for k, v in b.items():
                    binds[k] = v.join(binds.get(k, EMPTY))
            if any(r is True for r in results):
                return True, binds
            if all(r is False for r in results):
                return False, binds
            return None, binds
        binds = {}
        for sub in ast.walk(p):
            if isinstance(sub, (ast.MatchAs, ast.MatchStar)) and sub.name:
                binds[sub.name] = self.iter_elems(subject, e) if isinstance(sub, ast.MatchStar) else UNKNOWN
            if isinstance(sub, ast.MatchMapping) and sub.rest:
                binds[sub.rest] = UNKNOWN
        return None, binds


S_METHODS = {n for n in dir(str) if not n.startswith("_")} | {n for n in dir(bytes) if not n.startswith("_")}


def is_pure(e):
    for n in ast.walk(e):
        if isinstance(n, (ast.Await, ast.Yield, ast.YieldFrom, ast.NamedExpr, ast.Lambda)):
            return False
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name) and f.id in PURE_CALLS:
                continue
            if isinstance(f, ast.Attribute) and f.attr in S_METHODS and f.attr not in ("pop", "append"):
                continue
            if isinstance(f, ast.Attribute) and f.attr in ("resolve", "absolute", "as_posix", "lower", "upper"):
                continue
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute) and f.value.attr == "path":
                continue
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in ("urllib", "os", "re"):
                continue
            return False
    return True


def _hashable(k):
    try:
        hash(k)
        return True
    except TypeError:
        return False


def _all_same(xs):
    if not xs:
        return None
    first = xs[0]
    return first if all(x == first for x in xs) else None
