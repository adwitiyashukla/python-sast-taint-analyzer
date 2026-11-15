from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Source:
    kind: str
    label: str
    file: str = ""
    line: int = 0
    col: int = 0
    index: int = -1


@dataclass(frozen=True, slots=True)
class Step:
    file: str
    line: int
    col: int
    note: str


@dataclass(frozen=True, slots=True)
class Props:
    allowed: frozenset | None = None
    excl: frozenset = frozenset()
    kinds: frozenset = frozenset()
    flags: frozenset = frozenset()

    def excludes(self, text):
        if text in self.excl or any(c in self.excl for c in text):
            return True
        if self.allowed is None:
            return False
        return any(not c.isalnum() and c not in self.allowed for c in text)

    def meet(self, other):
        if self.allowed is None:
            allowed = other.allowed
        elif other.allowed is None:
            allowed = self.allowed
        else:
            allowed = self.allowed & other.allowed
        return Props(allowed, self.excl | other.excl, self.kinds | other.kinds, self.flags | other.flags)

    def join(self, other):
        if self == other:
            return self
        if self.allowed is None or other.allowed is None:
            allowed = None
        else:
            allowed = self.allowed | other.allowed
        excl = set()
        for item in self.excl | other.excl:
            if self.excludes(item) and other.excludes(item):
                excl.add(item)
        if allowed is not None:
            excl = {x for x in excl if all(c.isalnum() or c in allowed for c in x)}
        return Props(allowed, frozenset(excl), self.kinds & other.kinds, self.flags & other.flags)

    def restrict(self, allowed=None, excl=(), kinds=(), flags=()):
        new_allowed = self.allowed
        if allowed is not None:
            new_allowed = frozenset(allowed) if self.allowed is None else self.allowed & frozenset(allowed)
        return Props(new_allowed, self.excl | frozenset(excl), self.kinds | frozenset(kinds), self.flags | frozenset(flags))


PLAIN = Props()
NUMERIC = Props(allowed=frozenset("-+."))
ALNUM = Props(allowed=frozenset())


class Hole:
    __slots__ = ("hid", "facts", "props", "trace", "_hash")

    def __init__(self, hid, facts, props=PLAIN, trace=()):
        self.hid = hid
        self.facts = facts
        self.props = props
        self.trace = trace
        self._hash = hash((hid, facts, props))

    def __eq__(self, other):
        return isinstance(other, Hole) and self._hash == other._hash and self.hid == other.hid and self.facts == other.facts and self.props == other.props

    def __hash__(self):
        return self._hash

    def __repr__(self):
        return f"Hole({self.hid!r}, {sorted(f.label for f in self.facts)}, {self.props})"

    def with_props(self, props):
        if props == self.props:
            return self
        return Hole(self.hid, self.facts, props, self.trace)

    def derive(self, hid=None, props=None, trace=None):
        return Hole(self.hid if hid is None else hid, self.facts, self.props if props is None else props, self.trace if trace is None else trace)

    def add_step(self, step, limit):
        if self.trace and self.trace[-1] == step:
            return self
        trace = self.trace + (step,)
        if len(trace) > limit:
            trace = trace[:1] + trace[len(trace) - limit + 1:]
        return Hole(self.hid, self.facts, self.props, trace)

    def kinds_of(self):
        return {f.kind for f in self.facts}


def merge_holes(holes, hid=None):
    holes = list(holes)
    if not holes:
        return None
    if len(holes) == 1 and hid is None:
        return holes[0]
    facts = frozenset().union(*(h.facts for h in holes))
    tainted = [h for h in holes if h.facts]
    props = tainted[0].props if tainted else PLAIN
    for h in tainted[1:]:
        props = props.join(h.props)
    if hid is None:
        hid = min((h.hid for h in holes), key=repr)
    trace = min((h.trace for h in holes), key=lambda t: (len(t), repr(t)))
    return Hole(hid, facts, props, trace)


@dataclass(frozen=True, slots=True)
class Str:
    parts: tuple
    raw: bool = False

    @staticmethod
    def make(parts, raw=False):
        out = []
        for p in parts:
            if isinstance(p, str):
                if not p:
                    continue
                if out and isinstance(out[-1], str):
                    out[-1] = out[-1] + p
                    continue
            out.append(p)
        return Str(tuple(out), raw)

    def is_const(self):
        return all(isinstance(p, str) for p in self.parts)

    def text(self):
        return "".join(self.parts)

    def holes(self):
        return [p for p in self.parts if isinstance(p, Hole)]

    def python(self):
        t = self.text()
        return t.encode("latin-1", "replace") if self.raw else t


OPAQUE = Hole(("opaque",), frozenset())


@dataclass(frozen=True, slots=True)
class LenOf:
    target: object
    offset: int


@dataclass(frozen=True, slots=True)
class Const:
    value: object


@dataclass(frozen=True, slots=True)
class Num:
    hole: Hole | None = None


@dataclass(frozen=True, slots=True)
class Unk:
    hole: Hole | None = None


@dataclass(frozen=True, slots=True)
class Ref:
    aid: object


@dataclass(frozen=True, slots=True)
class Tup:
    items: tuple


@dataclass(frozen=True, slots=True)
class Fn:
    fid: object
    recv: object = None


@dataclass(frozen=True, slots=True)
class Cls:
    cid: object


@dataclass(frozen=True, slots=True)
class Mod:
    name: str


@dataclass(frozen=True, slots=True)
class Lib:
    name: str


@dataclass(frozen=True, slots=True)
class Meth:
    recv: object
    name: str


class Val:
    __slots__ = ("alts", "_hash")

    def __init__(self, alts=()):
        self.alts = frozenset(alts)
        self._hash = hash(self.alts)

    def __eq__(self, other):
        return isinstance(other, Val) and self._hash == other._hash and self.alts == other.alts

    def __hash__(self):
        return self._hash

    def __repr__(self):
        return "Val(" + ", ".join(sorted(repr(a) for a in self.alts)) + ")"

    def __iter__(self):
        return iter(self.alts)

    def __len__(self):
        return len(self.alts)

    def is_empty(self):
        return not self.alts

    def join(self, other):
        if other is None or other is self or other.alts <= self.alts:
            return self
        if self.alts <= other.alts:
            return other
        return Val(self.alts | other.alts)

    def holes(self):
        out = []
        for a in self.alts:
            out.extend(alt_holes(a))
        return out

    def tainted(self, kind=None):
        for h in self.holes():
            if h.facts and (kind is None or any(f.kind == kind for f in h.facts)):
                return True
        return False

    def consts(self):
        out = []
        for a in self.alts:
            if isinstance(a, Const):
                out.append(a.value)
            elif isinstance(a, Str) and a.is_const():
                out.append(a.python())
            else:
                return None
        return out

    def single_const(self):
        c = self.consts()
        if c is not None and len(c) == 1:
            return c[0]
        return NOTHING

    def strs(self):
        return [a for a in self.alts if isinstance(a, Str)]

    def refs(self):
        return [a.aid for a in self.alts if isinstance(a, Ref)]

    def map_holes(self, fn):
        changed = False
        out = []
        for a in self.alts:
            b = map_alt(a, fn)
            changed = changed or b is not a
            out.append(b)
        return Val(out) if changed else self

    def remap(self, hfn, rfn):
        changed = False
        out = []
        for a in self.alts:
            b = remap_alt(a, hfn, rfn)
            changed = changed or b is not a
            out.append(b)
        return Val(out) if changed else self

    def truth(self):
        result = None
        for a in self.alts:
            t = alt_truth(a)
            if t is None:
                return None
            if result is None:
                result = t
            elif result != t:
                return None
        return result


class _Nothing:
    def __repr__(self):
        return "NOTHING"


NOTHING = _Nothing()
EMPTY = Val()
UNKNOWN = Val([Unk()])
NONE = Val([Const(None)])
TRUE = Val([Const(True)])
FALSE = Val([Const(False)])
BOOL = Val([Const(True), Const(False)])


def const(value):
    if isinstance(value, str):
        return Val([Str.make([value])])
    if isinstance(value, bytes):
        return Val([Str.make([value.decode("latin-1")], raw=True)])
    return Val([Const(value)])


def alt_holes(a):
    if isinstance(a, Str):
        return a.holes()
    if isinstance(a, (Num, Unk)):
        return [a.hole] if a.hole is not None else []
    if isinstance(a, Tup):
        out = []
        for v in a.items:
            out.extend(v.holes())
        return out
    if isinstance(a, Meth):
        return a.recv.holes() if isinstance(a.recv, Val) else []
    return []


def map_alt(a, fn):
    if isinstance(a, Str):
        parts = tuple(fn(p) if isinstance(p, Hole) else p for p in a.parts)
        if all(x is y for x, y in zip(parts, a.parts, strict=False)):
            return a
        return Str.make(parts, a.raw)
    if isinstance(a, Num) and a.hole is not None:
        h = fn(a.hole)
        return a if h is a.hole else Num(h)
    if isinstance(a, Unk) and a.hole is not None:
        h = fn(a.hole)
        return a if h is a.hole else Unk(h)
    if isinstance(a, Tup):
        items = tuple(v.map_holes(fn) for v in a.items)
        if all(x is y for x, y in zip(items, a.items, strict=False)):
            return a
        return Tup(items)
    if isinstance(a, Meth) and isinstance(a.recv, Val):
        r = a.recv.map_holes(fn)
        return a if r is a.recv else Meth(r, a.name)
    return a


def remap_alt(a, hfn, rfn):
    if isinstance(a, Ref):
        n = rfn(a.aid)
        return a if n == a.aid else Ref(n)
    if isinstance(a, Tup):
        items = tuple(v.remap(hfn, rfn) for v in a.items)
        if all(x is y for x, y in zip(items, a.items, strict=False)):
            return a
        return Tup(items)
    if isinstance(a, Fn) and a.recv is not None:
        r = a.recv.remap(hfn, rfn)
        return a if r is a.recv else Fn(a.fid, r)
    if isinstance(a, Meth) and isinstance(a.recv, Val):
        r = a.recv.remap(hfn, rfn)
        return a if r is a.recv else Meth(r, a.name)
    if isinstance(a, LenOf) and isinstance(a.target, Str):
        t = map_alt(a.target, hfn)
        return a if t is a.target else LenOf(t, a.offset)
    return map_alt(a, hfn)


def remap_obj(obj, hfn, rfn):
    if isinstance(obj, ListObj):
        elems = None if obj.elems is None else tuple(v.remap(hfn, rfn) for v in obj.elems)
        summ = None if obj.summ is None else obj.summ.remap(hfn, rfn)
        return ListObj(obj.kind, elems, summ)
    if isinstance(obj, DictObj):
        return DictObj(tuple((k, v.remap(hfn, rfn)) for k, v in obj.items), None if obj.rest is None else obj.rest.remap(hfn, rfn), obj.kind)
    if isinstance(obj, InstObj):
        return InstObj(obj.cid, tuple((k, v.remap(hfn, rfn)) for k, v in obj.attrs))
    if isinstance(obj, LibObj):
        return LibObj(obj.type, tuple((k, v.remap(hfn, rfn)) for k, v in obj.attrs))
    return obj


def alt_truth(a):
    if isinstance(a, Const):
        return bool(a.value)
    if isinstance(a, Str):
        if any(isinstance(p, str) and p for p in a.parts):
            return True
        if a.is_const():
            return False
        return None
    if isinstance(a, Tup):
        return bool(a.items)
    if isinstance(a, (Fn, Cls, Mod)):
        return True
    return None


@dataclass(frozen=True, slots=True)
class ListObj:
    kind: str
    elems: tuple | None
    summ: Val | None = None

    def all_values(self):
        out = EMPTY
        if self.elems is not None:
            for v in self.elems:
                out = out.join(v)
        if self.summ is not None:
            out = out.join(self.summ)
        return out


@dataclass(frozen=True, slots=True)
class DictObj:
    items: tuple
    rest: Val | None = None
    kind: str = "dict"

    def as_dict(self):
        return dict(self.items)

    def all_values(self):
        out = EMPTY
        for _, v in self.items:
            out = out.join(v)
        if self.rest is not None:
            out = out.join(self.rest)
        return out


@dataclass(frozen=True, slots=True)
class InstObj:
    cid: object
    attrs: tuple

    def as_dict(self):
        return dict(self.attrs)


@dataclass(frozen=True, slots=True)
class LibObj:
    type: str
    attrs: tuple

    def as_dict(self):
        return dict(self.attrs)

    def get(self, name, default=None):
        for k, v in self.attrs:
            if k == name:
                return v
        return default


def items_tuple(d):
    return tuple(sorted(d.items(), key=lambda kv: repr(kv[0])))


def obj_values(obj):
    if isinstance(obj, ListObj):
        vals = list(obj.elems or ())
        if obj.summ is not None:
            vals.append(obj.summ)
        return vals
    if isinstance(obj, DictObj):
        vals = [v for _, v in obj.items]
        if obj.rest is not None:
            vals.append(obj.rest)
        return vals
    if isinstance(obj, (InstObj, LibObj)):
        return [v for _, v in obj.attrs]
    return []


def map_obj(obj, fn):
    if isinstance(obj, ListObj):
        elems = None if obj.elems is None else tuple(v.map_holes(fn) for v in obj.elems)
        summ = None if obj.summ is None else obj.summ.map_holes(fn)
        return ListObj(obj.kind, elems, summ)
    if isinstance(obj, DictObj):
        return DictObj(tuple((k, v.map_holes(fn)) for k, v in obj.items), None if obj.rest is None else obj.rest.map_holes(fn), obj.kind)
    if isinstance(obj, InstObj):
        return InstObj(obj.cid, tuple((k, v.map_holes(fn)) for k, v in obj.attrs))
    if isinstance(obj, LibObj):
        return LibObj(obj.type, tuple((k, v.map_holes(fn)) for k, v in obj.attrs))
    return obj


def join_opt(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a.join(b)


def join_obj(a, b):
    if a is None:
        return b
    if b is None or a is b or a == b:
        return a
    if isinstance(a, ListObj) and isinstance(b, ListObj):
        if a.elems is not None and b.elems is not None and len(a.elems) == len(b.elems):
            return ListObj(a.kind, tuple(x.join(y) for x, y in zip(a.elems, b.elems, strict=True)), join_opt(a.summ, b.summ))
        return ListObj(a.kind, None, a.all_values().join(b.all_values()))
    if isinstance(a, DictObj) and isinstance(b, DictObj):
        da, db = a.as_dict(), b.as_dict()
        out = {}
        for k in set(da) | set(db):
            out[k] = join_opt(da.get(k), db.get(k))
        return DictObj(items_tuple(out), join_opt(a.rest, b.rest), a.kind)
    if isinstance(a, InstObj) and isinstance(b, InstObj):
        da, db = a.as_dict(), b.as_dict()
        return InstObj(a.cid, items_tuple({k: join_opt(da.get(k), db.get(k)) for k in set(da) | set(db)}))
    if isinstance(a, LibObj) and isinstance(b, LibObj):
        da, db = a.as_dict(), b.as_dict()
        return LibObj(a.type, items_tuple({k: join_opt(da.get(k), db.get(k)) for k in set(da) | set(db)}))
    return a
