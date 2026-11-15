from __future__ import annotations

import _string
import string as _stdstring

from .values import (
    NUMERIC,
    OPAQUE,
    Const,
    Hole,
    LenOf,
    Num,
    Props,
    Str,
    Tup,
    Unk,
    merge_holes,
)

WHITESPACE = frozenset(" \t\n\r\x0b\x0c")


def root_hid(hid):
    while isinstance(hid, tuple) and len(hid) == 3 and hid[0] == "d":
        hid = hid[2]
    return hid


def derive(hole, site, props=None):
    if not hole.facts:
        return hole
    return hole.derive(hid=("d", site, root_hid(hole.hid)), props=props)


def opaque(raw=False):
    return Str((OPAQUE,), raw)


def as_str(alt):
    if isinstance(alt, Str):
        return alt
    if isinstance(alt, Const):
        return Str.make([str(alt.value)])
    if isinstance(alt, Num):
        if alt.hole is None:
            return opaque()
        return Str((alt.hole.with_props(alt.hole.props.restrict(allowed=NUMERIC.allowed)),))
    if isinstance(alt, Unk):
        return Str((alt.hole,)) if alt.hole is not None else opaque()
    if isinstance(alt, LenOf):
        return opaque()
    if isinstance(alt, Tup):
        holes = []
        for v in alt.items:
            holes.extend(v.holes())
        h = merge_holes([x for x in holes if x.facts])
        return Str((h,)) if h is not None else opaque()
    return None


def bytes_repr(s):
    if s.is_const():
        return Str.make([repr(s.python())])
    return Str.make(["b'"] + list(s.parts) + ["'"])


def to_text(s):
    if s.raw:
        return bytes_repr(s)
    return s


def concat(a, b):
    return Str.make(a.parts + b.parts, a.raw)


def summarize(s, site, props=None):
    holes = [h for h in s.holes() if h.facts]
    if not holes:
        return opaque(s.raw)
    h = derive(merge_holes(holes), site, props)
    if props is not None:
        h = h.with_props(props)
    return Str((h,), s.raw)


def _edges(s):
    parts = list(s.parts)
    head = parts[0] if parts and isinstance(parts[0], str) else ""
    tail = parts[-1] if len(parts) > 1 and isinstance(parts[-1], str) else ""
    middle = parts[(1 if head else 0): len(parts) - (1 if tail else 0)]
    return head, middle, tail


def _norm_index(i, s):
    if isinstance(i, LenOf):
        if i.target != s:
            return Ellipsis
        if i.offset >= 0:
            return None
        return i.offset
    if i is None or isinstance(i, int):
        return i
    return Ellipsis


def slice_str(s, start, stop, step, site):
    start = _norm_index(start, s)
    stop = _norm_index(stop, s)
    if s.is_const():
        if Ellipsis in (start, stop) or not (step is None or isinstance(step, int)) or step == 0:
            return opaque(s.raw)
        return Str.make([s.text()[start:stop:step]], s.raw)
    if step not in (None, 1):
        return summarize(s, site)
    head, middle, tail = _edges(s)
    p, q = len(head), len(tail)
    if start is None:
        start = 0
    holes = [x for x in middle if isinstance(x, Hole)]

    def merged():
        tainted = [h for h in holes if h.facts]
        if not tainted:
            return OPAQUE
        return derive(merge_holes(tainted), site)

    if isinstance(start, int) and start < 0 and -start <= q:
        if stop is None:
            return Str.make([tail[q + start:]], s.raw)
        if isinstance(stop, int) and stop < 0 and -stop <= q:
            return Str.make([tail[q + start:q + stop]], s.raw)
        return Str((merged(),), s.raw)
    if isinstance(start, int) and 0 <= start <= p:
        from_head = head[start:]
        if isinstance(stop, int) and 0 <= stop <= p:
            return Str.make([head[start:stop]], s.raw)
        if stop is None:
            return Str.make([from_head] + middle + [tail], s.raw)
        if isinstance(stop, int) and stop < 0 and -stop <= q:
            return Str.make([from_head] + middle + [tail[:q + stop]], s.raw)
        return Str.make([from_head, merged()], s.raw)
    if stop is None:
        return Str.make([merged(), tail], s.raw)
    if isinstance(stop, int) and stop < 0 and -stop <= q:
        return Str.make([merged(), tail[:q + stop]], s.raw)
    return Str((merged(),), s.raw)


def index_str(s, i, site):
    i = _norm_index(i, s)
    if s.is_const():
        if not isinstance(i, int):
            return opaque(s.raw)
        t = s.text()
        if -len(t) <= i < len(t):
            if s.raw:
                return Const(ord(t[i]))
            return Str.make([t[i]])
        return None
    head, middle, tail = _edges(s)
    if isinstance(i, int) and 0 <= i < len(head):
        return Const(ord(head[i])) if s.raw else Str.make([head[i]])
    if isinstance(i, int) and i < 0 and -i <= len(tail):
        return Const(ord(tail[i])) if s.raw else Str.make([tail[i]])
    tainted = [h for h in s.holes() if h.facts]
    if not tainted:
        return Num() if s.raw else opaque()
    h = derive(merge_holes(tainted), site)
    if s.raw:
        return Num(h.with_props(h.props.restrict(allowed=NUMERIC.allowed)))
    return Str((h,))


def chars(s, site, limit):
    out = []
    if s.raw:
        tainted = [h for h in s.holes() if h.facts]
        if tainted:
            h = derive(merge_holes(tainted), site)
            out.append(Num(h.with_props(h.props.restrict(allowed=NUMERIC.allowed))))
        if any(isinstance(p, str) and p for p in s.parts):
            out.append(Num())
        return out
    seen = set()
    for p in s.parts:
        if isinstance(p, str):
            seen.update(p)
    if len(seen) > limit:
        out.append(opaque())
    else:
        out.extend(Str.make([c]) for c in sorted(seen))
    tainted = [h for h in s.holes() if h.facts]
    if tainted:
        out.append(Str((derive(merge_holes(tainted), site),)))
    elif any(not isinstance(p, str) for p in s.parts):
        out.append(opaque())
    return out


def startswith(s, prefix):
    head, _, _ = _edges(s)
    if s.is_const():
        return s.text().startswith(prefix)
    if len(head) >= len(prefix):
        return head.startswith(prefix)
    if not prefix.startswith(head):
        return False
    return None


def endswith(s, suffix):
    _, _, tail = _edges(s)
    if s.is_const():
        return s.text().endswith(suffix)
    if len(tail) >= len(suffix):
        return tail.endswith(suffix)
    if not suffix.endswith(tail):
        return False
    return None


def contains(s, sub):
    if s.is_const():
        return sub in s.text()
    if any(isinstance(p, str) and sub in p for p in s.parts):
        return True
    tainted = [h for h in s.holes() if h.facts]
    opaque_parts = [h for h in s.holes() if not h.facts]
    if opaque_parts:
        return None
    if all(all(h.props.excludes(c) for c in set(sub)) for h in tainted):
        return False
    if len(s.parts) == 1 and all(h.props.excludes(sub) for h in tainted):
        return False
    return None


def specials(text):
    return {c for c in text if not c.isalnum()}


def replace(s, old, new, count, site):
    if s.is_const():
        return Str.make([s.text().replace(old, new, count)], s.raw)
    parts = []
    for p in s.parts:
        if isinstance(p, str):
            parts.append(p.replace(old, new, count))
            continue
        if not p.facts:
            parts.append(p)
            continue
        pr = p.props
        allowed = pr.allowed
        if allowed is not None:
            allowed = allowed | specials(new)
            if len(old) == 1 and old not in new and count < 0:
                allowed = allowed - {old}
        excl = {x for x in pr.excl if len(x) == 1 and x not in new}
        if len(old) == 1 and old not in new and count < 0:
            excl.add(old)
        kinds = pr.kinds if all(c.isalnum() for c in new) else frozenset()
        parts.append(derive(p, site, Props(None if allowed is None else frozenset(allowed), frozenset(excl), kinds, frozenset())))
    return Str.make(parts, s.raw)


def transform_holes(s, site, props_fn=None):
    parts = []
    for p in s.parts:
        if isinstance(p, Hole) and p.facts:
            parts.append(derive(p, site, props_fn(p.props) if props_fn else None))
        else:
            parts.append(p)
    return Str.make(parts, s.raw)


def map_const_parts(s, fn, site, props_fn=None):
    parts = []
    for p in s.parts:
        if isinstance(p, str):
            parts.append(fn(p))
        elif p.facts:
            parts.append(derive(p, site, props_fn(p.props) if props_fn else None))
        else:
            parts.append(p)
    return Str.make(parts, s.raw)


def strip_like(s, method, args, site):
    args = tuple(a.decode("latin-1") if isinstance(a, bytes) else a for a in args)
    if any(a is not None and not isinstance(a, str) for a in args):
        return summarize(s, site)
    if s.is_const():
        return Str.make([getattr(s.text(), method)(*args)], s.raw)
    head, middle, tail = _edges(s)
    if method in ("strip", "lstrip", "rstrip"):
        if method in ("strip", "lstrip") and head:
            head = head.lstrip(*args)
        if method in ("strip", "rstrip") and tail:
            tail = tail.rstrip(*args)
        mid = [derive(x, site) if isinstance(x, Hole) and x.facts else x for x in middle]
        return Str.make([head] + mid + [tail], s.raw)
    return map_const_parts(s, lambda t: getattr(t, method)(*args), site)


def split(s, sep, maxsplit, site):
    if s.is_const():
        t = s.text()
        pieces = t.split(sep, maxsplit) if sep is not None or maxsplit != -1 else t.split()
        return [Str.make([x], s.raw) for x in pieces], None
    tainted = [h for h in s.holes() if h.facts]
    alts = []
    for p in s.parts:
        if isinstance(p, str):
            for x in (p.split(sep) if sep is not None else p.split()):
                alts.append(Str.make([x], s.raw))
    if tainted:
        h = derive(merge_holes(tainted), site)
        if maxsplit < 0:
            if sep is None:
                h = h.with_props(h.props.restrict(excl=WHITESPACE))
            elif len(sep) == 1:
                h = h.with_props(h.props.restrict(excl=[sep]))
        alts.append(Str((h,), s.raw))
    else:
        alts.append(opaque(s.raw))
    return None, alts


def join_strs(sep, items, raw=False):
    parts = []
    for i, it in enumerate(items):
        if i:
            parts.extend(sep.parts)
        parts.extend(it.parts)
    return Str.make(parts, raw or sep.raw)


def repeat(s, n, site):
    if s.is_const() and isinstance(n, int):
        return Str.make([s.text() * n], s.raw)
    return summarize(s, site)


def parse_format(fmt):
    try:
        return list(_stdstring.Formatter().parse(fmt))
    except (ValueError, TypeError):
        return None


def parse_field(name):
    try:
        first, rest = _string.formatter_field_name_split(name)
        return first, list(rest)
    except (ValueError, TypeError):
        return None


def parse_percent(fmt):
    out = []
    i = 0
    lit = []
    n = len(fmt)
    while i < n:
        c = fmt[i]
        if c != "%":
            lit.append(c)
            i += 1
            continue
        if i + 1 < n and fmt[i + 1] == "%":
            lit.append("%")
            i += 2
            continue
        if lit:
            out.append("".join(lit))
            lit = []
        i += 1
        key = None
        if i < n and fmt[i] == "(":
            j = fmt.find(")", i)
            if j < 0:
                return None
            key = fmt[i + 1:j]
            i = j + 1
        while i < n and fmt[i] in "-+ #0":
            i += 1
        while i < n and (fmt[i].isdigit() or fmt[i] == "*"):
            i += 1
        if i < n and fmt[i] == ".":
            i += 1
            while i < n and (fmt[i].isdigit() or fmt[i] == "*"):
                i += 1
        while i < n and fmt[i] in "hlL":
            i += 1
        if i >= n:
            return None
        out.append(("spec", key, fmt[i]))
        i += 1
    if lit:
        out.append("".join(lit))
    return out
