from __future__ import annotations

import ast


class Node:
    __slots__ = ("nid", "kind", "ast", "succs", "data", "order")

    def __init__(self, nid, kind, node=None, data=None):
        self.nid = nid
        self.kind = kind
        self.ast = node
        self.data = data
        self.succs = []
        self.order = 0

    def __repr__(self):
        line = getattr(self.ast, "lineno", "-")
        return f"<{self.nid}:{self.kind}@{line}>"


class CFG:
    def __init__(self):
        self.nodes = []
        self.entry = self.add("entry")
        self.exit = self.add("exit")

    def add(self, kind, node=None, data=None):
        n = Node(len(self.nodes), kind, node, data)
        self.nodes.append(n)
        return n

    def edge(self, a, b, label=None):
        a.succs.append((b, label))

    def number(self):
        seen = set()
        post = []
        stack = [(self.entry, iter(self.entry.succs))]
        seen.add(self.entry.nid)
        while stack:
            node, it = stack[-1]
            for nxt, _ in it:
                if nxt.nid not in seen:
                    seen.add(nxt.nid)
                    stack.append((nxt, iter(nxt.succs)))
                    break
            else:
                stack.pop()
                post.append(node)
        for i, n in enumerate(reversed(post)):
            n.order = i
        for n in self.nodes:
            if n.nid not in seen:
                n.order = len(self.nodes) + n.nid
        return self


SIMPLE = (
    ast.Assign,
    ast.AugAssign,
    ast.AnnAssign,
    ast.Expr,
    ast.Import,
    ast.ImportFrom,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Delete,
    ast.TypeAlias,
)


class Builder:
    def __init__(self):
        self.cfg = CFG()
        self.loops = []
        self.handlers = []
        self.temp = 0

    def build(self, body):
        out = self.stmts(body, [(self.cfg.entry, None)])
        self.link(out, self.cfg.exit)
        return self.cfg.number()

    def link(self, preds, node):
        for p, label in preds:
            self.cfg.edge(p, node, label)

    def node(self, kind, s, preds, data=None):
        n = self.cfg.add(kind, s, data)
        self.link(preds, n)
        if self.handlers:
            self.cfg.edge(n, self.handlers[-1], "exc")
        return n

    def fresh(self, prefix):
        self.temp += 1
        return f"${prefix}{self.temp}"

    def stmts(self, body, preds):
        for s in body:
            if not preds:
                break
            preds = self.stmt(s, preds)
        return preds

    def cond(self, e, preds):
        if isinstance(e, ast.BoolOp) and isinstance(e.op, ast.And):
            t, f = preds, []
            for v in e.values:
                t, f2 = self.cond(v, t)
                f = f + f2
            return t, f
        if isinstance(e, ast.BoolOp) and isinstance(e.op, ast.Or):
            t, f = [], preds
            for v in e.values:
                t2, f = self.cond(v, f)
                t = t + t2
            return t, f
        if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
            t, f = self.cond(e.operand, preds)
            return f, t
        n = self.node("test", e, preds)
        return [(n, True)], [(n, False)]

    def stmt(self, s, preds):
        if isinstance(s, SIMPLE):
            return [(self.node("stmt", s, preds), None)]
        if isinstance(s, (ast.Pass, ast.Global, ast.Nonlocal)):
            return preds
        if isinstance(s, ast.If):
            t, f = self.cond(s.test, preds)
            return self.stmts(s.body, t) + self.stmts(s.orelse, f)
        if isinstance(s, ast.While):
            head = self.cfg.add("nop", s)
            self.link(preds, head)
            t, f = self.cond(s.test, [(head, None)])
            breaks = []
            self.loops.append((head, breaks))
            body = self.stmts(s.body, t)
            self.loops.pop()
            self.link(body, head)
            return self.stmts(s.orelse, f) + breaks
        if isinstance(s, (ast.For, ast.AsyncFor)):
            tmp = self.fresh("it")
            init = self.node("for_init", s, preds, tmp)
            head = self.cfg.add("for_next", s, tmp)
            self.cfg.edge(init, head)
            breaks = []
            self.loops.append((head, breaks))
            body = self.stmts(s.body, [(head, True)])
            self.loops.pop()
            self.link(body, head)
            return self.stmts(s.orelse, [(head, False)]) + breaks
        if isinstance(s, ast.Break):
            if self.loops:
                n = self.cfg.add("nop", s)
                self.link(preds, n)
                self.loops[-1][1].append((n, None))
            return []
        if isinstance(s, ast.Continue):
            if self.loops:
                self.link(preds, self.loops[-1][0])
            return []
        if isinstance(s, ast.Return):
            n = self.node("return", s, preds)
            self.cfg.edge(n, self.cfg.exit)
            return []
        if isinstance(s, ast.Raise):
            self.node("raise", s, preds)
            return []
        if isinstance(s, ast.Assert):
            t, _ = self.cond(s.test, preds)
            return t
        if isinstance(s, (ast.Try, ast.TryStar)):
            return self.try_stmt(s, preds)
        if isinstance(s, (ast.With, ast.AsyncWith)):
            n = self.node("with", s, preds)
            return self.stmts(s.body, [(n, None)])
        if isinstance(s, ast.Match):
            return self.match_stmt(s, preds)
        return [(self.node("stmt", s, preds), None)]

    def try_stmt(self, s, preds):
        dispatch = self.cfg.add("nop", s) if s.handlers else None
        if dispatch is not None:
            self.handlers.append(dispatch)
        body = self.stmts(s.body, preds)
        if dispatch is not None:
            self.handlers.pop()
        out = self.stmts(s.orelse, body)
        for h in s.handlers:
            hn = self.cfg.add("handler", h)
            self.cfg.edge(dispatch, hn)
            if self.handlers:
                self.cfg.edge(hn, self.handlers[-1], "exc")
            out = out + self.stmts(h.body, [(hn, None)])
        if s.finalbody:
            if not out:
                fin = self.cfg.add("nop", s)
                self.link(preds, fin)
                self.stmts(s.finalbody, [(fin, None)])
                return []
            return self.stmts(s.finalbody, out)
        return out

    def match_stmt(self, s, preds):
        tmp = self.fresh("m")
        subj = self.node("match_subject", s, preds, tmp)
        nxt = [(subj, None)]
        out = []
        for case in s.cases:
            n = self.node("case", case, nxt, (tmp, s.subject))
            t = [(n, True)]
            f = [(n, False)]
            if case.guard is not None:
                t, f2 = self.cond(case.guard, t)
                f = f + f2
            out = out + self.stmts(case.body, t)
            nxt = f
        return out + nxt


def build(body):
    return Builder().build(body)
