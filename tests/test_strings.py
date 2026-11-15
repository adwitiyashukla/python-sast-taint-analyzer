from pysast import strings as S
from pysast.rules import quote_state, unsafe_parts
from pysast.values import Hole, Props, Source, Str

SITE = ("t", 1, 0, 0)


def hole(props=Props()):
    return Hole(("s", 1), frozenset([Source("input", "test")]), props)


def unsafe(mode, s):
    return [h for h, _, _ in unsafe_parts(mode, s, "input")]


def test_slice_that_cuts_both_constants_keeps_the_hole():
    h = hole()
    s = Str.make(["help", h, "on a plane"])
    out = S.slice_str(s, 4, -10, None, SITE)
    assert out.parts == (h,)


def test_slice_inside_a_constant_is_constant():
    s = Str.make(["help", hole(), "tail"])
    assert S.slice_str(s, 0, 4, None, SITE).parts == ("help",)
    assert S.slice_str(s, -4, None, None, SITE).parts == ("tail",)


def test_index_into_prefix_is_constant():
    s = Str.make(["abc", hole()])
    assert S.index_str(s, 1, SITE).parts == ("b",)


def test_replace_single_char_excludes_it():
    out = S.replace(Str((hole(),)), "'", "&apos;", -1, SITE)
    assert out.holes()[0].props.excludes("'")


def test_replace_that_keeps_the_char_does_not_exclude_it():
    out = S.replace(Str((hole(),)), "'", "''", -1, SITE)
    assert not out.holes()[0].props.excludes("'")


def test_multi_char_replace_is_not_trusted():
    out = S.replace(Str((hole(),)), "../", "", -1, SITE)
    assert not out.holes()[0].props.excludes("../")


def test_contains_is_decided_when_possible():
    s = Str.make(["select ", hole(Props(excl=frozenset("'")))])
    assert S.contains(s, "select") is True
    assert S.contains(s, "'") is False
    assert S.contains(Str((hole(),)), "'") is None


def test_split_element_excludes_separator():
    _, alts = S.split(Str((hole(),)), "/", -1, SITE)
    assert any(a.holes() and a.holes()[0].props.excludes("/") for a in alts)


def test_percent_and_format_parsers():
    assert S.parse_percent("a %s b %(k)d %%") == ["a ", ("spec", None, "s"), " b ", ("spec", "k", "d"), " %"]
    assert S.parse_field("0[bar]") == (0, [(False, "bar")])


def test_quote_context():
    assert quote_state("WHERE a = '") == "'"
    assert quote_state("WHERE a = 'x' AND b = ") is None
    assert quote_state('echo "', backslash=True) == '"'


def test_sql_context_rules():
    h = hole(Props(excl=frozenset("'")))
    assert unsafe("sql", Str.make(["WHERE a = '", h, "'"])) == []
    assert unsafe("sql", Str.make(['WHERE a = "', h, '"'])) == [h]
    assert unsafe("sql", Str.make(["WHERE id = ", h])) == [h]


def test_alphanumeric_props_are_safe_everywhere():
    h = hole(Props(allowed=frozenset()))
    for mode in ("sql", "xpath", "ldap", "shell", "path", "html"):
        assert unsafe(mode, Str.make(["x", h])) == []


def test_url_with_fixed_host_is_safe():
    h = hole()
    assert unsafe("ssrf", Str.make(["https://api.example.com/v1/", h])) == []
    assert unsafe("ssrf", Str.make(["https://", h])) == [h]
    assert unsafe("redirect", Str.make(["//", h])) == [h]
