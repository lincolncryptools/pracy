from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.var import Var
from pracy.frontend.parsing import parse_var


def test_parse_var_simple1():
    name = "alpha"
    idcs = [Idx("l")]
    quants = [Quant("l", QSet.AUTHORITIES)]
    var = Var(name, idcs, quants)
    assert parse_var("alpha_{l}_[l:AUTHS]") == var


def test_parse_var_simple2():
    name = "b"
    idcs = [Idx("att")]
    quants = [Quant("att", QSet.ATTRIBUTE_UNIVERSE)]
    var = Var(name, idcs, quants)
    assert parse_var("b_{att}_[att:ATTR_UNI]") == var


def test_parse_var_local_map():
    name = "b"
    idcs = [Idx("att", IMap.TO_AUTHORITY)]
    quants = [Quant("att", QSet.USER_ATTRIBUTES)]
    var = Var(name, idcs, quants)
    assert parse_var("b_{att.auth}_[att:USER_ATTRS]") == var


def test_parse_var_global_map():
    name = "x"
    idcs = [Idx("y")]
    quants = [Quant("y", QSet.ATTRIBUTE_UNIVERSE, QMap.ATTRIBUTE_TO_LABEL)]
    var = Var(name, idcs, quants)
    assert parse_var("x_{y}_[y:attr_to_lbl(ATTR_UNI)]") == var


def test_parse_var_multi_index():
    name = "beta"
    idcs = [Idx("x"), Idx("y")]
    quants = [Quant("y", QSet.LABELS)]
    var = Var(name, idcs, quants)
    assert parse_var("beta_{x,y}_[y:LABELS]") == var


def test_parse_var_multi_quant():
    name = "beta"
    idcs = [Idx("x")]
    quants = [Quant("x", QSet.LABELS), Quant("y", QSet.ATTRIBUTE_UNIVERSE)]
    var = Var(name, idcs, quants)
    assert parse_var("beta_{x}_[x:LABELS,y:ATTR_UNI]") == var


def test_parse_var_complex():
    name = "alpha"
    idcs = [Idx("1"), Idx("x", IMap.TO_ATTR), Idx("y")]
    quants = [
        Quant("x", QSet.LSSS_ROWS),
        Quant("y", QSet.LSSS_ROWS, QMap.LSSS_ROW_TO_XATTR),
    ]
    var = Var(name, idcs, quants)
    assert (
        parse_var("alpha_{1,x.attr,y}_[x:LSSS_ROWS,y:ls_row_to_xattr(LSSS_ROWS)]")
        == var
    )


def test_parse_var_numeric_index():
    name = "s"
    idcs = [Idx("1"), Idx("j")]
    var = Var(name, idcs)
    assert parse_var("s_{1,j}") == var
