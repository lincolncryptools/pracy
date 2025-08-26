from pracy.core.equiv import equiv
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.var import Var


def test_var_equiv_simple():
    var_a = Var("a", [])
    var_b = Var("a", [])
    assert equiv(var_a, var_b)


def test_var_equiv_const_indices():
    var_a = Var("a", [Idx("1")])
    var_b = Var("a", [Idx("1")])
    assert equiv(var_a, var_b)


def test_var_equiv_quant_indices():
    var_a = Var("a", [Idx("i")], [Quant("i", QSet.AUTHORITIES)])
    var_b = Var("a", [Idx("k")], [Quant("k", QSet.AUTHORITIES)])
    assert equiv(var_a, var_b)


def test_var_equiv_local_map():
    var_a = Var("a", [Idx("i")], [Quant("i", QSet.AUTHORITIES)])
    var_b = Var("a", [Idx("k", IMap.TO_AUTHORITY)], [Quant("k", QSet.LSSS_ROWS)])
    assert equiv(var_a, var_b)


def test_var_equiv_global_map():
    var_a = Var("a", [Idx("i")], [Quant("i", QSet.LSSS_ROWS, QMap.LSSS_ROW_TO_ATTR)])
    var_b = Var("a", [Idx("k")], [Quant("k", QSet.USER_ATTRIBUTES)])
    assert equiv(var_a, var_b)


def test_var_equiv_complex():
    var_a = Var(
        "a",
        [
            Idx("1"),
            Idx("i"),
        ],
        [Quant("i", QSet.LSSS_ROWS, QMap.LSSS_ROW_TO_LABEL)],
    )
    var_b = Var("a", [Idx("1"), Idx("k", IMap.TO_LABEL)], [Quant("k", QSet.LSSS_ROWS)])
    assert equiv(var_a, var_b)


def test_var_not_equiv_by_name():
    var_a = Var("a", [Idx("1")])
    var_b = Var("b", [Idx("1")])
    assert not equiv(var_a, var_b)


def test_var_not_equiv_by_index():
    var_a = Var("a", [Idx("1")])
    var_b = Var("a", [Idx("2")])
    assert not equiv(var_a, var_b)


def test_var_not_equiv_by_index_count():
    var_a = Var("a", [Idx("1")])
    var_b = Var("a", [Idx("1"), Idx("2")])
    assert not equiv(var_a, var_b)


def test_var_not_equiv_by_index_const_vs_qunat():
    var_a = Var("a", [Idx("i")])
    var_b = Var("a", [Idx("i")], [Quant("i", QSet.LABELS)])
    assert not equiv(var_a, var_b)


def test_var_not_equiv_by_index_type():
    var_a = Var("a", [Idx("k", IMap.TO_AUTHORITY)], [Quant("k", QSet.LSSS_ROWS)])
    var_b = Var("a", [Idx("i")], [Quant("i", QSet.LABELS)])
    assert not equiv(var_a, var_b)
