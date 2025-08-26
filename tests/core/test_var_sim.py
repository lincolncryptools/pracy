from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.sim import sim
from pracy.core.var import Var


def test_var_sim_simple():
    var_a = Var("a", [])
    var_b = Var("a", [])
    assert sim(var_a, var_b)


def test_var_sim_const_indices():
    var_a = Var("a", [Idx("1")])
    var_b = Var("a", [Idx("1")])
    assert sim(var_a, var_b)


def test_var_sim_quant_index():
    var_a = Var("a", [Idx("i")], [Quant("i", QSet.AUTHORITIES)])
    var_b = Var("a", [Idx("k")])
    assert sim(var_a, var_b)


def test_var_sim_quant_indices():
    var_a = Var("a", [Idx("i")], [Quant("i", QSet.AUTHORITIES)])
    var_b = Var("a", [Idx("k")], [Quant("k", QSet.USER_ATTRIBUTES)])
    assert sim(var_a, var_b)


def test_var_sim_local_map():
    var_a = Var("a", [Idx("i")], [Quant("i", QSet.AUTHORITIES)])
    var_b = Var("a", [Idx("k", IMap.TO_AUTHORITY)], [Quant("k", QSet.LSSS_ROWS)])
    assert sim(var_a, var_b)


def test_var_sim_global_map():
    var_a = Var("a", [Idx("i")], [Quant("i", QSet.LSSS_ROWS, QMap.LSSS_ROW_TO_ATTR)])
    var_b = Var("a", [Idx("k")], [Quant("k", QSet.USER_ATTRIBUTES)])
    assert sim(var_a, var_b)


def test_var_sim_complex():
    var_a = Var(
        "a",
        [
            Idx("1"),
            Idx("i"),
        ],
        [Quant("i", QSet.LSSS_ROWS, QMap.LSSS_ROW_TO_LABEL)],
    )
    var_b = Var("a", [Idx("k", IMap.TO_LABEL), Idx("1")], [Quant("k", QSet.LSSS_ROWS)])
    assert sim(var_a, var_b)


def test_var_not_sim_by_name():
    var_a = Var("a", [Idx("1")])
    var_b = Var("b", [Idx("1")])
    assert not sim(var_a, var_b)


def test_var_not_sim_by_index():
    var_a = Var("a", [Idx("1")])
    var_b = Var("a", [Idx("2")])
    assert not sim(var_a, var_b)


def test_var_not_sim_by_index_count():
    var_a = Var("a", [Idx("1")])
    var_b = Var("a", [Idx("1"), Idx("2")])
    assert not sim(var_a, var_b)
