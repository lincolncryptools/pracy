from sympy import Add, Symbol

from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.var import Var
from pracy.frontend.parsing import parse_matrix_entry
from pracy.frontend.raw_scheme import RawPair


def test_parse_matrix_entry_simple():
    lhs = Var("c", [Idx("2"), Idx("j")])
    rhs = Var("r", [Idx("j")])
    quants = [Quant("j", QSet.LINEAR_COMBINATION_INDICES)]
    expr = Symbol("<epsilon>_{j}")
    expected = RawPair(lhs, rhs, expr, quants)
    received = parse_matrix_entry("(c_{2, j} ~ r_{j} = <epsilon>_{j})_[j:LIN_COMB]")
    assert received == expected


def test_parse_matrix_entry_complex():
    lhs = Var("c", [Idx("2"), Idx("j")])
    rhs = Var("r", [Idx("j", IMap.TO_AUTHORITY)])
    quants = [Quant("j", QSet.LINEAR_COMBINATION_INDICES)]
    expr = Add(Symbol("<epsilon>_{j}"), 1)
    expected = RawPair(lhs, rhs, expr, quants)
    received = parse_matrix_entry(
        "(c_{2, j} ~ r_{j.auth} = <epsilon>_{j} + 1)_[j:LIN_COMB]"
    )
    assert received == expected


def test_parse_matrix_entry_special_var():
    lhs = Var("c", [Idx("2"), Idx("j")])
    rhs = Var("<rgid>", [])
    quants = [Quant("j", QSet.LINEAR_COMBINATION_INDICES)]
    expr = Symbol("<epsilon>_{j}")
    expected = RawPair(lhs, rhs, expr, quants)
    received = parse_matrix_entry("(c_{2, j} ~ <rgid> = <epsilon>_{j})_[j:LIN_COMB]")
    assert received == expected
