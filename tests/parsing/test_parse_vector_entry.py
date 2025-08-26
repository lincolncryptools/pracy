from sympy import Add, Mul, Symbol

from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.var import Var
from pracy.frontend.parsing import parse_vector_entry
from pracy.frontend.raw_scheme import RawSingle


def test_parse_vector_entry_simple():
    name = "c'"
    idcs = [Idx("j")]
    var = Var(name, idcs)
    expr = Symbol("<epsilon>_{j}")
    quants = [Quant("j", QSet.LINEAR_COMBINATION_INDICES)]
    expected = RawSingle(var, expr, quants)
    received = parse_vector_entry("(c'_{j} = <epsilon>_{j})_[j:LIN_COMB]")
    assert received == expected


def test_parse_vector_entry_negation():
    name = "ct"
    idcs = [Idx("j", IMap.TO_AUTHORITY)]
    var = Var(name, idcs)
    expr = Add(0, Mul(-1, Symbol("<epsilon>_{j}")))
    quants = [Quant("j", QSet.LINEAR_COMBINATION_INDICES)]
    expected = RawSingle(var, expr, quants)
    received = parse_vector_entry("(ct_{j.auth} = -<epsilon>_{j})_[j:LIN_COMB]")
    assert received == expected
