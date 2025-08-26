import pytest
from sympy import Add, Integer, S, Symbol

from pracy.analysis.errors import (
    SingleInconsistentVarType,
    SingleInvalidExpressionError,
    SinglesIllegalSpecialVarError,
    SinglesTypeError,
    SingleUnusedQuantsError,
)
from pracy.analysis.expr import Coeff, Term
from pracy.analysis.single import Single, analyze_singles
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var
from pracy.frontend.raw_scheme import RawSingle


def test_analyze_singles_ok():
    raw_singles = [
        RawSingle(
            Var("c'", [Idx("j")]),
            Symbol("<epsilon>_{j}"),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    sec = Var("c'", [Idx("j")], [Quant("j", QSet.LINEAR_COMBINATION_INDICES)])
    var_type_map = VarTypeMap()
    var_type_map[sec] = VarType.CIPHER_SECONDARY_POLY

    expected = [
        Single(
            Var("c'", [Idx("j")]),
            [Term(Coeff("<epsilon>_{j}"))],
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        )
    ]

    received = analyze_singles(var_type_map, raw_singles)
    assert received == expected


def test_analyze_singles_invalid_expression():
    raw_singles = [
        RawSingle(
            Var("c'", [Idx("j")]),
            S.Infinity,
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    sec = Var("c'", [Idx("j")], [Quant("j", QSet.LINEAR_COMBINATION_INDICES)])
    var_type_map = VarTypeMap()
    var_type_map[sec] = VarType.CIPHER_SECONDARY_POLY

    with pytest.raises(SingleInvalidExpressionError):
        _ = analyze_singles(var_type_map, raw_singles)


def test_analyze_singles_unused_quants():
    raw_singles = [
        RawSingle(
            Var("c'", []),
            Integer(2),
            [Quant("j", QSet.USER_ATTRIBUTES)],
        ),
    ]

    sec = Var("c'", [])
    var_type_map = VarTypeMap()
    var_type_map[sec] = VarType.CIPHER_SECONDARY_POLY

    with pytest.raises(SingleUnusedQuantsError):
        _ = analyze_singles(var_type_map, raw_singles)


def test_analyze_singles_type_error():
    raw_singles = [
        RawSingle(
            Var("c'", [Idx("j", IMap.TO_ATTR)]),
            Add(Integer(1), Symbol("<epsilon>_{j}")),
            [Quant("j", QSet.ATTRIBUTE_UNIVERSE)],
        ),
    ]

    sec = Var("c'", [Idx("j", IMap.TO_ATTR)], [Quant("j", QSet.ATTRIBUTE_UNIVERSE)])
    var_type_map = VarTypeMap()
    var_type_map[sec] = VarType.CIPHER_SECONDARY_POLY

    with pytest.raises(SinglesTypeError):
        _ = analyze_singles(var_type_map, raw_singles)


def test_analyze_singles_illegal_special_var():
    raw_singles = [
        RawSingle(
            Var("c'", []),
            Add(Integer(1), Symbol("<secret>")),
            [],
        ),
    ]

    sec = Var("c'", [])
    var_type_map = VarTypeMap()
    var_type_map[sec] = VarType.CIPHER_SECONDARY_POLY

    with pytest.raises(SinglesIllegalSpecialVarError):
        _ = analyze_singles(var_type_map, raw_singles)


def test_analyze_singles_inconsistent_var_type():
    raw_singles = [
        RawSingle(
            Var("c'", [Idx("j")]),
            Symbol("<epsilon>_{j}"),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    sec = Var("c'", [Idx("j")], [Quant("j", QSet.LINEAR_COMBINATION_INDICES)])
    var_type_map = VarTypeMap()
    var_type_map[sec] = VarType.CIPHER_PRIMARY_POLY

    with pytest.raises(SingleInconsistentVarType):
        _ = analyze_singles(var_type_map, raw_singles)
