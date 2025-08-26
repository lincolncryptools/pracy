import pytest
from sympy import Add, Integer, Mul, S, Symbol

from pracy.analysis.errors import (
    PairIllegalGroupCombination,
    PairInconsistentVarTypeError,
    PairInvalidExpressionError,
    PairsIllegalSpecialVarError,
    PairsTypeError,
    PairUnusedQuantsError,
)
from pracy.analysis.expr import Coeff, Term
from pracy.analysis.pair import Pair, analyze_pairs
from pracy.core.group import Group, GroupMap
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var
from pracy.frontend.raw_scheme import RawPair


def test_analyze_pairs_ok():
    raw_pairs = [
        RawPair(
            Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
            Var("k", [Idx("2"), Idx("j", IMap.TO_ATTR)]),
            Symbol("<epsilon>_{j}"),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    arg1 = Var(
        "s",
        [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)],
        [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
    )
    arg2 = Var(
        "k",
        [Idx("2"), Idx("j", IMap.TO_ATTR)],
        [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
    )
    var_type_map = VarTypeMap()
    var_type_map[arg1] = VarType.CIPHER_NON_LONE_RANDOM
    var_type_map[arg2] = VarType.KEY_POLY

    group_map = GroupMap()
    group_map[arg1] = Group.H
    group_map[arg2] = Group.G

    expected = [
        Pair(
            Var("k", [Idx("2"), Idx("j", IMap.TO_ATTR)]),
            Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
            [Term(Coeff("<epsilon>_{j}"))],
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        )
    ]

    received = analyze_pairs(var_type_map, group_map, raw_pairs)
    assert received == expected


def test_analyze_pairs_special_vars_ok():
    raw_pairs = [
        RawPair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("<rgid>", []),
            Symbol("<epsilon>_{j}"),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    arg1 = Var(
        "c",
        [Idx("1"), Idx("j")],
        [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
    )
    arg2 = Var(
        "<rgid>",
        [],
    )
    var_type_map = VarTypeMap()
    var_type_map[arg1] = VarType.CIPHER_PRIMARY_POLY
    var_type_map[arg2] = VarType.KEY_NON_LONE_RANDOM_VAR

    group_map = GroupMap()
    group_map[arg1] = Group.G
    group_map[arg2] = Group.H

    expected = [
        Pair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("<rgid>", []),
            [Term(Coeff("<epsilon>_{j}"))],
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        )
    ]

    received = analyze_pairs(var_type_map, group_map, raw_pairs)
    assert received == expected


def test_analyze_pairs_unused_quants():
    raw_pairs = [
        RawPair(
            Var("c", [Idx("1")]),
            Var("<rgid>", []),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    arg1 = Var(
        "c",
        [Idx("1")],
        [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
    )
    arg2 = Var(
        "<rgid>",
        [],
    )
    var_type_map = VarTypeMap()
    var_type_map[arg1] = VarType.CIPHER_PRIMARY_POLY
    var_type_map[arg2] = VarType.KEY_NON_LONE_RANDOM_VAR

    group_map = GroupMap()
    group_map[arg1] = Group.G
    group_map[arg2] = Group.H

    with pytest.raises(PairUnusedQuantsError):
        _ = analyze_pairs(var_type_map, group_map, raw_pairs)


def test_analyze_pairs_type_error():
    raw_pairs = [
        RawPair(
            Var("s", [Idx("1"), Idx("j")]),
            Var("k", [Idx("1"), Idx("j", IMap.TO_AUTHORITY)]),
            Add(Integer(0), Mul(Integer(-1), Symbol("<epsilon>_{j}"))),
            [Quant("j", QSet.AUTHORITIES)],
        ),
    ]

    arg1 = Var(
        "s",
        [Idx("1"), Idx("j")],
        [Quant("j", QSet.AUTHORITIES)],
    )
    arg2 = Var(
        "k",
        [Idx("1"), Idx("j", IMap.TO_AUTHORITY)],
        [Quant("j", QSet.AUTHORITIES)],
    )
    var_type_map = VarTypeMap()
    var_type_map[arg1] = VarType.CIPHER_NON_LONE_RANDOM
    var_type_map[arg2] = VarType.KEY_POLY

    group_map = GroupMap()
    group_map[arg1] = Group.H
    group_map[arg2] = Group.G

    with pytest.raises(PairsTypeError):
        _ = analyze_pairs(var_type_map, group_map, raw_pairs)


def test_analyze_pairs_illegal_special_var():
    raw_pairs = [
        RawPair(
            Var("<lambda>", []),
            Var("k", [Idx("1"), Idx("j")]),
            Integer(1),
            [Quant("j", QSet.POS_LINEAR_COMBINATION_INDICES)],
        ),
    ]

    arg1 = Var(
        "<lambda>",
        [],
    )
    arg2 = Var(
        "k",
        [Idx("1"), Idx("j")],
        [Quant("j", QSet.POS_LINEAR_COMBINATION_INDICES)],
    )
    var_type_map = VarTypeMap()
    var_type_map[arg1] = VarType.CIPHER_NON_LONE_RANDOM
    var_type_map[arg2] = VarType.KEY_POLY

    group_map = GroupMap()
    group_map[arg1] = Group.H
    group_map[arg2] = Group.G

    with pytest.raises(PairsIllegalSpecialVarError):
        _ = analyze_pairs(var_type_map, group_map, raw_pairs)


def test_analyze_pairs_inconsistent_var_types():
    raw_pairs = [
        RawPair(
            Var("s", [Idx("2"), Idx("j")]),
            Var("k", [Idx("2"), Idx("j")]),
            Symbol("<epsilon>_{j}"),
            [Quant("j", QSet.NEG_LSSS_ROWS)],
        ),
    ]

    arg1 = Var(
        "s",
        [Idx("2"), Idx("j")],
        [Quant("j", QSet.NEG_LSSS_ROWS)],
    )
    arg2 = Var(
        "k",
        [Idx("2"), Idx("j")],
        [Quant("j", QSet.NEG_LSSS_ROWS)],
    )
    var_type_map = VarTypeMap()
    var_type_map[arg1] = VarType.CIPHER_PRIMARY_POLY
    var_type_map[arg2] = VarType.KEY_POLY

    group_map = GroupMap()
    group_map[arg1] = Group.H
    group_map[arg2] = Group.G

    with pytest.raises(PairInconsistentVarTypeError):
        _ = analyze_pairs(var_type_map, group_map, raw_pairs)


def test_analyze_pairs_invalid_expression():
    raw_pairs = [
        RawPair(
            Var("s", [Idx("2"), Idx("j")]),
            Var("k", [Idx("2"), Idx("j")]),
            S.Infinity,
            [Quant("j", QSet.NEG_LSSS_ROWS)],
        ),
    ]

    arg1 = Var(
        "s",
        [Idx("2"), Idx("j")],
        [Quant("j", QSet.NEG_LSSS_ROWS)],
    )
    arg2 = Var(
        "k",
        [Idx("2"), Idx("j")],
        [Quant("j", QSet.NEG_LSSS_ROWS)],
    )
    var_type_map = VarTypeMap()
    var_type_map[arg1] = VarType.CIPHER_PRIMARY_POLY
    var_type_map[arg2] = VarType.KEY_NON_LONE_RANDOM_VAR

    group_map = GroupMap()
    group_map[arg1] = Group.H
    group_map[arg2] = Group.G

    with pytest.raises(PairInvalidExpressionError):
        _ = analyze_pairs(var_type_map, group_map, raw_pairs)


def test_analyze_pairs_illegal_group_combination():
    raw_pairs = [
        RawPair(
            Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
            Var("k", [Idx("2"), Idx("j", IMap.TO_ATTR)]),
            Symbol("<epsilon>_{j}"),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    arg1 = Var(
        "s",
        [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)],
        [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
    )
    arg2 = Var(
        "k",
        [Idx("2"), Idx("j", IMap.TO_ATTR)],
        [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
    )
    var_type_map = VarTypeMap()
    var_type_map[arg1] = VarType.CIPHER_NON_LONE_RANDOM
    var_type_map[arg2] = VarType.KEY_POLY

    group_map = GroupMap()
    group_map[arg1] = Group.G
    group_map[arg2] = Group.G

    with pytest.raises(PairIllegalGroupCombination):
        _ = analyze_pairs(var_type_map, group_map, raw_pairs)


def test_analyze_pairs_illegal_group_combination_rgid():
    raw_pairs = [
        RawPair(
            Var("<rgid>", []),
            Var("c", [Idx("j")]),
            Symbol("<epsilon>_{j}"),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    arg1 = Var("<rgid>", [])
    arg2 = Var(
        "c",
        [Idx("j")],
        [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
    )
    var_type_map = VarTypeMap()
    var_type_map[arg1] = VarType.KEY_NON_LONE_RANDOM_VAR
    var_type_map[arg2] = VarType.CIPHER_PRIMARY_POLY

    group_map = GroupMap()
    group_map[arg1] = Group.G
    group_map[arg2] = Group.G

    with pytest.raises(PairIllegalGroupCombination):
        _ = analyze_pairs(var_type_map, group_map, raw_pairs)
