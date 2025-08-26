import pytest
from sympy import Add, Mul, S, Symbol

from pracy.analysis.blinding_poly import BlindingPoly, analyze_blinding_poly
from pracy.analysis.errors import (
    BlindingPolyAmbigiousError,
    BlindingPolyIllegalSpecialVarError,
    BlindingPolyInconsistentNonLoneRandomVarError,
    BlindingPolyInconsistentPolyError,
    BlindingPolyInconsistentSpecialLoneRandomVarError,
    BlindingPolyInvalidBinaryTermError,
    BlindingPolyInvalidExpressionError,
    BlindingPolyInvalidGroupError,
    BlindingPolyInvalidNameError,
    BlindingPolyInvalidTermError,
    BlindingPolyInvalidUnaryTermError,
    BlindingPolyIsIndexedError,
    BlindingPolyIsQuantifiedError,
    BlindingPolyIsSpecialError,
    BlindingPolyMissingError,
    BlindingPolyTypeError,
)
from pracy.analysis.keypoly import KeyPoly
from pracy.core.equiv import EquivSet
from pracy.core.group import Group
from pracy.core.idx import Idx
from pracy.core.poly import Poly
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var


def test_analyze_blinding_poly_ok():
    poly = Poly(
        "cm",
        [],
        [],
        Symbol("<secret>"),
        Group.GT,
    )

    name = "cm"
    idcs = []
    quants = []
    master_key_terms = []
    special_lone_random_terms = [
        BlindingPoly.SpecialLoneRandomTerm(Var("<secret>", []))
    ]
    expected = BlindingPoly(
        name, idcs, quants, Group.GT, special_lone_random_terms, master_key_terms
    )
    master_key_vars = []
    common_vars = []
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    received = analyze_blinding_poly(
        var_type_map, received_non_lone_randoms, received_special_lone_randoms, [poly]
    )

    assert received == expected


def test_analyze_blinding_poly_alternative_ok():
    poly = Poly(
        "cm",
        [],
        [],
        Add(Symbol("<secret>"), Mul(Symbol("alpha"), Symbol("s_{0}"))),
        Group.GT,
    )

    name = "cm"
    idcs = []
    quants = []
    master_key_terms = [
        BlindingPoly.MasterKeyTerm(Var("s", [Idx("0")]), Var("alpha", []))
    ]
    special_lone_random_terms = [
        BlindingPoly.SpecialLoneRandomTerm(Var("<secret>", []))
    ]
    expected = BlindingPoly(
        name, idcs, quants, Group.GT, special_lone_random_terms, master_key_terms
    )
    master_key_vars = [Var("alpha", [])]
    common_vars = []
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    received = analyze_blinding_poly(
        var_type_map, received_non_lone_randoms, received_special_lone_randoms, [poly]
    )

    assert received == expected


def test_analyze_blinding_poly_missing():
    master_key_vars = []
    common_vars = []
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyMissingError):
        _ = analyze_blinding_poly(
            var_type_map, received_non_lone_randoms, received_special_lone_randoms, []
        )


def test_analyze_blinding_poly_ambigious():
    poly_1 = Poly(
        "cm",
        [],
        [],
        Symbol("<secret>"),
        Group.GT,
    )
    poly_2 = Poly(
        "cm",
        [],
        [],
        Mul(Symbol("alpha"), Symbol("s_{1}")),
        Group.GT,
    )
    msk = Var("alpha", [])
    var_type_map = VarTypeMap()
    var_type_map[msk] = VarType.MASTER_KEY_VAR
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyAmbigiousError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly_1, poly_2],
        )


def test_analyze_blinding_poly_invalid_term():
    poly = Poly(
        "cm",
        [],
        [],
        Mul(Symbol("s_{0}"), Symbol("b"), Symbol("<secret>")),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyInvalidTermError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_invalid_unary_term():
    poly = Poly(
        "cm",
        [],
        [],
        Symbol("b"),
        Group.GT,
    )
    cv = Var("b", [])
    var_type_map = VarTypeMap()
    var_type_map[cv] = VarType.COMMON_VAR
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyInvalidUnaryTermError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_unvalid_binary_term():
    poly = Poly(
        "cm",
        [],
        [],
        Add(Symbol("<secret>"), Mul(Symbol("b"), Symbol("s_{0}"))),
        Group.GT,
    )
    cv = Var("b", [Idx("0")])
    var_type_map = VarTypeMap()
    var_type_map[cv] = VarType.COMMON_VAR
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyInvalidBinaryTermError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_is_quantified():
    poly = Poly(
        "cm",
        [Idx("auth")],
        [Quant("auth", QSet.AUTHORITIES)],
        Symbol("<secret>"),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyIsQuantifiedError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_is_indexed():
    poly = Poly(
        "cm",
        [Idx("1")],
        [],
        Symbol("<secret>"),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyIsIndexedError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_invalid_expression():
    poly = Poly(
        "cm",
        [],
        [],
        Mul(S.Infinity, Symbol("<secret>")),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyInvalidExpressionError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_invalid_group():
    poly = Poly(
        "cm",
        [],
        [],
        Symbol("<secret>"),
        Group.H,
    )
    var_type_map = VarTypeMap()
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyInvalidGroupError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_illegal_special_var():
    poly = Poly(
        "cm",
        [],
        [],
        Symbol("<epsilon>_{j}"),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyIllegalSpecialVarError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_is_special():
    poly = Poly(
        "<rgid>",
        [],
        [],
        Symbol("<epsilon>_{j}"),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyIsSpecialError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_invalid_name():
    poly = Poly(
        "cblind",
        [],
        [],
        Symbol("<lambda>_{j}"),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyInvalidNameError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_type_check():
    poly = Poly(
        "cm",
        [],
        [],
        Symbol("<lambda>_{j.auth}"),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyTypeError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_conflicting_var_type_non_lone_var():
    poly = Poly(
        "cm",
        [],
        [],
        Mul(Symbol("a"), Symbol("s_{1}")),
        Group.GT,
    )
    msk = Var("a", [])
    nlr = Var("s", [Idx("1")])
    var_type_map = VarTypeMap()
    var_type_map[msk] = VarType.MASTER_KEY_VAR
    var_type_map[nlr] = VarType.KEY_NON_LONE_RANDOM_VAR
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyInconsistentNonLoneRandomVarError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_conflicting_var_type_special_lone_var():
    poly = Poly(
        "cm",
        [],
        [],
        Mul(Symbol("s_{1}")),
        Group.GT,
    )
    kp = KeyPoly("s", [Idx("1")], [], Group.G, [], [], [], [], [])
    var_type_map = VarTypeMap()
    var_type_map[kp] = VarType.KEY_POLY
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyInconsistentSpecialLoneRandomVarError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )


def test_analyze_blinding_poly_conflicting_var_type_poly():
    poly = Poly(
        "cm",
        [],
        [],
        Mul(Symbol("s_{1}")),
        Group.GT,
    )
    msk = Var("cm", [])
    var_type_map = VarTypeMap()
    var_type_map[msk] = VarType.MASTER_KEY_VAR
    received_non_lone_randoms = EquivSet()
    received_special_lone_randoms = EquivSet()
    with pytest.raises(BlindingPolyInconsistentPolyError):
        _ = analyze_blinding_poly(
            var_type_map,
            received_non_lone_randoms,
            received_special_lone_randoms,
            [poly],
        )
