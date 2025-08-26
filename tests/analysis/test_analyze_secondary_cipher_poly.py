import pytest
from sympy import Add, Mul, S, Symbol

from pracy.analysis.errors import (
    SecondaryPolyIllegalQuantsError,
    SecondaryPolyIllegalSpecialVarError,
    SecondaryPolyInconsistentNonLoneRandomVarError,
    SecondaryPolyInconsistentPolyError,
    SecondaryPolyInconsistentSpecialLoneRandomVarError,
    SecondaryPolyInvalidBinaryTermError,
    SecondaryPolyInvalidExpressionError,
    SecondaryPolyInvalidGroupError,
    SecondaryPolyInvalidNameError,
    SecondaryPolyInvalidTermError,
    SecondaryPolyInvalidUnaryTermError,
    SecondaryPolyIsSpecialError,
    SecondaryPolyNonUniqueError,
    SecondaryPolyTypeError,
    SecondaryPolyUnusedQuantsError,
)
from pracy.analysis.secondary_cipher_poly import (
    SecondaryCipherPoly,
    analyze_secondary_cipher_polys,
)
from pracy.analysis.variant import AbeVariant
from pracy.core.equiv import EquivSet
from pracy.core.group import Group
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.poly import Poly
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var


def test_analyze_secondary_cipher_poly_ok():
    poly = Poly(
        "c'",
        [Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Add(
            Symbol("<lambda>_{j}"),
            Mul(Symbol("alpha_{j.auth}"), Symbol("s_{1,j}")),
        ),
        Group.GT,
    )

    name = "c'"
    idcs = [Idx("j")]
    quants = [Quant("j", QSet.LSSS_ROWS)]
    master_key_terms = [
        SecondaryCipherPoly.MasterKeyTerm(
            Var("s", [Idx("1"), Idx("j")]),
            Var("alpha", [Idx("j", IMap.TO_AUTHORITY)]),
        ),
    ]
    special_lone_random_terms = [
        SecondaryCipherPoly.SpecialLoneRandomTerm(Var("<lambda>", [Idx("j")]))
    ]
    expected = [
        SecondaryCipherPoly(
            name, idcs, quants, Group.GT, master_key_terms, special_lone_random_terms
        )
    ]

    master_key_vars = [
        Var(
            "alpha",
            [Idx("j")],
            [Quant("j", QSet.AUTHORITIES)],
        ),
    ]
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    received = analyze_secondary_cipher_polys(
        AbeVariant.CP_ABE,
        var_type_map,
        cipher_non_lone_randoms,
        cipher_special_lone_randoms,
        [poly],
    )

    assert received == expected


def test_analyze_secondary_cipher_polys_invalid_expression():
    poly = Poly(
        "c'",
        [Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Mul(S.Infinity, Symbol("alpha_{ls_row_j.auth}")),
        Group.GT,
    )
    master_key_vars = [
        Var(
            "alpha",
            [Idx("j")],
            [Quant("j", QSet.AUTHORITIES)],
        ),
    ]
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyInvalidExpressionError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_polys_type_error():
    poly = Poly(
        "c'",
        [Idx("j", IMap.TO_AUTHORITY)],
        [Quant("j", QSet.AUTHORITIES)],
        Symbol("<lambda>_{j}"),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyTypeError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_polys_is_special():
    poly = Poly(
        "<lambda>",
        [Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Symbol("s_{1}"),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyIsSpecialError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_polys_illegal_special_var():
    poly = Poly(
        "c",
        [Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Symbol("<epsilon>_{j}"),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyIllegalSpecialVarError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_polys_invalid_unary_term():
    poly = Poly(
        "c'",
        [Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Symbol("b_{j.auth}"),
        Group.GT,
    )
    cv = Var("b", [Idx("i")], [Quant("i", QSet.LSSS_ROWS, QMap.LSSS_ROW_TO_AUTHORITY)])
    var_type_map = VarTypeMap()
    var_type_map[cv] = VarType.COMMON_VAR
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyInvalidUnaryTermError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_polys_invalid_binary_term():
    poly = Poly(
        "c",
        [Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Add(
            Symbol("<lambda>_{j}"),
            Mul(Symbol("alpha"), Symbol("b_{1, j.auth}")),
        ),
        Group.GT,
    )
    msk = Var("alpha", [])
    cv = Var("b", [Idx("1"), Idx("i")], [Quant("i", QSet.AUTHORITIES)])
    var_type_map = VarTypeMap()
    var_type_map[msk] = VarType.MASTER_KEY_VAR
    var_type_map[cv] = VarType.COMMON_VAR
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyInvalidBinaryTermError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_polys_invalid_term():
    poly = Poly(
        "c'",
        [Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Mul(
            Symbol("<lambda>_{j}"),
            Symbol("alpha_{j.auth}"),
            Symbol("s_{1,j}"),
        ),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyInvalidTermError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_polys_non_unique_equiv():
    poly_1 = Poly(
        "c",
        [Idx("i")],
        [Quant("i", QSet.LSSS_ROWS, QMap.LSSS_ROW_TO_DEDUP_INDICES)],
        Symbol("<lambda>_{i}"),
        Group.GT,
    )
    poly_2 = Poly(
        "c",
        [Idx("j", IMap.TO_DEDUP_INDICES)],
        [Quant("j", QSet.LSSS_ROWS)],
        Add(
            Symbol("<lambda>_{j}"),
            Mul(Symbol("s_{1}"), Symbol("alpha_{1, j.auth}")),
        ),
        Group.GT,
    )
    msk = Var("alpha", [Idx("1"), Idx("j")], [Quant("j", QSet.AUTHORITIES)])
    var_type_map = VarTypeMap()
    var_type_map[msk] = VarType.MASTER_KEY_VAR
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyNonUniqueError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly_1, poly_2],
        )


def test_analyze_secondary_cipher_polys_non_unique_sim():
    poly_1 = Poly(
        "c",
        [Idx("i")],
        [],
        Symbol("s_{1}"),
        Group.GT,
    )
    poly_2 = Poly(
        "c",
        [Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Symbol("<lambda>_{j}"),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyNonUniqueError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly_1, poly_2],
        )


def test_analyze_secondary_cipher_polys_unused_quants():
    poly = Poly(
        "c",
        [Idx("j")],
        [Quant("j", QSet.LSSS_ROWS), Quant("i", QSet.ATTRIBUTE_UNIVERSE)],
        Symbol("<lambda>_{j}"),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyUnusedQuantsError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_polys_illegal_quants():
    poly = Poly(
        "c",
        [Idx("j")],
        [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        Mul(Symbol("alpha_{j.auth}"), Symbol("s_{1,j}")),
        Group.GT,
    )
    master_key_vars = [
        Var(
            "alpha",
            [Idx("j")],
            [Quant("j", QSet.AUTHORITIES)],
        )
    ]
    var_type_map = VarTypeMap()
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyIllegalQuantsError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_poly_illegal_group():
    poly = Poly(
        "c'",
        [Idx("j")],
        [Quant("j", QSet.AUTHORITIES)],
        Symbol("<lambda>_{j}"),
        Group.G,
    )
    var_type_map = VarTypeMap()
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyInvalidGroupError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_poly_invalid_name():
    poly = Poly(
        "cm",
        [Idx("j")],
        [Quant("j", QSet.AUTHORITIES)],
        Symbol("<lambda>_{j}"),
        Group.GT,
    )
    var_type_map = VarTypeMap()
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyInvalidNameError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_polys_conflicting_var_type_non_lone_random():
    poly = Poly(
        "c",
        [Idx("1"), Idx("j")],
        [Quant("j", QSet.AUTHORITIES)],
        Mul(Symbol("s_{j}"), Symbol("a")),
        Group.GT,
    )
    msk = Var("a", [])
    klr = Var("s", [Idx("x", IMap.TO_AUTHORITY)], [Quant("x", QSet.USER_ATTRIBUTES)])
    var_type_map = VarTypeMap()
    var_type_map[msk] = VarType.MASTER_KEY_VAR
    var_type_map[klr] = VarType.KEY_LONE_RANDOM_VAR
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyInconsistentNonLoneRandomVarError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_polys_conflicting_var_type_special_lone_random():
    poly = Poly(
        "c",
        [Idx("1"), Idx("j")],
        [Quant("j", QSet.AUTHORITIES)],
        Symbol("s_{j}"),
        Group.GT,
    )
    klr = Var("s", [Idx("x", IMap.TO_AUTHORITY)], [Quant("x", QSet.USER_ATTRIBUTES)])
    var_type_map = VarTypeMap()
    var_type_map[klr] = VarType.KEY_LONE_RANDOM_VAR

    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyInconsistentSpecialLoneRandomVarError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )


def test_analyze_secondary_cipher_polys_conflicting_var_type_poly():
    poly = Poly(
        "c",
        [Idx("1"), Idx("j")],
        [Quant("j", QSet.AUTHORITIES)],
        Mul(Symbol("s_{j}"), Symbol("a")),
        Group.GT,
    )
    msk = Var("a", [])
    prim = Var(
        "c",
        [Idx("1"), Idx("x", IMap.TO_AUTHORITY)],
        [Quant("x", QSet.ATTRIBUTE_UNIVERSE)],
    )
    var_type_map = VarTypeMap()
    var_type_map[msk] = VarType.MASTER_KEY_VAR
    var_type_map[prim] = VarType.CIPHER_PRIMARY_POLY
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    with pytest.raises(SecondaryPolyInconsistentPolyError):
        _ = analyze_secondary_cipher_polys(
            AbeVariant.CP_ABE,
            var_type_map,
            cipher_non_lone_randoms,
            cipher_special_lone_randoms,
            [poly],
        )
