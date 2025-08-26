import pytest
from sympy import Add, Mul, S, Symbol

from pracy.analysis.errors import (
    PrimaryPolyIllegalQuantsError,
    PrimaryPolyIllegalSpecialVarError,
    PrimaryPolyInconsistentLoneRandomVarError,
    PrimaryPolyInconsistentNonLoneRandomVarError,
    PrimaryPolyInconsistentPolyError,
    PrimaryPolyInvalidBinaryTermError,
    PrimaryPolyInvalidExpressionError,
    PrimaryPolyInvalidTermError,
    PrimaryPolyInvalidUnaryTermError,
    PrimaryPolyIsSpecialError,
    PrimaryPolyNonUniqueError,
    PrimaryPolysEmptyError,
    PrimaryPolyTypeError,
    PrimaryPolyUnusedQuantsError,
)
from pracy.analysis.primary_cipher_poly import (
    PrimaryCipherPoly,
    analyze_primary_cipher_polys,
)
from pracy.analysis.variant import AbeVariant
from pracy.core.equiv import EquivSet
from pracy.core.group import Group, GroupMap
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.poly import Poly
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var


def test_analyze_primary_cipher_poly_ok():
    poly = Poly(
        "c",
        [Idx("1"), Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Add(
            Symbol("<mu>_{j}"),
            Mul(Symbol("s_{1,j}"), Symbol("b_{j.auth}")),
        ),
        Group.H,
    )

    name = "c"
    idcs = [Idx("1"), Idx("j")]
    quants = [Quant("j", QSet.LSSS_ROWS)]
    lone_random_terms = [PrimaryCipherPoly.LoneRandomTerm(Var("<mu>", [Idx("j")]))]
    common_terms_plain = [
        PrimaryCipherPoly.CommonTerm(
            Var("s", [Idx("1"), Idx("j")]),
            Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
        ),
    ]
    common_terms_hashed = []
    expected = [
        PrimaryCipherPoly(
            name,
            idcs,
            quants,
            Group.H,
            lone_random_terms,
            common_terms_plain,
            common_terms_hashed,
        )
    ]

    master_key_vars = []
    common_vars = [
        Var(
            "b",
            [Idx("j")],
            [Quant("j", QSet.AUTHORITIES)],
        ),
    ]
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()
    received = analyze_primary_cipher_polys(
        variant,
        var_type_map,
        group_map,
        cipher_lone_randoms,
        cipher_non_lone_randoms,
        [poly],
    )

    assert received == expected


def test_analyze_primary_cipher_poly_alternative_ok():
    poly = Poly(
        "c",
        [Idx("2"), Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Add(
            Mul(Symbol("s_{1,j}"), Symbol("b'_{j.auth}")),
            Mul(Symbol("s_{2,j.dedup}"), Symbol("b_{j.attr}")),
        ),
        Group.H,
    )

    name = "c"
    idcs = [Idx("2"), Idx("j")]
    quants = [Quant("j", QSet.LSSS_ROWS)]
    lone_random_terms = []
    common_terms_plain = [
        PrimaryCipherPoly.CommonTerm(
            Var("s", [Idx("1"), Idx("j")]),
            Var("b'", [Idx("j", IMap.TO_AUTHORITY)]),
        ),
        PrimaryCipherPoly.CommonTerm(
            Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
            Var("b", [Idx("j", IMap.TO_ATTR)]),
        ),
    ]
    common_terms_hashed = []
    expected = [
        PrimaryCipherPoly(
            name,
            idcs,
            quants,
            Group.H,
            lone_random_terms,
            common_terms_plain,
            common_terms_hashed,
        )
    ]

    master_key_vars = []
    common_vars = [
        Var(
            "b",
            [Idx("j")],
            [Quant("j", QSet.USER_ATTRIBUTES)],
        ),
        Var(
            "b'",
            [Idx("j")],
            [Quant("j", QSet.AUTHORITIES)],
        ),
    ]
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()
    received = analyze_primary_cipher_polys(
        variant,
        var_type_map,
        group_map,
        cipher_lone_randoms,
        cipher_non_lone_randoms,
        [poly],
    )

    assert received == expected


def test_analyze_primary_cipher_polys_empty():
    master_key_vars = []
    common_vars = []
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolysEmptyError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [],
        )


def test_analyze_primary_cipher_polys_invalid_expression():
    poly = Poly(
        "c",
        [Idx("2"), Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Mul(Symbol("s_{j}"), S.Infinity),
        Group.H,
    )
    master_key_vars = []
    common_vars = []
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyInvalidExpressionError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_type_error():
    poly = Poly(
        "c",
        [Idx("j")],
        [Quant("j", QSet.ATTRIBUTE_UNIVERSE)],
        Add(
            Mul(Symbol("s_{j.attr}"), Symbol("b_{j}")),
        ),
        Group.H,
    )
    master_key_vars = []
    common_vars = [Var("b", [Idx("j")], [Quant("j", QSet.ATTRIBUTE_UNIVERSE)])]
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyTypeError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_illegal_special_var():
    poly = Poly(
        "c",
        [Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Mul(Symbol("<epsilon>_{j}"), Symbol("s'_{0}")),
        Group.G,
    )
    master_key_vars = []
    common_vars = []
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyIllegalSpecialVarError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_poly_is_special():
    poly = Poly(
        "<rgid>",
        [Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Mul(Symbol("b_{j.lbl}"), Symbol("s'_{0}")),
        Group.G,
    )
    master_key_vars = []
    common_vars = [Var("b", [Idx("l")], [Quant("l", QSet.LABELS)])]
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyIsSpecialError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_invalid_unary_term_master_key_var():
    poly = Poly(
        "c",
        [Idx("2"), Idx("j")],
        [Quant("j", QSet.AUTHORITIES)],
        Symbol("alpha_{j}"),
        Group.H,
    )
    master_key_vars = [Var("alpha", [Idx("j")], [Quant("j", QSet.AUTHORITIES)])]
    common_vars = []
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyInvalidUnaryTermError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_invalid_unary_term_common_var():
    poly = Poly(
        "c",
        [Idx("j")],
        [Quant("j", QSet.LABELS)],
        Symbol("b_{j}"),
        Group.H,
    )
    master_key_vars = []
    common_vars = [Var("b", [Idx("j")], [Quant("j", QSet.LABELS)])]
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyInvalidUnaryTermError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_invalid_binary_term_no_common_var():
    poly = Poly(
        "c",
        [Idx("2"), Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Add(
            Mul(Symbol("s_{1,j}"), Symbol("s_{2}")),
        ),
        Group.G,
    )
    master_key_vars = []
    common_vars = []
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyInvalidBinaryTermError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_invalid_binary_term_two_common_vars():
    poly = Poly(
        "cipher_poly",
        [],
        [],
        Add(
            Mul(Symbol("b_{1}"), Symbol("b_{2}")),
        ),
        Group.G,
    )
    master_key_vars = []
    common_vars = [Var("b", [Idx("1")]), Var("b", [Idx("2")])]
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyInvalidBinaryTermError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_invalid_binary_term_master_key_var():
    poly = Poly(
        "c",
        [Idx("i")],
        [Quant("i", QSet.LSSS_ROWS)],
        Add(
            Mul(Symbol("alpha"), Symbol("b_{1}")),
        ),
        Group.H,
    )
    master_key_vars = [Var("alpha", [])]
    common_vars = [Var("b", [Idx("1")])]
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyInvalidBinaryTermError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_invalid_term():
    poly = Poly(
        "c",
        [Idx("2"), Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Mul(Symbol("<secret>"), Symbol("s_{1,j}"), Symbol("b'_{j.auth}")),
        Group.H,
    )
    master_key_vars = []
    common_vars = [
        Var("b'", [Idx("j")], [Quant("j", QSet.LSSS_ROWS, QMap.LSSS_ROW_TO_AUTHORITY)]),
    ]
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyInvalidTermError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_non_unique_equiv():
    poly_1 = Poly(
        "c",
        [],
        [],
        Symbol("s'_{1}"),
        Group.G,
    )
    poly_2 = Poly(
        "c",
        [],
        [],
        Symbol("s'_{1}"),
        Group.G,
    )
    master_key_vars = []
    common_vars = []
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyNonUniqueError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly_1, poly_2],
        )


def test_analyze_primary_cipher_polys_non_unique_sim():
    poly_1 = Poly(
        "c",
        [Idx("1")],
        [],
        Symbol("s'_{1}"),
        Group.G,
    )
    poly_2 = Poly(
        "c",
        [Idx("att")],
        [Quant("att", QSet.ATTRIBUTE_UNIVERSE)],
        Symbol("s'_{1}"),
        Group.G,
    )
    master_key_vars = []
    common_vars = []
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyNonUniqueError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly_1, poly_2],
        )


def test_analyze_primary_cipher_poly_unused_quants():
    poly = Poly(
        "c",
        [Idx("1")],
        [Quant("j", QSet.LSSS_ROWS)],
        Mul(Symbol("s_{1}"), Symbol("b'")),
        Group.H,
    )
    master_key_vars = []
    common_vars = [Var("b'", [])]
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyUnusedQuantsError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_illegal_quants():
    poly = Poly(
        "c",
        [Idx("2"), Idx("j")],
        [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        Mul(Symbol("s_{1,j}")),
        Group.H,
    )
    master_key_vars = []
    common_vars = []
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyIllegalQuantsError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_conflicting_var_type_poly():
    poly = Poly(
        "c",
        [Idx("2"), Idx("j", IMap.TO_AUTHORITY)],
        [Quant("j", QSet.POS_LSSS_ROWS)],
        Mul(Symbol("s_{1,j}")),
        Group.H,
    )
    master_key_vars = [
        Var("c", [Idx("2"), Idx("auth")], [Quant("auth", QSet.AUTHORITIES)])
    ]
    common_vars = []
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyInconsistentPolyError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_conflicting_var_type_lone_random():
    poly = Poly(
        "c",
        [Idx("2"), Idx("j")],
        [Quant("j", QSet.NEG_LSSS_ROWS)],
        Mul(Symbol("s_{1,j.auth}")),
        Group.H,
    )
    master_key_vars = []
    common_vars = []
    keygen_lone_randoms = [
        Var(
            "s",
            [Idx("1"), Idx("a", IMap.TO_AUTHORITY)],
            [Quant("a", QSet.USER_ATTRIBUTES)],
        )
    ]
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    for klr in keygen_lone_randoms:
        var_type_map[klr] = VarType.KEY_LONE_RANDOM_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyInconsistentLoneRandomVarError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly],
        )


def test_analyze_primary_cipher_polys_conflicting_var_type_non_lone_random():
    poly1 = Poly(
        "c",
        [Idx("1"), Idx("j")],
        [Quant("j", QSet.NEG_LSSS_ROWS)],
        Mul(Symbol("s_{1,j.auth}")),
        Group.H,
    )
    poly2 = Poly(
        "c",
        [Idx("2"), Idx("j")],
        [Quant("j", QSet.NEG_LSSS_ROWS)],
        Mul(Symbol("s_{1,j.auth}"), Symbol("b_{j.lbl}")),
        Group.H,
    )
    master_key_vars = []
    common_vars = [Var("b", [Idx("j")], [Quant("j", QSet.LABELS)])]
    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()
    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()

    with pytest.raises(PrimaryPolyInconsistentNonLoneRandomVarError):
        _ = analyze_primary_cipher_polys(
            variant,
            var_type_map,
            group_map,
            cipher_lone_randoms,
            cipher_non_lone_randoms,
            [poly1, poly2],
        )
