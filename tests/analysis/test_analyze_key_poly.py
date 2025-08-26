import pytest
from sympy import Add, Mul, S, Symbol

from pracy.analysis.errors import (
    KeyPolyIllegalQuantsError,
    KeyPolyIllegalSpecialVarError,
    KeyPolyInconsistentLoneRandomVar,
    KeyPolyInconsistentNonLoneRandomVar,
    KeyPolyInconsistentPoly,
    KeyPolyInvalidBinaryTermError,
    KeyPolyInvalidExpressionError,
    KeyPolyInvalidGroupError,
    KeyPolyInvalidTermError,
    KeyPolyInvalidUnaryTermError,
    KeyPolyIsSpecialError,
    KeyPolysEmptyError,
    KeyPolysNonUniqueError,
    KeyPolyTypeError,
    KeyPolyUncomputableTermError,
    KeyPolyUnusedQuantsError,
)
from pracy.analysis.keypoly import (
    KeyPoly,
    analyze_key_polys,
    post_analyze_key_polys,
)
from pracy.analysis.variant import AbeVariant
from pracy.core.equiv import EquivSet
from pracy.core.fdh import FdhMap
from pracy.core.group import Group, GroupMap
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.poly import Poly
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var


def test_analyze_key_polys_ok():
    poly = Poly(
        "k",
        [Idx("1"), Idx("l")],
        [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
        Add(
            Symbol("alpha_{l}"),
            Mul(Symbol("<rgid>"), Symbol("b_{l}")),
            Mul(Symbol("r_{l}"), Symbol("b'_{l}")),
        ),
        Group.G,
    )

    name = "k"
    idcs = [Idx("1"), Idx("l")]
    quants = [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)]
    master_key_terms = [KeyPoly.MasterKeyTerm(Var("alpha", [Idx("l")]))]
    lone_random_terms = []
    common_terms_plain = [
        KeyPoly.CommonTerm(Var("<rgid>", []), Var("b", [Idx("l")])),
        KeyPoly.CommonTerm(Var("r", [Idx("l")]), Var("b'", [Idx("l")])),
    ]
    common_terms_random_hashed = []
    common_terms_common_hashed = []
    expected_polys = [
        KeyPoly(
            name,
            idcs,
            quants,
            Group.G,
            master_key_terms,
            lone_random_terms,
            common_terms_plain,
            common_terms_random_hashed,
            common_terms_common_hashed,
        )
    ]
    expected_lone_randoms = []
    expected_non_lone_randoms = [
        Var(
            "r",
            [Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
        )
    ]
    master_key_vars = [Var("alpha", [Idx("l")], [Quant("l", QSet.AUTHORITIES)])]
    common_vars = [
        Var(
            "b",
            [Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
        ),
        Var(
            "b'",
            [Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
        ),
    ]

    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    group_map = GroupMap()

    received_lone_randoms = EquivSet()
    received_non_lone_randoms = EquivSet()
    received_polys = analyze_key_polys(
        variant,
        var_type_map,
        group_map,
        received_lone_randoms,
        received_non_lone_randoms,
        [poly],
    )

    assert received_polys == expected_polys
    assert list(received_lone_randoms) == expected_lone_randoms
    assert list(received_non_lone_randoms) == expected_non_lone_randoms


def test_analyze_key_polys_alternative_ok():
    poly = Poly(
        "k",
        [Idx("2"), Idx("att")],
        [Quant("att", QSet.USER_ATTRIBUTES)],
        Mul(Symbol("r_{att.auth}"), Symbol("b_{att}")),
        Group.G,
    )

    name = "k"
    idcs = [Idx("2"), Idx("att")]
    quants = [Quant("att", QSet.USER_ATTRIBUTES)]
    master_key_terms = []
    lone_random_terms = []
    common_terms_plain = [
        KeyPoly.CommonTerm(
            Var("r", [Idx("att", IMap.TO_AUTHORITY)]),
            Var("b", [Idx("att")]),
        ),
    ]
    common_terms_random_hashed = []
    common_terms_common_hashed = []
    expected_polys = [
        KeyPoly(
            name,
            idcs,
            quants,
            Group.G,
            master_key_terms,
            lone_random_terms,
            common_terms_plain,
            common_terms_random_hashed,
            common_terms_common_hashed,
        )
    ]
    expected_lone_randoms = []
    expected_non_lone_randoms = [
        Var("r", [Idx("att", IMap.TO_AUTHORITY)], [Quant("att", QSet.USER_ATTRIBUTES)])
    ]
    master_key_vars = []
    common_vars = [
        Var(
            "b",
            [Idx("att")],
            [Quant("att", QSet.ATTRIBUTE_UNIVERSE)],
        ),
    ]

    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    group_map = GroupMap()

    received_lone_randoms = EquivSet()
    received_non_lone_randoms = EquivSet()
    received_polys = analyze_key_polys(
        variant,
        var_type_map,
        group_map,
        received_lone_randoms,
        received_non_lone_randoms,
        [poly],
    )

    assert received_polys == expected_polys
    assert list(received_lone_randoms) == expected_lone_randoms
    assert list(received_non_lone_randoms) == expected_non_lone_randoms


def test_post_analyze_key_polys_ok():
    name = "k"
    idcs = [Idx("1"), Idx("l")]
    quants = [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)]
    master_key_terms = [KeyPoly.MasterKeyTerm(Var("alpha", [Idx("l")]))]
    lone_random_terms = []
    common_terms_plain = [
        KeyPoly.CommonTerm(Var("r", []), Var("b", [Idx("l")])),
        KeyPoly.CommonTerm(Var("r", [Idx("l")]), Var("b'", [Idx("l")])),
    ]
    common_terms_random_hashed = []
    common_terms_common_hashed = []
    key_polys = [
        KeyPoly(
            name,
            idcs,
            quants,
            Group.G,
            master_key_terms,
            lone_random_terms,
            common_terms_plain,
            common_terms_random_hashed,
            common_terms_common_hashed,
        )
    ]

    common_terms_plain = [
        KeyPoly.CommonTerm(Var("r", []), Var("b", [Idx("l")])),
    ]
    common_terms_common_hashed = [
        KeyPoly.CommonTerm(Var("r", [Idx("l")]), Var("b'", [Idx("l")])),
    ]
    expected = [
        KeyPoly(
            name,
            idcs,
            quants,
            Group.G,
            master_key_terms,
            lone_random_terms,
            common_terms_plain,
            common_terms_random_hashed,
            common_terms_common_hashed,
        )
    ]

    common_var = Var(
        "b'",
        [Idx("l")],
        [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
    )
    fdh_map = FdhMap()
    fdh_map[common_var] = 4

    received = post_analyze_key_polys(key_polys, fdh_map)

    assert received == expected


def test_post_analyze_key_polys__rgid_ok():
    name = "k"
    idcs = [Idx("1"), Idx("l")]
    quants = [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)]
    master_key_terms = [KeyPoly.MasterKeyTerm(Var("alpha", [Idx("l")]))]
    lone_random_terms = []
    common_terms_plain = [
        KeyPoly.CommonTerm(Var("<rgid>", []), Var("b", [Idx("l")])),
        KeyPoly.CommonTerm(Var("r", [Idx("l")]), Var("b'", [Idx("l")])),
    ]
    common_terms_random_hashed = []
    common_terms_common_hashed = []
    key_polys = [
        KeyPoly(
            name,
            idcs,
            quants,
            Group.G,
            master_key_terms,
            lone_random_terms,
            common_terms_plain,
            common_terms_random_hashed,
            common_terms_common_hashed,
        )
    ]

    common_terms_plain = []
    common_terms_common_hashed = [
        KeyPoly.CommonTerm(Var("r", [Idx("l")]), Var("b'", [Idx("l")])),
    ]
    common_terms_random_hashed = [
        KeyPoly.CommonTerm(Var("<rgid>", []), Var("b", [Idx("l")])),
    ]
    expected = [
        KeyPoly(
            name,
            idcs,
            quants,
            Group.G,
            master_key_terms,
            lone_random_terms,
            common_terms_plain,
            common_terms_random_hashed,
            common_terms_common_hashed,
        )
    ]

    common_var = Var(
        "b'",
        [Idx("l")],
        [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
    )
    fdh_map = FdhMap()
    fdh_map[common_var] = 4

    received = post_analyze_key_polys(key_polys, fdh_map)

    assert received == expected


def test_post_analyze_key_polys_alternative_ok():
    name = "k"
    idcs = [Idx("1"), Idx("l")]
    quants = [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)]
    master_key_terms = [KeyPoly.MasterKeyTerm(Var("alpha", [Idx("l")]))]
    lone_random_terms = []
    common_terms_plain = [
        KeyPoly.CommonTerm(Var("r", []), Var("b", [Idx("l")])),
        KeyPoly.CommonTerm(Var("r", [Idx("l")]), Var("b'", [Idx("l")])),
    ]
    common_terms_random_hashed = []
    common_terms_common_hashed = []
    key_polys = [
        KeyPoly(
            name,
            idcs,
            quants,
            Group.G,
            master_key_terms,
            lone_random_terms,
            common_terms_plain,
            common_terms_random_hashed,
            common_terms_common_hashed,
        )
    ]

    expected = [
        KeyPoly(
            name,
            idcs,
            quants,
            Group.G,
            master_key_terms,
            lone_random_terms,
            common_terms_plain,
            common_terms_random_hashed,
            common_terms_common_hashed,
        )
    ]

    fdh_map = FdhMap()
    received = post_analyze_key_polys(key_polys, fdh_map)

    assert received == expected


def test_analyze_key_polys_invalid_term():
    poly = Poly(
        "k",
        [Idx("att")],
        [Quant("att", QSet.USER_ATTRIBUTES)],
        Add(
            Mul(Symbol("<rgid>"), Symbol("r_{att}"), Symbol("b_{att}")),
        ),
        Group.G,
    )

    master_key_vars = []
    common_vars = [
        Var(
            "b",
            [Idx("attr")],
            [Quant("attr", QSet.USER_ATTRIBUTES)],
        ),
    ]

    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    group_map = GroupMap()
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyInvalidTermError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly],
        )


def test_post_analyze_key_polys_uncomputable_term():
    name = "k"
    idcs = [Idx("1")]
    quants = []
    master_key_terms = []
    lone_random_terms = []
    common_terms_plain = [
        KeyPoly.CommonTerm(Var("r", []), Var("b", [])),
    ]
    common_terms_random_hashed = []
    common_terms_common_hashed = []
    key_polys = [
        KeyPoly(
            name,
            idcs,
            quants,
            Group.G,
            master_key_terms,
            lone_random_terms,
            common_terms_plain,
            common_terms_random_hashed,
            common_terms_common_hashed,
        )
    ]

    common_var = Var("b", [])
    non_lone_random_var = Var("r", [])
    fdh_map = FdhMap()
    fdh_map[common_var] = 4
    fdh_map[non_lone_random_var] = 5

    with pytest.raises(KeyPolyUncomputableTermError):
        _ = post_analyze_key_polys(key_polys, fdh_map)


def test_post_analyze_key_polys_rgid_uncomputable_term():
    name = "k"
    idcs = []
    quants = []
    master_key_terms = []
    lone_random_terms = []
    common_terms_plain = [
        KeyPoly.CommonTerm(Var("<rgid>", []), Var("b", [])),
    ]
    common_terms_random_hashed = []
    common_terms_common_hashed = []
    key_polys = [
        KeyPoly(
            name,
            idcs,
            quants,
            Group.G,
            master_key_terms,
            lone_random_terms,
            common_terms_plain,
            common_terms_random_hashed,
            common_terms_common_hashed,
        )
    ]

    common_var = Var("b", [])
    fdh_map = FdhMap()
    fdh_map[common_var] = 4

    with pytest.raises(KeyPolyUncomputableTermError):
        _ = post_analyze_key_polys(key_polys, fdh_map)


def test_analyze_key_polys_invalid_unary_term():
    poly = Poly(
        "k",
        [Idx("j")],
        [Quant("j", QSet.ATTRIBUTE_UNIVERSE)],
        Symbol("r_{j}"),
        Group.G,
    )

    master_key_vars = []
    common_vars = [Var("r", [Idx("j")], [Quant("j", QSet.ATTRIBUTE_UNIVERSE)])]

    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    group_map = GroupMap()
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyInvalidUnaryTermError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly],
        )


def test_analyze_key_polys_duplicate_common_var():
    poly = Poly(
        "k",
        [Idx("att")],
        [Quant("att", QSet.USER_ATTRIBUTES)],
        Add(
            Mul(Symbol("b'"), Symbol("b_{att}")),
        ),
        Group.H,
    )

    master_key_vars = []
    common_vars = [
        Var(
            "b",
            [Idx("attr")],
            [Quant("attr", QSet.USER_ATTRIBUTES)],
        ),
        Var("b'", []),
    ]

    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    group_map = GroupMap()
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyInvalidBinaryTermError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly],
        )


def test_analyze_key_polys_no_common_var_binary_term():
    poly = Poly(
        "k",
        [Idx("att")],
        [Quant("att", QSet.USER_ATTRIBUTES)],
        Add(
            Mul(Symbol("b'"), Symbol("b_{att}")),
        ),
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
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyInvalidBinaryTermError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly],
        )


def test_analyze_key_polys_duplicate_polys_sim():
    poly_1 = Poly(
        "k",
        [Idx("lbl")],
        [Quant("lbl", QSet.LABELS)],
        Symbol("x"),
        Group.H,
    )

    poly_2 = Poly(
        "k",
        [Idx("att")],
        [Quant("att", QSet.USER_ATTRIBUTES)],
        Symbol("y"),
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
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolysNonUniqueError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly_1, poly_2],
        )


def test_analyze_key_polys_duplicate_polys_equiv():
    poly_1 = Poly(
        "k",
        [Idx("att")],
        [Quant("att", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
        Symbol("x"),
        Group.H,
    )

    poly_2 = Poly(
        "k",
        [Idx("att", IMap.TO_AUTHORITY)],
        [Quant("att", QSet.USER_ATTRIBUTES)],
        Symbol("y"),
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
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolysNonUniqueError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly_1, poly_2],
        )


def test_analyze_key_polys_invalid_group():
    poly = Poly(
        "k",
        [Idx("att")],
        [Quant("att", QSet.USER_ATTRIBUTES)],
        Add(
            Mul(Symbol("b'"), Symbol("b_{att}")),
        ),
        Group.GT,
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
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyInvalidGroupError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly],
        )


def test_analyze_key_polys_empty():
    master_key_vars = []
    common_vars = []

    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    group_map = GroupMap()
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolysEmptyError):
        _ = analyze_key_polys(
            variant, var_type_map, group_map, key_lone_randoms, key_non_lone_randoms, []
        )


def test_analyze_key_polys_illegal_special_var():
    poly = Poly(
        "k",
        [Idx("att")],
        [Quant("att", QSet.USER_ATTRIBUTES)],
        Add(
            Mul(Symbol("<secret>"), Symbol("b_{att}")),
        ),
        Group.H,
    )

    master_key_vars = []
    common_vars = [
        Var(
            "b",
            [Idx("attr")],
            [Quant("attr", QSet.USER_ATTRIBUTES)],
        ),
    ]

    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    group_map = GroupMap()
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyIllegalSpecialVarError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly],
        )


def test_analyze_key_polys_type_error():
    poly = Poly(
        "k",
        [Idx("lbl", IMap.TO_LABEL)],
        [Quant("lbl", QSet.LABELS)],
        Add(
            Mul(Symbol("r"), Symbol("b")),
        ),
        Group.H,
    )

    master_key_vars = []
    common_vars = [Var("b", [])]

    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    group_map = GroupMap()
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyTypeError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly],
        )


def test_analyze_key_polys_invalid_expression():
    poly = Poly(
        "k",
        [Idx("lbl")],
        [Quant("lbl", QSet.LABELS)],
        Add(Mul(Symbol("r"), Symbol("b_{lbl}")), S.Infinity),
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
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyInvalidExpressionError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly],
        )


def test_analyze_key_polys_unused_quants():
    poly = Poly(
        "k",
        [Idx("att")],
        [Quant("i", QSet.ATTRIBUTE_UNIVERSE)],
        Add(
            Symbol("r_{1}"),
            Mul(Symbol("r"), Symbol("b_{att}")),
        ),
        Group.G,
    )

    master_key_vars = []
    common_vars = [Var("b", [Idx("att")])]

    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    group_map = GroupMap()
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyUnusedQuantsError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly],
        )


def test_analyze_key_polys_illegal_quants():
    poly = Poly(
        "k",
        [Idx("j")],
        [Quant("j", QSet.LSSS_ROWS)],
        Symbol("r_{j}"),
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
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyIllegalQuantsError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly],
        )


def test_analyze_key_poly_conflicting_var_type_poly():
    poly = Poly(
        "k",
        [Idx("j")],
        [Quant("j", QSet.USER_ATTRIBUTES)],
        Symbol("r_{j}"),
        Group.G,
    )

    master_key_vars = []
    common_vars = [Var("k", [Idx("att")], [Quant("att", QSet.ATTRIBUTE_UNIVERSE)])]

    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    group_map = GroupMap()
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyInconsistentPoly):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly],
        )


def test_analyze_key_poly_conflicting_var_type_lone_var():
    poly1 = Poly(
        "k",
        [Idx("j")],
        [Quant("j", QSet.USER_ATTRIBUTES)],
        Symbol("r_{j}"),
        Group.G,
    )
    poly2 = Poly(
        "k",
        [Idx("1"), Idx("j")],
        [Quant("j", QSet.USER_ATTRIBUTES)],
        Symbol("k_{j}"),
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
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyInconsistentLoneRandomVar):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly1, poly2],
        )


def test_analyze_key_poly_conflicting_var_type_non_lone_var():
    poly1 = Poly(
        "k",
        [Idx("j")],
        [Quant("j", QSet.USER_ATTRIBUTES)],
        Symbol("r_{j}"),
        Group.G,
    )
    poly2 = Poly(
        "k",
        [Idx("1"), Idx("j")],
        [Quant("j", QSet.USER_ATTRIBUTES)],
        Mul(Symbol("k_{j}"), Symbol("b_{j.auth}")),
        Group.H,
    )

    master_key_vars = []
    common_vars = [Var("b", [Idx("auth")], [Quant("auth", QSet.AUTHORITIES)])]

    variant = AbeVariant.CP_ABE
    var_type_map = VarTypeMap()
    for msk in master_key_vars:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    group_map = GroupMap()
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyInconsistentNonLoneRandomVar):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly1, poly2],
        )


def test_analyze_key_poly_is_special_var():
    poly = Poly(
        "<rgid>",
        [],
        [],
        Symbol("r_{j}"),
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
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()

    with pytest.raises(KeyPolyIsSpecialError):
        _ = analyze_key_polys(
            variant,
            var_type_map,
            group_map,
            key_lone_randoms,
            key_non_lone_randoms,
            [poly],
        )
