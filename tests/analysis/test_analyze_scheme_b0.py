from pracy.analysis.blinding_poly import BlindingPoly
from pracy.analysis.expr import Coeff, Term
from pracy.analysis.keypoly import KeyPoly
from pracy.analysis.pair import Pair
from pracy.analysis.primary_cipher_poly import PrimaryCipherPoly
from pracy.analysis.scheme import Scheme, analyze_scheme
from pracy.analysis.secondary_cipher_poly import SecondaryCipherPoly
from pracy.analysis.single import Single
from pracy.analysis.variant import AbeVariant
from pracy.core.equiv import EquivSet
from pracy.core.fdh import FdhMap
from pracy.core.group import Group, GroupMap
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var
from pracy.frontend.parsing import parse_json


def test_analyze_scheme_b0():
    json_input = """
{
    "meta": {},
    "spec": {
        "master_key_vars": [
            "alpha_{l}_[l:AUTHS]"
        ],
        "common_vars": [
            "b_{l}_[l:AUTHS]",
            "b'_{l}_[l:AUTHS]",
            "b_{l, lab, 0}_[l:AUTHS, lab:LABELS]",
            "b_{l, lab, 1}_[l:AUTHS, lab:LABELS]"
        ],
        "key_polys": [
            "(k_{1, l} : G = alpha_{l} + <rgid>*b_{l} + r_{l}*b'_{l})_[l:attr_to_auth(USER_ATTRS)]",
            "(k_{2, att.lbl, att} : G = r_{att.auth}*b_{att.auth, att.lbl, 0} + <xattr>_{att}*r_{att.auth}*b_{att.auth, att.lbl, 1})_[att:USER_ATTRS]"
        ],
        "cipher_polys": [
            "cm : Gt = <secret>",
            "(c_{1, j} : H = <mu>_{j} + s_{j}*b_{j.auth})_[j:LSSS_ROWS]",
            "(c_{2, j, 0} : H = s_{j}*b'_{j.auth} + s'_{j.dedup}*b_{j.auth, j.lbl, 0} + s'_{j.dedup}*<xattr>_{j.attr}*b_{j.auth, j.lbl, 1})_[j:POS_LSSS_ROWS]",
            "(c_{2, j, 1} : H = s_{j}*b'_{j.auth} + s'_{j.dedup}*b_{j.auth, j.lbl, 1})_[j:NEG_LSSS_ROWS]",
            "(c_{3, j} : H = s'_{j.dedup}*b_{j.auth, j.lbl, 0} + s'_{j.dedup}*<xattr>_{j.attr}*b_{j.auth, j.lbl, 1})_[j:NEG_LSSS_ROWS]",
            "(c'_{j} : Gt = <lambda>_{j} + alpha_{j.auth}*s_{j})_[j:LSSS_ROWS]"
        ],
        "e_vec": [
            "(c'_{j} = <epsilon>_{j})_[j:LIN_COMB]"
        ],
        "e_mat": [
            "(s_{j} ~ k_{1, j.auth} = -<epsilon>_{j})_[j:LIN_COMB]",
            "(s'_{j.dedup} ~ k_{2, j.lbl, j.attr} = -<epsilon>_{j})_[j:POS_LIN_COMB]",
            "(s'_{j.dedup} ~ k_{2, j.lbl, j.alt_attr} = -<epsilon>_{j} / (<xattralt>_{j} - <xattr>_{j.attr}))_[j:NEG_LIN_COMB]",
            "(c_{1, j} ~ <rgid> = <epsilon>_{j})_[j:LIN_COMB]",
            "(c_{2, j, 0} ~ r_{j.auth} = <epsilon>_{j})_[j:POS_LIN_COMB]",
            "(c_{2, j, 1} ~ r_{j.auth} = <epsilon>_{j})_[j:NEG_LIN_COMB]",
            "(c_{3, j} ~ r_{j.auth} = <epsilon>_{j} / (<xattralt>_{j} - <xattr>_{j.attr}))_[j:NEG_LIN_COMB]"
        ],
        "fdh_map": []
    }
}
"""  # noqa: E501
    raw_scheme = parse_json(json_input)
    received = analyze_scheme(raw_scheme)

    variant = AbeVariant.CP_ABE

    master_key_vars = [Var("alpha", [Idx("l")], [Quant("l", QSet.AUTHORITIES)])]
    common_vars = [
        Var("b", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
        Var("b'", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
        Var(
            "b",
            [Idx("l"), Idx("lab"), Idx("0")],
            [Quant("l", QSet.AUTHORITIES), Quant("lab", QSet.LABELS)],
        ),
        Var(
            "b",
            [Idx("l"), Idx("lab"), Idx("1")],
            [Quant("l", QSet.AUTHORITIES), Quant("lab", QSet.LABELS)],
        ),
    ]
    key_polys = [
        KeyPoly(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            Group.G,
            [KeyPoly.MasterKeyTerm(Var("alpha", [Idx("l")]))],
            [],
            [
                KeyPoly.CommonTerm(Var("r", [Idx("l")]), Var("b'", [Idx("l")])),
            ],
            [
                KeyPoly.CommonTerm(Var("<rgid>", []), Var("b", [Idx("l")])),
            ],
            [],
        ),
        KeyPoly(
            "k",
            [Idx("2"), Idx("att", IMap.TO_LABEL), Idx("att")],
            [Quant("att", QSet.USER_ATTRIBUTES)],
            Group.G,
            [],
            [],
            [
                KeyPoly.CommonTerm(
                    Var("r", [Idx("att", IMap.TO_AUTHORITY)]),
                    Var(
                        "b",
                        [
                            Idx("att", IMap.TO_AUTHORITY),
                            Idx("att", IMap.TO_LABEL),
                            Idx("0"),
                        ],
                    ),
                ),
                KeyPoly.CommonTerm(
                    Var("r", [Idx("att", IMap.TO_AUTHORITY)]),
                    Var(
                        "b",
                        [
                            Idx("att", IMap.TO_AUTHORITY),
                            Idx("att", IMap.TO_LABEL),
                            Idx("1"),
                        ],
                    ),
                    factor=Term(Coeff("<xattr>_{att}")),
                ),
            ],
            [],
            [],
        ),
    ]
    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet(
        [
            Var(
                "r",
                [Idx("l")],
                [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            )
        ]
    )

    cipher_primaries = [
        PrimaryCipherPoly(
            "c",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [PrimaryCipherPoly.LoneRandomTerm(Var("<mu>", [Idx("j")]))],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("j")]),
                    Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
            [],
        ),
        PrimaryCipherPoly(
            "c",
            [Idx("2"), Idx("j"), Idx("0")],
            [Quant("j", QSet.POS_LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("j")]),
                    Var("b'", [Idx("j", IMap.TO_AUTHORITY)]),
                ),
                PrimaryCipherPoly.CommonTerm(
                    Var("s'", [Idx("j", IMap.TO_DEDUP_INDICES)]),
                    Var(
                        "b",
                        [
                            Idx("j", IMap.TO_AUTHORITY),
                            Idx("j", IMap.TO_LABEL),
                            Idx("0"),
                        ],
                    ),
                ),
                PrimaryCipherPoly.CommonTerm(
                    Var("s'", [Idx("j", IMap.TO_DEDUP_INDICES)]),
                    Var(
                        "b",
                        [
                            Idx("j", IMap.TO_AUTHORITY),
                            Idx("j", IMap.TO_LABEL),
                            Idx("1"),
                        ],
                    ),
                    factor=Term(Coeff("<xattr>_{j.attr}")),
                ),
            ],
            [],
        ),
        PrimaryCipherPoly(
            "c",
            [Idx("2"), Idx("j"), Idx("1")],
            [Quant("j", QSet.NEG_LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("j")]),
                    Var("b'", [Idx("j", IMap.TO_AUTHORITY)]),
                ),
                PrimaryCipherPoly.CommonTerm(
                    Var("s'", [Idx("j", IMap.TO_DEDUP_INDICES)]),
                    Var(
                        "b",
                        [
                            Idx("j", IMap.TO_AUTHORITY),
                            Idx("j", IMap.TO_LABEL),
                            Idx("1"),
                        ],
                    ),
                ),
            ],
            [],
        ),
        PrimaryCipherPoly(
            "c",
            [Idx("3"), Idx("j")],
            [Quant("j", QSet.NEG_LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s'", [Idx("j", IMap.TO_DEDUP_INDICES)]),
                    Var(
                        "b",
                        [
                            Idx("j", IMap.TO_AUTHORITY),
                            Idx("j", IMap.TO_LABEL),
                            Idx("0"),
                        ],
                    ),
                ),
                PrimaryCipherPoly.CommonTerm(
                    Var("s'", [Idx("j", IMap.TO_DEDUP_INDICES)]),
                    Var(
                        "b",
                        [
                            Idx("j", IMap.TO_AUTHORITY),
                            Idx("j", IMap.TO_LABEL),
                            Idx("1"),
                        ],
                    ),
                    factor=Term(Coeff("<xattr>_{j.attr}")),
                ),
            ],
            [],
        ),
    ]
    cipher_secondaries = [
        SecondaryCipherPoly(
            "c'",
            [Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.GT,
            [
                SecondaryCipherPoly.MasterKeyTerm(
                    Var("s", [Idx("j")]),
                    Var("alpha", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
            [SecondaryCipherPoly.SpecialLoneRandomTerm(Var("<lambda>", [Idx("j")]))],
        )
    ]
    cipher_blinding = BlindingPoly(
        "cm",
        [],
        [],
        Group.GT,
        [BlindingPoly.SpecialLoneRandomTerm(Var("<secret>", []))],
        [],
    )
    cipher_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet(
        [
            Var("s", [Idx("j")], [Quant("j", QSet.LSSS_ROWS)]),
            Var(
                "s'",
                [Idx("j", IMap.TO_DEDUP_INDICES)],
                [Quant("j", QSet.LSSS_ROWS)],
            ),
        ]
    )

    dec_singles = [
        Single(
            Var("c'", [Idx("j")]),
            [Term(Coeff("<epsilon>_{j}"))],
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        )
    ]

    dec_pairs = [
        Pair(
            Var("k", [Idx("1"), Idx("j", IMap.TO_AUTHORITY)]),
            Var("s", [Idx("j")]),
            [Term(Coeff(-1), Coeff("<epsilon>_{j}"))],
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        Pair(
            Var(
                "k",
                [
                    Idx("2"),
                    Idx("j", IMap.TO_LABEL),
                    Idx("j", IMap.TO_ATTR),
                ],
            ),
            Var("s'", [Idx("j", IMap.TO_DEDUP_INDICES)]),
            [Term(Coeff(-1), Coeff("<epsilon>_{j}"))],
            [Quant("j", QSet.POS_LINEAR_COMBINATION_INDICES)],
        ),
        Pair(
            Var(
                "k",
                [
                    Idx("2"),
                    Idx("j", IMap.TO_LABEL),
                    Idx("j", IMap.TO_ALT_ATTR),
                ],
            ),
            Var("s'", [Idx("j", IMap.TO_DEDUP_INDICES)]),
            [
                Term(
                    Coeff(-1),
                    Coeff("<epsilon>_{j}"),
                    Coeff(
                        1,
                        denom=[["<xattralt>_{j}"], [-1, "<xattr>_{j.attr}"]],
                    ),
                )
            ],
            [Quant("j", QSet.NEG_LINEAR_COMBINATION_INDICES)],
        ),
        Pair(
            Var("<rgid>", []),
            Var("c", [Idx("1"), Idx("j")]),
            [Term(Coeff("<epsilon>_{j}"))],
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        Pair(
            Var("r", [Idx("j", IMap.TO_AUTHORITY)]),
            Var("c", [Idx("2"), Idx("j"), Idx("0")]),
            [Term(Coeff("<epsilon>_{j}"))],
            [Quant("j", QSet.POS_LINEAR_COMBINATION_INDICES)],
        ),
        Pair(
            Var("r", [Idx("j", IMap.TO_AUTHORITY)]),
            Var("c", [Idx("2"), Idx("j"), Idx("1")]),
            [Term(Coeff("<epsilon>_{j}"))],
            [Quant("j", QSet.NEG_LINEAR_COMBINATION_INDICES)],
        ),
        Pair(
            Var("r", [Idx("j", IMap.TO_AUTHORITY)]),
            Var("c", [Idx("3"), Idx("j")]),
            [
                Term(
                    Coeff("<epsilon>_{j}"),
                    Coeff(
                        1,
                        denom=[["<xattralt>_{j}"], [-1, "<xattr>_{j.attr}"]],
                    ),
                )
            ],
            [Quant("j", QSet.NEG_LINEAR_COMBINATION_INDICES)],
        ),
    ]

    group_map = GroupMap()
    group_map[Var("<rgid>", [])] = Group.G
    group_map[key_polys[0]] = Group.G
    group_map[key_polys[1]] = Group.G
    group_map[cipher_primaries[0]] = Group.H
    group_map[cipher_primaries[1]] = Group.H
    group_map[cipher_primaries[2]] = Group.H
    group_map[cipher_primaries[3]] = Group.H
    group_map[common_vars[0]] = Group.H
    group_map[common_vars[1]] = Group.H
    group_map[common_vars[2]] = Group.H
    group_map[common_vars[3]] = Group.H
    group_map[key_non_lone_randoms[0]] = Group.G
    group_map[cipher_non_lone_randoms[0]] = Group.H
    group_map[cipher_non_lone_randoms[1]] = Group.H

    fdh_map = FdhMap()

    var_type_map = VarTypeMap()
    var_type_map[master_key_vars[0]] = VarType.MASTER_KEY_VAR
    var_type_map[common_vars[0]] = VarType.COMMON_VAR
    var_type_map[common_vars[1]] = VarType.COMMON_VAR
    var_type_map[common_vars[2]] = VarType.COMMON_VAR
    var_type_map[common_vars[3]] = VarType.COMMON_VAR
    var_type_map[key_non_lone_randoms[0]] = VarType.KEY_NON_LONE_RANDOM_VAR
    var_type_map[key_polys[0]] = VarType.KEY_POLY
    var_type_map[key_polys[1]] = VarType.KEY_POLY
    var_type_map[cipher_non_lone_randoms[0]] = VarType.CIPHER_NON_LONE_RANDOM
    var_type_map[cipher_non_lone_randoms[1]] = VarType.CIPHER_NON_LONE_RANDOM
    var_type_map[cipher_primaries[0]] = VarType.CIPHER_PRIMARY_POLY
    var_type_map[cipher_primaries[1]] = VarType.CIPHER_PRIMARY_POLY
    var_type_map[cipher_primaries[2]] = VarType.CIPHER_PRIMARY_POLY
    var_type_map[cipher_primaries[3]] = VarType.CIPHER_PRIMARY_POLY
    var_type_map[cipher_secondaries[0]] = VarType.CIPHER_SECONDARY_POLY
    var_type_map[cipher_blinding] = VarType.CIPHER_BLINDING_POLY

    expected = Scheme(
        variant,
        master_key_vars,
        common_vars,
        key_polys,
        key_lone_randoms,
        key_non_lone_randoms,
        cipher_primaries,
        cipher_secondaries,
        cipher_blinding,
        cipher_lone_randoms,
        cipher_special_lone_randoms,
        cipher_non_lone_randoms,
        dec_singles,
        dec_pairs,
        group_map,
        fdh_map,
        var_type_map,
    )

    assert received == expected
