import pytest
from sympy import Integer

from pracy.analysis.errors import (
    GroupMapConflictingCommonVarGroups,
    GroupMapConflictingHashedKeyNonLoneRandomGroups,
    GroupMapConflictingPartnerCipherNonLoneRandomError,
    GroupMapConflictingPartnerKeyNonLoneRandomError,
    GroupMapConflictingPolyGroupsWithSharedHashedCommonVarError,
    GroupMapMissingPartnerCipherNonLoneRandomError,
    GroupMapMissingPartnerKeyNonLoneRandomError,
    GroupMapUnusedCommonVarError,
)
from pracy.analysis.group_map import analyze_group_map
from pracy.analysis.keypoly import KeyPoly
from pracy.analysis.primary_cipher_poly import PrimaryCipherPoly
from pracy.core.equiv import EquivSet
from pracy.core.fdh import FdhMap
from pracy.core.group import Group, GroupMap
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.var import Var
from pracy.frontend.raw_scheme import RawPair


def test_analyze_group_map_ok():
    key_polys = [
        KeyPoly(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            Group.G,
            [],
            [],
            [],
            [],
            [],
        ),
        KeyPoly(
            "k",
            [Idx("2"), Idx("att")],
            [Quant("att", QSet.USER_ATTRIBUTES)],
            Group.G,
            [],
            [],
            [],
            [],
            [],
        ),
    ]
    cipher_primaries = [
        PrimaryCipherPoly(
            "c",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
            [],
        ),
        PrimaryCipherPoly(
            "c",
            [Idx("2"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b'", [Idx("j", IMap.TO_AUTHORITY)]),
                ),
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
                    Var("b", [Idx("1"), Idx("j", IMap.TO_ATTR)]),
                ),
            ],
            [],
        ),
    ]
    common_vars = [
        Var("b", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
        Var("b'", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
        Var("b", [Idx("1"), Idx("att")], [Quant("att", QSet.ATTRIBUTE_UNIVERSE)]),
    ]
    key_non_lone_randoms = EquivSet(
        [
            Var(
                "r",
                [Idx("l")],
                [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            )
        ]
    )
    cipher_non_lone_randoms = EquivSet(
        [
            Var("s", [Idx("1"), Idx("j")], [Quant("j", QSet.LSSS_ROWS)]),
            Var(
                "s",
                [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)],
                [Quant("j", QSet.LSSS_ROWS)],
            ),
        ]
    )
    pairs = [
        RawPair(
            Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
            Var("k", [Idx("2"), Idx("j", IMap.TO_ATTR)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("s", [Idx("1"), Idx("j")]),
            Var("k", [Idx("1"), Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("<rgid>", []),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("2"), Idx("j")]),
            Var("r", [Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    group_map = GroupMap()
    group_map[key_polys[0]] = Group.G
    group_map[key_polys[1]] = Group.G
    group_map[cipher_primaries[0]] = Group.H
    group_map[cipher_primaries[1]] = Group.H

    expected = GroupMap()
    expected[key_polys[0]] = Group.G
    expected[key_polys[1]] = Group.G
    expected[cipher_primaries[0]] = Group.H
    expected[cipher_primaries[1]] = Group.H

    expected[common_vars[0]] = Group.H
    expected[common_vars[1]] = Group.H
    expected[common_vars[2]] = Group.H
    expected[key_non_lone_randoms[0]] = Group.G
    expected[cipher_non_lone_randoms[0]] = Group.H
    expected[cipher_non_lone_randoms[1]] = Group.H

    analyze_group_map(
        group_map,
        FdhMap(),
        key_polys,
        cipher_primaries,
        common_vars,
        key_non_lone_randoms,
        cipher_non_lone_randoms,
        pairs,
    )
    assert group_map == expected


def test_analyze_group_map_unused_common_var():
    key_polys = [
        Var("k", [Idx("1"), Idx("att")], [Quant("att", QSet.USER_ATTRIBUTES)]),
    ]
    cipher_primaries = [
        PrimaryCipherPoly(
            "c",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
            [],
        )
    ]
    common_vars = [
        Var("b", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
        Var("b'", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
    ]
    key_non_lone_randoms = EquivSet(
        [
            Var(
                "r",
                [Idx("l")],
                [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            )
        ]
    )
    cipher_non_lone_randoms = EquivSet(
        [
            Var("s", [Idx("1"), Idx("j")], [Quant("j", QSet.LSSS_ROWS)]),
        ]
    )
    pairs = [
        RawPair(
            Var("s", [Idx("1"), Idx("j")]),
            Var("k", [Idx("1"), Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("r", [Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    group_map = GroupMap()
    group_map[key_polys[0]] = Group.G
    group_map[cipher_primaries[0]] = Group.H

    with pytest.raises(GroupMapUnusedCommonVarError):
        analyze_group_map(
            group_map,
            FdhMap(),
            key_polys,
            cipher_primaries,
            common_vars,
            key_non_lone_randoms,
            cipher_non_lone_randoms,
            pairs,
        )


def test_analyze_group_map_conflicting_common_var_usages():
    key_polys = [
        Var("k", [Idx("1"), Idx("att")], [Quant("att", QSet.USER_ATTRIBUTES)]),
    ]
    cipher_primaries = [
        PrimaryCipherPoly(
            "c",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
            [],
        ),
        PrimaryCipherPoly(
            "c",
            [Idx("2"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.G,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
            [],
        ),
    ]
    common_vars = [
        Var("b", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
        Var("b'", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
    ]
    key_non_lone_randoms = EquivSet(
        [
            Var(
                "r",
                [Idx("l")],
                [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            )
        ]
    )
    cipher_non_lone_randoms = EquivSet(
        [
            Var("s", [Idx("1"), Idx("j")], [Quant("j", QSet.LSSS_ROWS)]),
        ]
    )
    pairs = [
        RawPair(
            Var("s", [Idx("1"), Idx("j")]),
            Var("k", [Idx("1"), Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("r", [Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    group_map = GroupMap()
    group_map[key_polys[0]] = Group.G
    group_map[cipher_primaries[0]] = Group.H
    group_map[cipher_primaries[1]] = Group.G

    with pytest.raises(GroupMapConflictingCommonVarGroups):
        analyze_group_map(
            group_map,
            FdhMap(),
            key_polys,
            cipher_primaries,
            common_vars,
            key_non_lone_randoms,
            cipher_non_lone_randoms,
            pairs,
        )


def test_analyze_group_map_missing_partner_key_non_lone_random():
    key_polys = [
        Var("k", [Idx("1"), Idx("att")], [Quant("att", QSet.USER_ATTRIBUTES)]),
    ]
    cipher_primaries = [
        PrimaryCipherPoly(
            "c",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
            [],
        ),
    ]
    common_vars = [
        Var("b", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
    ]
    key_non_lone_randoms = EquivSet(
        [
            Var(
                "r",
                [Idx("l")],
                [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            )
        ]
    )
    cipher_non_lone_randoms = EquivSet(
        [
            Var("s", [Idx("1"), Idx("j")], [Quant("j", QSet.LSSS_ROWS)]),
        ]
    )
    pairs = [
        RawPair(
            Var("s", [Idx("1"), Idx("j")]),
            Var("k", [Idx("1"), Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("<rgid>", []),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    group_map = GroupMap()
    group_map[key_polys[0]] = Group.G
    group_map[cipher_primaries[0]] = Group.H

    with pytest.raises(GroupMapMissingPartnerKeyNonLoneRandomError):
        analyze_group_map(
            group_map,
            FdhMap(),
            key_polys,
            cipher_primaries,
            common_vars,
            key_non_lone_randoms,
            cipher_non_lone_randoms,
            pairs,
        )


def test_analyze_group_map_missing_partner_cipher_non_lone_random():
    key_polys = [
        Var("k", [Idx("1"), Idx("att")], [Quant("att", QSet.USER_ATTRIBUTES)]),
    ]
    cipher_primaries = [
        PrimaryCipherPoly(
            "c",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
            [],
        ),
    ]
    common_vars = [
        Var("b", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
    ]
    key_non_lone_randoms = EquivSet(
        [
            Var(
                "r",
                [Idx("l")],
                [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            )
        ]
    )
    cipher_non_lone_randoms = EquivSet(
        [
            Var("s", [Idx("1"), Idx("j")], [Quant("j", QSet.LSSS_ROWS)]),
        ]
    )
    pairs = [
        RawPair(
            Var("<rgid>", []),
            Var("k", [Idx("1"), Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("r", [Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    group_map = GroupMap()
    group_map[key_polys[0]] = Group.G
    group_map[cipher_primaries[0]] = Group.H

    with pytest.raises(GroupMapMissingPartnerCipherNonLoneRandomError):
        analyze_group_map(
            group_map,
            FdhMap(),
            key_polys,
            cipher_primaries,
            common_vars,
            key_non_lone_randoms,
            cipher_non_lone_randoms,
            pairs,
        )


def test_analyze_group_map_conflicting_partner_key_non_lone_random():
    key_polys = [
        Var(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
        ),
        Var("k", [Idx("2"), Idx("att")], [Quant("att", QSet.USER_ATTRIBUTES)]),
    ]
    cipher_primaries = [
        PrimaryCipherPoly(
            "c",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
            [],
        ),
        PrimaryCipherPoly(
            "c",
            [Idx("2"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b'", [Idx("j", IMap.TO_AUTHORITY)]),
                ),
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
                    Var("b", [Idx("1"), Idx("j", IMap.TO_ATTR)]),
                ),
            ],
            [],
        ),
    ]
    common_vars = [
        Var("b", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
        Var("b'", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
        Var("b", [Idx("1"), Idx("att")], [Quant("att", QSet.ATTRIBUTE_UNIVERSE)]),
    ]
    key_non_lone_randoms = EquivSet(
        [
            Var(
                "r",
                [Idx("l")],
                [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            )
        ]
    )
    cipher_non_lone_randoms = EquivSet(
        [
            Var("s", [Idx("1"), Idx("j")], [Quant("j", QSet.LSSS_ROWS)]),
            Var(
                "s",
                [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)],
                [Quant("j", QSet.LSSS_ROWS)],
            ),
        ]
    )
    pairs = [
        RawPair(
            Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
            Var("k", [Idx("2"), Idx("j", IMap.TO_ATTR)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("s", [Idx("1"), Idx("j")]),
            Var("k", [Idx("1"), Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("<rgid>", []),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("r", [Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("2"), Idx("j")]),
            Var("r", [Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    group_map = GroupMap()
    group_map[key_polys[0]] = Group.G
    group_map[key_polys[1]] = Group.H
    group_map[cipher_primaries[0]] = Group.H
    group_map[cipher_primaries[1]] = Group.G

    with pytest.raises(GroupMapConflictingPartnerKeyNonLoneRandomError):
        analyze_group_map(
            group_map,
            FdhMap(),
            key_polys,
            cipher_primaries,
            common_vars,
            key_non_lone_randoms,
            cipher_non_lone_randoms,
            pairs,
        )


def test_analyze_group_map_conflicting_partner_cipher_non_lone_random():
    key_polys = [
        Var(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
        ),
        Var("k", [Idx("2"), Idx("att")], [Quant("att", QSet.USER_ATTRIBUTES)]),
    ]
    cipher_primaries = [
        PrimaryCipherPoly(
            "c",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
            [],
        ),
        PrimaryCipherPoly(
            "c",
            [Idx("2"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b'", [Idx("j", IMap.TO_AUTHORITY)]),
                ),
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
                    Var("b", [Idx("1"), Idx("j", IMap.TO_ATTR)]),
                ),
            ],
            [],
        ),
    ]
    common_vars = [
        Var("b", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
        Var("b'", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
        Var("b", [Idx("1"), Idx("att")], [Quant("att", QSet.ATTRIBUTE_UNIVERSE)]),
    ]
    key_non_lone_randoms = EquivSet(
        [
            Var(
                "r",
                [Idx("l")],
                [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            )
        ]
    )
    cipher_non_lone_randoms = EquivSet(
        [
            Var("s", [Idx("1"), Idx("j")], [Quant("j", QSet.LSSS_ROWS)]),
            Var(
                "s",
                [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)],
                [Quant("j", QSet.LSSS_ROWS)],
            ),
        ]
    )
    pairs = [
        RawPair(
            Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
            Var("k", [Idx("2"), Idx("j", IMap.TO_ATTR)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("s", [Idx("1"), Idx("j")]),
            Var("k", [Idx("1"), Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("s", [Idx("1"), Idx("j")]),
            Var("k", [Idx("2"), Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("<rgid>", []),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("2"), Idx("j")]),
            Var("r", [Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    group_map = GroupMap()
    group_map[key_polys[0]] = Group.G
    group_map[key_polys[1]] = Group.H
    group_map[cipher_primaries[0]] = Group.H
    group_map[cipher_primaries[1]] = Group.G

    with pytest.raises(GroupMapConflictingPartnerCipherNonLoneRandomError):
        analyze_group_map(
            group_map,
            FdhMap(),
            key_polys,
            cipher_primaries,
            common_vars,
            key_non_lone_randoms,
            cipher_non_lone_randoms,
            pairs,
        )


def test_analyze_group_map_conflicting_groups_with_shared_hashed_common_var():
    key_polys = [
        KeyPoly(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            Group.G,
            [],
            [],
            [],
            [],
            [KeyPoly.CommonTerm(Var("r", [], []), Var("b", [Idx("l")]))],
        )
    ]
    cipher_primaries = [
        PrimaryCipherPoly(
            "c",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [],
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
        ),
    ]
    common_vars = [
        Var("b", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
    ]
    key_non_lone_randoms = EquivSet(
        [Var("r", [], [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)])]
    )
    cipher_non_lone_randoms = EquivSet(
        [
            Var("s", [Idx("1"), Idx("j")], [Quant("j", QSet.LSSS_ROWS)]),
        ]
    )
    pairs = [
        RawPair(
            Var("s", [Idx("1"), Idx("j")]),
            Var("k", [Idx("1"), Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("r", []),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    group_map = GroupMap()
    group_map[key_polys[0]] = Group.G
    group_map[cipher_primaries[0]] = Group.H

    fdh_map = FdhMap()
    fdh_map[common_vars[0]] = 20

    with pytest.raises(GroupMapConflictingPolyGroupsWithSharedHashedCommonVarError):
        analyze_group_map(
            group_map,
            fdh_map,
            key_polys,
            cipher_primaries,
            common_vars,
            key_non_lone_randoms,
            cipher_non_lone_randoms,
            pairs,
        )


def test_analyze_group_map_conflicting_groups_with_hashed_non_lone_var():
    key_polys = [
        KeyPoly(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            Group.H,
            [],
            [],
            [],
            [KeyPoly.CommonTerm(Var("r", [], []), Var("b", [Idx("l")]))],
            [],
        )
    ]
    cipher_primaries = [
        PrimaryCipherPoly(
            "c",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [],
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
        ),
    ]
    common_vars = [
        Var("b", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
    ]
    key_non_lone_randoms = EquivSet(
        [Var("r", [], [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)])]
    )
    cipher_non_lone_randoms = EquivSet(
        [
            Var("s", [Idx("1"), Idx("j")], [Quant("j", QSet.LSSS_ROWS)]),
        ]
    )
    pairs = [
        RawPair(
            Var("s", [Idx("1"), Idx("j")]),
            Var("k", [Idx("1"), Idx("j", IMap.TO_AUTHORITY)]),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("r", []),
            Integer(1),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]

    group_map = GroupMap()
    group_map[key_polys[0]] = Group.G
    group_map[cipher_primaries[0]] = Group.H

    fdh_map = FdhMap()
    fdh_map[key_non_lone_randoms[0]] = 2

    with pytest.raises(GroupMapConflictingHashedKeyNonLoneRandomGroups):
        analyze_group_map(
            group_map,
            fdh_map,
            key_polys,
            cipher_primaries,
            common_vars,
            key_non_lone_randoms,
            cipher_non_lone_randoms,
            pairs,
        )
