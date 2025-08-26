from pracy.analysis.keypoly import KeyPoly
from pracy.backend import ir
from pracy.backend.compiler.keygen import compile_keygen
from pracy.core.fdh import FdhMap
from pracy.core.group import Group, GroupMap
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.var import Var


def test_codegen_keygen_lone_randoms_only():
    lone_randoms = [Var("r", [Idx("i")], [Quant("i", QSet.LABELS)])]
    non_lone_randoms = []
    key_polys = []

    group_map = GroupMap()
    fdh_map = FdhMap()
    received = compile_keygen(
        lone_randoms, non_lone_randoms, key_polys, group_map, fdh_map
    )

    expected = [
        ir.Comment("BEGIN KEYGEN"),
        ir.Loop(
            "i",
            ir.IrType.LABEL,
            QSet.LABELS,
            [
                ir.SetIndex(""),
                ir.AppendIndexLiteral("r"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("i"), ir.IrFunc.LABEL_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.SampleZ(ir.KEYGEN_LONE_RANDOMS.indexed_at(ir.IDX)),
            ],
        ),
        ir.Comment("END KEYGEN"),
    ]
    assert received == expected


def test_codegen_keygen_non_lone_randoms_only():
    lone_randoms = []
    non_lone_randoms = [Var("r", [Idx("i")], [Quant("i", QSet.LABELS)])]
    key_polys = []

    group_map = GroupMap()
    group_map[non_lone_randoms[0]] = Group.H
    fdh_map = FdhMap()
    received = compile_keygen(
        lone_randoms, non_lone_randoms, key_polys, group_map, fdh_map
    )

    expected = [
        ir.Comment("BEGIN KEYGEN"),
        ir.Loop(
            "i",
            ir.IrType.LABEL,
            QSet.LABELS,
            [
                ir.SetIndex(""),
                ir.AppendIndexLiteral("r"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("i"), ir.IrFunc.LABEL_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.SampleZ(ir.KEYGEN_NON_LONE_RANDOMS.indexed_at(ir.IDX)),
                ir.LiftH(
                    ir.USK_RANDOMS_H.indexed_at(ir.IDX),
                    ir.KEYGEN_NON_LONE_RANDOMS.indexed_at(ir.IDX),
                ),
            ],
        ),
        ir.Comment("END KEYGEN"),
    ]
    assert received == expected


def test_codegen_keygen_master_key_terms_only():
    lone_randoms = []
    non_lone_randoms = []
    key_polys = [
        KeyPoly(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            Group.G,
            [KeyPoly.MasterKeyTerm(Var("alpha", [Idx("l")]))],
            [],
            [],
            [],
            [],
        )
    ]

    group_map = GroupMap()
    fdh_map = FdhMap()
    received = compile_keygen(
        lone_randoms, non_lone_randoms, key_polys, group_map, fdh_map
    )

    expected = [
        ir.Comment("BEGIN KEYGEN"),
        ir.Loop(
            "l_global",
            ir.IrType.ATTRIBUTE,
            QSet.USER_ATTRIBUTES,
            [
                ir.Alloc(
                    ir.IrVar("l"),
                    ir.IrType.AUTHORITY,
                    ir.Call(
                        ir.IrFunc.ATTRIBUTE_TO_AUTHORITY,
                        [ir.Read(ir.IrVar("l_global"))],
                    ),
                ),
                ir.ResetZ(ir.TMP_Z),
                ir.ResetZ(ir.ACC_Z),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("alpha"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.AUTHORITY_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.MulZ(
                    ir.TMP_Z,
                    ir.TMP_Z,
                    ir.MSK_ALPHAS.indexed_at(ir.IDX),
                ),
                ir.AddZ(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z),
                ir.LiftG(ir.ACC_G, ir.ACC_Z),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("k"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.AUTHORITY_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.USK_POLYS_G.indexed_at(ir.IDX), ir.ACC_G),
            ],
        ),
        ir.Comment("END KEYGEN"),
    ]
    assert received == expected


def test_codegen_keygen_lone_random_terms_only():
    lone_randoms = []
    non_lone_randoms = []
    key_polys = [
        KeyPoly(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES)],
            Group.G,
            [],
            [KeyPoly.LoneRandomTerm(Var("r", [Idx("l", IMap.TO_LABEL)]))],
            [],
            [],
            [],
        )
    ]

    group_map = GroupMap()
    fdh_map = FdhMap()
    received = compile_keygen(
        lone_randoms, non_lone_randoms, key_polys, group_map, fdh_map
    )

    expected = [
        ir.Comment("BEGIN KEYGEN"),
        ir.Loop(
            "l",
            ir.IrType.ATTRIBUTE,
            QSet.USER_ATTRIBUTES,
            [
                ir.ResetZ(ir.TMP_Z),
                ir.ResetZ(ir.ACC_Z),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("r"),
                ir.AppendIndexLiteral("_{"),
                ir.Alloc(
                    ir.IrVar("l_local_0"),
                    ir.IrType.LABEL,
                    ir.Call(ir.IrFunc.ATTRIBUTE_TO_LABEL, [ir.Read(ir.IrVar("l"))]),
                ),
                ir.AppendIndex(ir.IrVar("l_local_0"), ir.IrFunc.LABEL_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.MulZ(
                    ir.TMP_Z,
                    ir.TMP_Z,
                    ir.KEYGEN_LONE_RANDOMS.indexed_at(ir.IDX),
                ),
                ir.AddZ(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z),
                ir.LiftG(ir.ACC_G, ir.ACC_Z),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("k"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.ATTRIBUTE_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.USK_POLYS_G.indexed_at(ir.IDX), ir.ACC_G),
            ],
        ),
        ir.Comment("END KEYGEN"),
    ]
    assert received == expected


def test_codegen_keygen_common_terms_only():
    lone_randoms = []
    non_lone_randoms = []
    key_polys = [
        KeyPoly(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.LABELS)],
            Group.H,
            [],
            [],
            [KeyPoly.CommonTerm(Var("r", [Idx("l")]), Var("b", [Idx("1")]))],
            [],
            [],
        )
    ]

    group_map = GroupMap()
    fdh_map = FdhMap()
    received = compile_keygen(
        lone_randoms, non_lone_randoms, key_polys, group_map, fdh_map
    )

    expected = [
        ir.Comment("BEGIN KEYGEN"),
        ir.Loop(
            "l",
            ir.IrType.LABEL,
            QSet.LABELS,
            [
                ir.ResetZ(ir.TMP_Z),
                ir.ResetZ(ir.ACC_Z),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("r"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.LABEL_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.MulZ(
                    ir.TMP_Z,
                    ir.TMP_Z,
                    ir.KEYGEN_NON_LONE_RANDOMS.indexed_at(ir.IDX),
                ),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("b"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral("}"),
                ir.MulZ(
                    ir.TMP_Z,
                    ir.TMP_Z,
                    ir.MSK_COMMON_VARS.indexed_at(ir.IDX),
                ),
                ir.AddZ(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z),
                ir.LiftH(ir.ACC_H, ir.ACC_Z),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("k"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.LABEL_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.USK_POLYS_H.indexed_at(ir.IDX), ir.ACC_H),
            ],
        ),
        ir.Comment("END KEYGEN"),
    ]
    assert received == expected


def test_codegen_keygen_hashed_common_terms_only():
    lone_randoms = []
    non_lone_randoms = []
    key_polys = [
        KeyPoly(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.LABELS)],
            Group.H,
            [],
            [],
            [],
            [],
            [KeyPoly.CommonTerm(Var("r", [Idx("l")]), Var("b", [Idx("1")]))],
        )
    ]

    group_map = GroupMap()
    fdh_map = FdhMap()
    fdh_map[Var("b", [Idx("1")])] = 3
    received = compile_keygen(
        lone_randoms, non_lone_randoms, key_polys, group_map, fdh_map
    )

    expected = [
        ir.Comment("BEGIN KEYGEN"),
        ir.Loop(
            "l",
            ir.IrType.LABEL,
            QSet.LABELS,
            [
                ir.ResetZ(ir.TMP_Z),
                ir.ResetZ(ir.ACC_Z),
                ir.LiftH(ir.ACC_H, ir.ACC_Z),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("r"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.LABEL_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.MulZ(
                    ir.TMP_Z,
                    ir.TMP_Z,
                    ir.KEYGEN_NON_LONE_RANDOMS.indexed_at(ir.IDX),
                ),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("b"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral("}"),
                ir.FdhH(ir.TMP_H, 3, ir.IDX),
                ir.ScaleH(ir.TMP_H, ir.TMP_Z, ir.TMP_H),
                ir.AddH(ir.ACC_H, ir.ACC_H, ir.TMP_H),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("k"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.LABEL_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.USK_POLYS_H.indexed_at(ir.IDX), ir.ACC_H),
            ],
        ),
        ir.Comment("END KEYGEN"),
    ]
    assert received == expected


def test_codegen_keygen_hashed_common_terms_only2():
    lone_randoms = []
    non_lone_randoms = []
    key_polys = [
        KeyPoly(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.LABELS)],
            Group.G,
            [],
            [],
            [],
            [KeyPoly.CommonTerm(Var("r", [Idx("l")]), Var("b", [Idx("1")]))],
            [],
        )
    ]

    group_map = GroupMap()
    fdh_map = FdhMap()
    fdh_map[Var("r", [Idx("l")], [Quant("l", QSet.LABELS)])] = 7
    received = compile_keygen(
        lone_randoms, non_lone_randoms, key_polys, group_map, fdh_map
    )

    expected = [
        ir.Comment("BEGIN KEYGEN"),
        ir.Loop(
            "l",
            ir.IrType.LABEL,
            QSet.LABELS,
            [
                ir.ResetZ(ir.TMP_Z),
                ir.ResetZ(ir.ACC_Z),
                ir.LiftG(ir.ACC_G, ir.ACC_Z),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("b"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral("}"),
                ir.MulZ(
                    ir.TMP_Z,
                    ir.TMP_Z,
                    ir.MSK_COMMON_VARS.indexed_at(ir.IDX),
                ),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("r"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.LABEL_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.FdhG(ir.TMP_G, 7, ir.IDX),
                ir.ScaleG(ir.TMP_G, ir.TMP_Z, ir.TMP_G),
                ir.AddG(ir.ACC_G, ir.ACC_G, ir.TMP_G),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("k"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.LABEL_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.USK_POLYS_G.indexed_at(ir.IDX), ir.ACC_G),
            ],
        ),
        ir.Comment("END KEYGEN"),
    ]
    assert received == expected


def test_codegen_keygen_special_var():
    lone_randoms = []
    non_lone_randoms = []
    key_polys = [
        KeyPoly(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.LABELS)],
            Group.H,
            [],
            [],
            [],
            [KeyPoly.CommonTerm(Var("<rgid>", []), Var("b", [Idx("1")]))],
            [],
        )
    ]

    group_map = GroupMap()
    fdh_map = FdhMap()
    received = compile_keygen(
        lone_randoms, non_lone_randoms, key_polys, group_map, fdh_map
    )

    expected = [
        ir.Comment("BEGIN KEYGEN"),
        ir.Loop(
            "l",
            ir.IrType.LABEL,
            QSet.LABELS,
            [
                ir.ResetZ(ir.TMP_Z),
                ir.ResetZ(ir.ACC_Z),
                ir.LiftH(ir.ACC_H, ir.ACC_Z),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("b"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral("}"),
                ir.MulZ(
                    ir.TMP_Z,
                    ir.TMP_Z,
                    ir.MSK_COMMON_VARS.indexed_at(ir.IDX),
                ),
                ir.GetRgidH(ir.TMP_H),
                ir.ScaleH(ir.TMP_H, ir.TMP_Z, ir.TMP_H),
                ir.AddH(ir.ACC_H, ir.ACC_H, ir.TMP_H),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("k"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.LABEL_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.USK_POLYS_H.indexed_at(ir.IDX), ir.ACC_H),
            ],
        ),
        ir.Comment("END KEYGEN"),
    ]
    assert received == expected
