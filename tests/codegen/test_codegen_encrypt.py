from pracy.analysis.blinding_poly import BlindingPoly
from pracy.analysis.primary_cipher_poly import PrimaryCipherPoly
from pracy.analysis.secondary_cipher_poly import SecondaryCipherPoly
from pracy.backend import ir
from pracy.backend.compiler.encrypt import compile_encrypt
from pracy.core.fdh import FdhMap
from pracy.core.group import Group, GroupMap
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.var import Var


def test_codegen_encrypt_lone_randoms():
    lone_randoms = [Var("r", [Idx("i")], [Quant("i", QSet.LABELS)])]
    special_lone_randoms = []
    non_lone_randoms = []
    primaries = []
    secondaries = []
    blinding = BlindingPoly(
        "cm",
        [],
        [],
        Group.GT,
        [BlindingPoly.SpecialLoneRandomTerm(Var("<secret>", []))],
        [],
    )

    group_map = GroupMap()
    fdh_map = FdhMap()
    received = compile_encrypt(
        lone_randoms,
        special_lone_randoms,
        non_lone_randoms,
        primaries,
        secondaries,
        blinding,
        group_map,
        fdh_map,
    )

    expected = [
        ir.Comment("BEGIN ENCRYPT"),
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
                ir.SampleZ(ir.ENCRYPT_LONE_RANDOMS.indexed_at(ir.IDX)),
            ],
        ),
        ir.ResetZ(ir.TMP_Z),
        ir.ResetZ(ir.ACC_Z),
        ir.ResetGt(ir.TMP_GT),
        ir.ResetGt(ir.ACC_GT),
        ir.SetZ(ir.TMP_Z, "1"),
        ir.GetSecret(ir.AUX_Z),
        ir.MulZ(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z),
        ir.AddZ(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z),
        ir.LiftGt(ir.ACC_GT, ir.ACC_Z),
        ir.Store(ir.CT_BLINDING_POLY, ir.ACC_GT),
        ir.Comment("END ENCRYPT"),
    ]

    assert received == expected


def test_codegen_encrypt_special_lone_randoms():
    lone_randoms = []
    special_lone_randoms = [Var("r", [Idx("i")], [Quant("i", QSet.LABELS)])]
    non_lone_randoms = []
    primaries = []
    secondaries = []
    blinding = BlindingPoly(
        "cm",
        [],
        [],
        Group.GT,
        [BlindingPoly.SpecialLoneRandomTerm(Var("<secret>", []))],
        [],
    )

    group_map = GroupMap()
    fdh_map = FdhMap()
    received = compile_encrypt(
        lone_randoms,
        special_lone_randoms,
        non_lone_randoms,
        primaries,
        secondaries,
        blinding,
        group_map,
        fdh_map,
    )

    expected = [
        ir.Comment("BEGIN ENCRYPT"),
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
                ir.SampleZ(ir.ENCRYPT_SPECIAL_LONE_RANDOMS.indexed_at(ir.IDX)),
            ],
        ),
        ir.ResetZ(ir.TMP_Z),
        ir.ResetZ(ir.ACC_Z),
        ir.ResetGt(ir.TMP_GT),
        ir.ResetGt(ir.ACC_GT),
        ir.SetZ(ir.TMP_Z, "1"),
        ir.GetSecret(ir.AUX_Z),
        ir.MulZ(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z),
        ir.AddZ(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z),
        ir.LiftGt(ir.ACC_GT, ir.ACC_Z),
        ir.Store(ir.CT_BLINDING_POLY, ir.ACC_GT),
        ir.Comment("END ENCRYPT"),
    ]

    assert received == expected


def test_codegen_encrypt_non_lone_randoms():
    lone_randoms = []
    special_lone_randoms = []
    non_lone_randoms = [Var("s", [Idx("i")], [Quant("i", QSet.LABELS)])]
    primaries = []
    secondaries = []
    blinding = BlindingPoly(
        "cm",
        [],
        [],
        Group.GT,
        [BlindingPoly.SpecialLoneRandomTerm(Var("<secret>", []))],
        [],
    )

    group_map = GroupMap()
    group_map[non_lone_randoms[0]] = Group.G
    fdh_map = FdhMap()
    received = compile_encrypt(
        lone_randoms,
        special_lone_randoms,
        non_lone_randoms,
        primaries,
        secondaries,
        blinding,
        group_map,
        fdh_map,
    )

    expected = [
        ir.Comment("BEGIN ENCRYPT"),
        ir.Loop(
            "i",
            ir.IrType.LABEL,
            QSet.LABELS,
            [
                ir.SetIndex(""),
                ir.AppendIndexLiteral("s"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("i"), ir.IrFunc.LABEL_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.SampleZ(ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX)),
                ir.LiftG(
                    ir.CT_RANDOMS_G.indexed_at(ir.IDX),
                    ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX),
                ),
            ],
        ),
        ir.ResetZ(ir.TMP_Z),
        ir.ResetZ(ir.ACC_Z),
        ir.ResetGt(ir.TMP_GT),
        ir.ResetGt(ir.ACC_GT),
        ir.SetZ(ir.TMP_Z, "1"),
        ir.GetSecret(ir.AUX_Z),
        ir.MulZ(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z),
        ir.AddZ(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z),
        ir.LiftGt(ir.ACC_GT, ir.ACC_Z),
        ir.Store(ir.CT_BLINDING_POLY, ir.ACC_GT),
        ir.Comment("END ENCRYPT"),
    ]

    assert received == expected


def test_codegen_blinding_poly_only():
    lone_randoms = []
    special_lone_randoms = []
    non_lone_randoms = []
    primaries = []
    secondaries = []
    blinding = BlindingPoly(
        "cm",
        [],
        [],
        Group.GT,
        [BlindingPoly.SpecialLoneRandomTerm(Var("<secret>", []))],
        [],
    )

    group_map = GroupMap()
    fdh_map = FdhMap()
    received = compile_encrypt(
        lone_randoms,
        special_lone_randoms,
        non_lone_randoms,
        primaries,
        secondaries,
        blinding,
        group_map,
        fdh_map,
    )

    expected = [
        ir.Comment("BEGIN ENCRYPT"),
        ir.ResetZ(ir.TMP_Z),
        ir.ResetZ(ir.ACC_Z),
        ir.ResetGt(ir.TMP_GT),
        ir.ResetGt(ir.ACC_GT),
        ir.SetZ(ir.TMP_Z, "1"),
        ir.GetSecret(ir.AUX_Z),
        ir.MulZ(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z),
        ir.AddZ(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z),
        ir.LiftGt(ir.ACC_GT, ir.ACC_Z),
        ir.Store(ir.CT_BLINDING_POLY, ir.ACC_GT),
        ir.Comment("END ENCRYPT"),
    ]

    assert received == expected


def test_codegen_primary_poly():
    lone_randoms = []
    special_lone_randoms = []
    non_lone_randoms = []
    primaries = [
        PrimaryCipherPoly(
            "c",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.H,
            [PrimaryCipherPoly.LoneRandomTerm(Var("<mu>", [Idx("j")]))],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
            [],
        )
    ]
    secondaries = []
    blinding = BlindingPoly(
        "cm",
        [],
        [],
        Group.GT,
        [BlindingPoly.SpecialLoneRandomTerm(Var("<secret>", []))],
        [],
    )

    group_map = GroupMap()
    fdh_map = FdhMap()
    received = compile_encrypt(
        lone_randoms,
        special_lone_randoms,
        non_lone_randoms,
        primaries,
        secondaries,
        blinding,
        group_map,
        fdh_map,
    )

    expected = [
        ir.Comment("BEGIN ENCRYPT"),
        ir.Loop(
            "j",
            ir.IrType.LSSS_ROW,
            QSet.LSSS_ROWS,
            [
                ir.ResetZ(ir.TMP_Z),
                ir.ResetZ(ir.ACC_Z),
                ir.ResetH(ir.TMP_H),
                ir.ResetH(ir.ACC_H),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.GetMu(ir.AUX_Z, ir.IrVar("j")),
                ir.MulZ(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z),
                ir.AddZ(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z),
                ir.LiftH(ir.ACC_H, ir.ACC_Z),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("s"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("j"), ir.IrFunc.LSSS_ROW_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.MulZ(
                    ir.TMP_Z,
                    ir.TMP_Z,
                    ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX),
                ),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("b"),
                ir.AppendIndexLiteral("_{"),
                ir.Alloc(
                    ir.IrVar("j_local_0"),
                    ir.IrType.AUTHORITY,
                    ir.Call(ir.IrFunc.LSSS_ROW_TO_AUTHORITY, [ir.Read(ir.IrVar("j"))]),
                ),
                ir.AppendIndex(ir.IrVar("j_local_0"), ir.IrFunc.AUTHORITY_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.TMP_H, ir.MPK_COMMON_VARS_H.indexed_at(ir.IDX)),
                ir.ScaleH(ir.TMP_H, ir.TMP_Z, ir.TMP_H),
                ir.AddH(ir.ACC_H, ir.ACC_H, ir.TMP_H),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("c"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("j"), ir.IrFunc.LSSS_ROW_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.CT_PRIMARIES_H.indexed_at(ir.IDX), ir.ACC_H),
            ],
        ),
        ir.ResetZ(ir.TMP_Z),
        ir.ResetZ(ir.ACC_Z),
        ir.ResetGt(ir.TMP_GT),
        ir.ResetGt(ir.ACC_GT),
        ir.SetZ(ir.TMP_Z, "1"),
        ir.GetSecret(ir.AUX_Z),
        ir.MulZ(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z),
        ir.AddZ(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z),
        ir.LiftGt(ir.ACC_GT, ir.ACC_Z),
        ir.Store(ir.CT_BLINDING_POLY, ir.ACC_GT),
        ir.Comment("END ENCRYPT"),
    ]

    assert received == expected


def test_codegen_primary_poly_alternative():
    lone_randoms = []
    special_lone_randoms = []
    non_lone_randoms = []
    primaries = [
        PrimaryCipherPoly(
            "c",
            [Idx("2"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.G,
            [],
            [
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("b'", [Idx("j", IMap.TO_AUTHORITY)]),
                ),
                PrimaryCipherPoly.CommonTerm(
                    Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
                    Var("b", [Idx("j", IMap.TO_ATTR)]),
                ),
            ],
            [],
        )
    ]
    secondaries = []
    blinding = BlindingPoly(
        "cm",
        [],
        [],
        Group.GT,
        [BlindingPoly.SpecialLoneRandomTerm(Var("<secret>", []))],
        [],
    )

    group_map = GroupMap()
    fdh_map = FdhMap()
    received = compile_encrypt(
        lone_randoms,
        special_lone_randoms,
        non_lone_randoms,
        primaries,
        secondaries,
        blinding,
        group_map,
        fdh_map,
    )

    expected = [
        ir.Comment("BEGIN ENCRYPT"),
        ir.Loop(
            "j",
            ir.IrType.LSSS_ROW,
            QSet.LSSS_ROWS,
            [
                ir.ResetZ(ir.TMP_Z),
                ir.ResetZ(ir.ACC_Z),
                ir.ResetG(ir.TMP_G),
                ir.ResetG(ir.ACC_G),
                ir.LiftG(ir.ACC_G, ir.ACC_Z),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("s"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("j"), ir.IrFunc.LSSS_ROW_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.MulZ(
                    ir.TMP_Z,
                    ir.TMP_Z,
                    ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX),
                ),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("b'"),
                ir.AppendIndexLiteral("_{"),
                ir.Alloc(
                    ir.IrVar("j_local_0"),
                    ir.IrType.AUTHORITY,
                    ir.Call(ir.IrFunc.LSSS_ROW_TO_AUTHORITY, [ir.Read(ir.IrVar("j"))]),
                ),
                ir.AppendIndex(ir.IrVar("j_local_0"), ir.IrFunc.AUTHORITY_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.TMP_G, ir.MPK_COMMON_VARS_G.indexed_at(ir.IDX)),
                ir.ScaleG(ir.TMP_G, ir.TMP_Z, ir.TMP_G),
                ir.AddG(ir.ACC_G, ir.ACC_G, ir.TMP_G),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("s"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("2"),
                ir.AppendIndexLiteral(","),
                ir.Alloc(
                    ir.IrVar("j_local_1"),
                    ir.IrType.DEDUP_INDEX,
                    ir.Call(
                        ir.IrFunc.LSSS_ROW_TO_DEDUP_INDICES, [ir.Read(ir.IrVar("j"))]
                    ),
                ),
                ir.AppendIndex(ir.IrVar("j_local_1"), ir.IrFunc.DEDUP_IDX_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.MulZ(
                    ir.TMP_Z,
                    ir.TMP_Z,
                    ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX),
                ),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("b"),
                ir.AppendIndexLiteral("_{"),
                ir.Alloc(
                    ir.IrVar("j_local_2"),
                    ir.IrType.ATTRIBUTE,
                    ir.Call(ir.IrFunc.LSSS_ROW_TO_ATTR, [ir.Read(ir.IrVar("j"))]),
                ),
                ir.AppendIndex(ir.IrVar("j_local_2"), ir.IrFunc.ATTRIBUTE_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.TMP_G, ir.MPK_COMMON_VARS_G.indexed_at(ir.IDX)),
                ir.ScaleG(ir.TMP_G, ir.TMP_Z, ir.TMP_G),
                ir.AddG(ir.ACC_G, ir.ACC_G, ir.TMP_G),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("c"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("2"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("j"), ir.IrFunc.LSSS_ROW_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.CT_PRIMARIES_G.indexed_at(ir.IDX), ir.ACC_G),
            ],
        ),
        ir.ResetZ(ir.TMP_Z),
        ir.ResetZ(ir.ACC_Z),
        ir.ResetGt(ir.TMP_GT),
        ir.ResetGt(ir.ACC_GT),
        ir.SetZ(ir.TMP_Z, "1"),
        ir.GetSecret(ir.AUX_Z),
        ir.MulZ(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z),
        ir.AddZ(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z),
        ir.LiftGt(ir.ACC_GT, ir.ACC_Z),
        ir.Store(ir.CT_BLINDING_POLY, ir.ACC_GT),
        ir.Comment("END ENCRYPT"),
    ]

    assert received == expected


def test_codegen_secondary_poly():
    lone_randoms = []
    special_lone_randoms = []
    non_lone_randoms = []
    primaries = []
    secondaries = [
        SecondaryCipherPoly(
            "c'",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Group.GT,
            [
                SecondaryCipherPoly.MasterKeyTerm(
                    Var("s", [Idx("1"), Idx("j")]),
                    Var("alpha", [Idx("j", IMap.TO_AUTHORITY)]),
                )
            ],
            [SecondaryCipherPoly.SpecialLoneRandomTerm(Var("<lambda>", [Idx("j")]))],
        )
    ]
    blinding = BlindingPoly(
        "cm",
        [],
        [],
        Group.GT,
        [BlindingPoly.SpecialLoneRandomTerm(Var("<secret>", []))],
        [],
    )

    group_map = GroupMap()
    fdh_map = FdhMap()
    received = compile_encrypt(
        lone_randoms,
        special_lone_randoms,
        non_lone_randoms,
        primaries,
        secondaries,
        blinding,
        group_map,
        fdh_map,
    )

    expected = [
        ir.Comment("BEGIN ENCRYPT"),
        ir.Loop(
            "j",
            ir.IrType.LSSS_ROW,
            QSet.LSSS_ROWS,
            [
                ir.ResetZ(ir.TMP_Z),
                ir.ResetZ(ir.ACC_Z),
                ir.ResetGt(ir.TMP_GT),
                ir.ResetGt(ir.ACC_GT),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.GetLambda(ir.AUX_Z, ir.IrVar("j")),
                ir.MulZ(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z),
                ir.AddZ(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z),
                ir.LiftGt(ir.ACC_GT, ir.ACC_Z),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("alpha"),
                ir.AppendIndexLiteral("_{"),
                ir.Alloc(
                    ir.IrVar("j_local_0"),
                    ir.IrType.AUTHORITY,
                    ir.Call(ir.IrFunc.LSSS_ROW_TO_AUTHORITY, [ir.Read(ir.IrVar("j"))]),
                ),
                ir.AppendIndex(ir.IrVar("j_local_0"), ir.IrFunc.AUTHORITY_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.TMP_GT, ir.MPK_ALPHAS.indexed_at(ir.IDX)),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("s"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("j"), ir.IrFunc.LSSS_ROW_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.MulZ(
                    ir.TMP_Z,
                    ir.TMP_Z,
                    ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX),
                ),
                ir.ScaleGt(ir.TMP_GT, ir.TMP_Z, ir.TMP_GT),
                ir.AddGt(ir.ACC_GT, ir.ACC_GT, ir.TMP_GT),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("c'"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("j"), ir.IrFunc.LSSS_ROW_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.CT_SECONDARIES.indexed_at(ir.IDX), ir.ACC_GT),
            ],
        ),
        ir.ResetZ(ir.TMP_Z),
        ir.ResetZ(ir.ACC_Z),
        ir.ResetGt(ir.TMP_GT),
        ir.ResetGt(ir.ACC_GT),
        ir.SetZ(ir.TMP_Z, "1"),
        ir.GetSecret(ir.AUX_Z),
        ir.MulZ(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z),
        ir.AddZ(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z),
        ir.LiftGt(ir.ACC_GT, ir.ACC_Z),
        ir.Store(ir.CT_BLINDING_POLY, ir.ACC_GT),
        ir.Comment("END ENCRYPT"),
    ]

    assert received == expected
