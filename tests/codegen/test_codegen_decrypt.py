from pracy.analysis.expr import Coeff, Term
from pracy.analysis.pair import Pair
from pracy.analysis.single import Single
from pracy.backend import ir
from pracy.backend.compiler.decrypt import compile_decrypt
from pracy.core.fdh import FdhMap
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var


def test_code_gen_singles_only():
    singles = [
        Single(
            Var("c'", [Idx("j")]),
            [Term(Coeff("<epsilon>_{j}"))],
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        )
    ]
    pairs = []
    var_type_map = VarTypeMap()
    fdh_map = FdhMap()

    received = compile_decrypt(singles, pairs, var_type_map, fdh_map)

    expected = [
        ir.Comment("BEGIN DECRYPT"),
        ir.Loop(
            "j",
            ir.IrType.LSSS_ROW,
            QSet.LINEAR_COMBINATION_INDICES,
            [
                ir.SetZ(ir.TMP_Z, "1"),
                ir.GetEpsilon(ir.AUX_Z, ir.IrVar("j")),
                ir.MulZ(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("c'"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("j"), ir.IrFunc.LSSS_ROW_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.ScaleGt(
                    ir.TMP_GT,
                    ir.TMP_Z,
                    ir.CT_SECONDARIES.indexed_at(ir.IDX),
                ),
                ir.AddGt(ir.ACC_GT, ir.ACC_GT, ir.TMP_GT),
            ],
        ),
        ir.Store(ir.BLINDING_POLY, ir.ACC_GT),
        ir.Comment("END DECRYPT"),
    ]
    assert received == expected


def test_code_gen_pairs_only():
    singles = []
    pairs = [
        Pair(
            Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
            Var("k", [Idx("2"), Idx("j", IMap.TO_ATTR)]),
            [Term(Coeff("<epsilon>_{j}"))],
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        )
    ]
    var_type_map = VarTypeMap()
    var_type_map[
        Var(
            "s",
            [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)],
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        )
    ] = VarType.CIPHER_NON_LONE_RANDOM
    var_type_map[
        Var(
            "k",
            [Idx("2"), Idx("j", IMap.TO_ATTR)],
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        )
    ] = VarType.KEY_POLY

    fdh_map = FdhMap()
    received = compile_decrypt(singles, pairs, var_type_map, fdh_map)

    expected = [
        ir.Comment("BEGIN DECRYPT"),
        ir.Loop(
            "j",
            ir.IrType.LSSS_ROW,
            QSet.LINEAR_COMBINATION_INDICES,
            [
                ir.SetIndex(""),
                ir.AppendIndexLiteral("s"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("2"),
                ir.AppendIndexLiteral(","),
                ir.Alloc(
                    ir.IrVar("j_local_0"),
                    ir.IrType.DEDUP_INDEX,
                    ir.Call(
                        ir.IrFunc.LSSS_ROW_TO_DEDUP_INDICES, [ir.Read(ir.IrVar("j"))]
                    ),
                ),
                ir.AppendIndex(ir.IrVar("j_local_0"), ir.IrFunc.DEDUP_IDX_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.TMP_G, ir.CT_RANDOMS_G.indexed_at(ir.IDX)),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("k"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("2"),
                ir.AppendIndexLiteral(","),
                ir.Alloc(
                    ir.IrVar("j_local_1"),
                    ir.IrType.ATTRIBUTE,
                    ir.Call(ir.IrFunc.LSSS_ROW_TO_ATTR, [ir.Read(ir.IrVar("j"))]),
                ),
                ir.AppendIndex(ir.IrVar("j_local_1"), ir.IrFunc.ATTRIBUTE_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.TMP_H, ir.USK_POLYS_H.indexed_at(ir.IDX)),
                ir.Pair(ir.TMP_GT, ir.TMP_G, ir.TMP_H),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.GetEpsilon(ir.AUX_Z, ir.IrVar("j")),
                ir.MulZ(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z),
                ir.ScaleGt(ir.TMP_GT, ir.TMP_Z, ir.TMP_GT),
                ir.AddGt(ir.ACC_GT, ir.ACC_GT, ir.TMP_GT),
            ],
        ),
        ir.Store(ir.BLINDING_POLY, ir.ACC_GT),
        ir.Comment("END DECRYPT"),
    ]
    assert received == expected


def test_code_gen_pairs_special_symbol():
    singles = []
    pairs = [
        Pair(
            Var("<rgid>", []),
            Var("c", [Idx("1"), Idx("j")]),
            [Term(Coeff("<epsilon>_{j}"))],
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        )
    ]
    var_type_map = VarTypeMap()
    var_type_map[
        Var("c", [Idx("1"), Idx("j")], [Quant("j", QSet.LINEAR_COMBINATION_INDICES)])
    ] = VarType.CIPHER_PRIMARY_POLY

    fdh_map = FdhMap()
    received = compile_decrypt(singles, pairs, var_type_map, fdh_map)

    expected = [
        ir.Comment("BEGIN DECRYPT"),
        ir.Loop(
            "j",
            ir.IrType.LSSS_ROW,
            QSet.LINEAR_COMBINATION_INDICES,
            [
                ir.GetRgidG(ir.TMP_G),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("c"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndexLiteral("1"),
                ir.AppendIndexLiteral(","),
                ir.AppendIndex(ir.IrVar("j"), ir.IrFunc.LSSS_ROW_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.Store(ir.TMP_H, ir.CT_PRIMARIES_H.indexed_at(ir.IDX)),
                ir.Pair(ir.TMP_GT, ir.TMP_G, ir.TMP_H),
                ir.SetZ(ir.TMP_Z, "1"),
                ir.GetEpsilon(ir.AUX_Z, ir.IrVar("j")),
                ir.MulZ(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z),
                ir.ScaleGt(ir.TMP_GT, ir.TMP_Z, ir.TMP_GT),
                ir.AddGt(ir.ACC_GT, ir.ACC_GT, ir.TMP_GT),
            ],
        ),
        ir.Store(ir.BLINDING_POLY, ir.ACC_GT),
        ir.Comment("END DECRYPT"),
    ]
    assert received == expected
