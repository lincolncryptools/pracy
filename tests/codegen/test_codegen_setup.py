from pracy.backend import ir
from pracy.backend.compiler.setup import compile_setup
from pracy.core.fdh import FdhMap
from pracy.core.group import Group, GroupMap
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.var import Var


def test_codegen_setup_master_key_only():
    master_key_vars = [Var("alpha", [Idx("l")], [Quant("l", QSet.AUTHORITIES)])]
    common_vars = []

    received = compile_setup(master_key_vars, common_vars, GroupMap(), FdhMap())

    expected = [
        ir.Comment("BEGIN SETUP"),
        ir.Loop(
            "l",
            ir.IrType.AUTHORITY,
            QSet.AUTHORITIES,
            [
                ir.SetIndex(""),
                ir.AppendIndexLiteral("alpha"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.AUTHORITY_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.SampleZ(ir.MSK_ALPHAS.indexed_at(ir.IDX)),
                ir.LiftGt(
                    ir.MPK_ALPHAS.indexed_at(ir.IDX),
                    ir.MSK_ALPHAS.indexed_at(ir.IDX),
                ),
            ],
        ),
        ir.Comment("END SETUP"),
    ]
    assert received == expected


def test_codegen_setup_common_vars_local_map():
    master_key_vars = []
    common_vars = [
        Var(
            "b",
            [Idx("l", IMap.TO_AUTHORITY)],
            [Quant("l", QSet.ATTRIBUTE_UNIVERSE)],
        ),
    ]

    group_map = GroupMap()
    group_map[common_vars[0]] = Group.G

    received = compile_setup(master_key_vars, common_vars, group_map, FdhMap())

    expected = [
        ir.Comment("BEGIN SETUP"),
        ir.Loop(
            "l",
            ir.IrType.ATTRIBUTE,
            QSet.ATTRIBUTE_UNIVERSE,
            [
                ir.SetIndex(""),
                ir.AppendIndexLiteral("b"),
                ir.AppendIndexLiteral("_{"),
                ir.Alloc(
                    ir.IrVar("l_local_0"),
                    ir.IrType.AUTHORITY,
                    ir.Call(ir.IrFunc.ATTRIBUTE_TO_AUTHORITY, [ir.Read(ir.IrVar("l"))]),
                ),
                ir.AppendIndex(ir.IrVar("l_local_0"), ir.IrFunc.AUTHORITY_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.SampleZ(ir.MSK_COMMON_VARS.indexed_at(ir.IDX)),
                ir.LiftG(
                    ir.MPK_COMMON_VARS_G.indexed_at(ir.IDX),
                    ir.MSK_COMMON_VARS.indexed_at(ir.IDX),
                ),
            ],
        ),
        ir.Comment("END SETUP"),
    ]
    assert received == expected


def test_codegen_setup_common_vars_global_map():
    master_key_vars = []
    common_vars = [
        Var(
            "b",
            [Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_LABEL)],
        ),
    ]

    group_map = GroupMap()
    group_map[common_vars[0]] = Group.G

    received = compile_setup(master_key_vars, common_vars, group_map, FdhMap())

    expected = [
        ir.Comment("BEGIN SETUP"),
        ir.Loop(
            "l_global",
            ir.IrType.ATTRIBUTE,
            QSet.USER_ATTRIBUTES,
            [
                ir.Alloc(
                    ir.IrVar("l"),
                    ir.IrType.LABEL,
                    ir.Call(
                        ir.IrFunc.ATTRIBUTE_TO_LABEL, [ir.Read(ir.IrVar("l_global"))]
                    ),
                ),
                ir.SetIndex(""),
                ir.AppendIndexLiteral("b"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.LABEL_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.SampleZ(ir.MSK_COMMON_VARS.indexed_at(ir.IDX)),
                ir.LiftG(
                    ir.MPK_COMMON_VARS_G.indexed_at(ir.IDX),
                    ir.MSK_COMMON_VARS.indexed_at(ir.IDX),
                ),
            ],
        ),
        ir.Comment("END SETUP"),
    ]
    assert received == expected


def test_codegen_setup_combined():
    master_key_vars = [Var("alpha", [Idx("l")], [Quant("l", QSet.AUTHORITIES)])]
    common_vars = [
        Var(
            "b",
            [Idx("l")],
            [Quant("l", QSet.AUTHORITIES)],
        )
    ]

    group_map = GroupMap()
    group_map[common_vars[0]] = Group.H

    received = compile_setup(master_key_vars, common_vars, group_map, FdhMap())

    expected = [
        ir.Comment("BEGIN SETUP"),
        ir.Loop(
            "l",
            ir.IrType.AUTHORITY,
            QSet.AUTHORITIES,
            [
                ir.SetIndex(""),
                ir.AppendIndexLiteral("alpha"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.AUTHORITY_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.SampleZ(ir.MSK_ALPHAS.indexed_at(ir.IDX)),
                ir.LiftGt(
                    ir.MPK_ALPHAS.indexed_at(ir.IDX),
                    ir.MSK_ALPHAS.indexed_at(ir.IDX),
                ),
            ],
        ),
        ir.Loop(
            "l",
            ir.IrType.AUTHORITY,
            QSet.AUTHORITIES,
            [
                ir.SetIndex(""),
                ir.AppendIndexLiteral("b"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.AUTHORITY_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.SampleZ(ir.MSK_COMMON_VARS.indexed_at(ir.IDX)),
                ir.LiftH(
                    ir.MPK_COMMON_VARS_H.indexed_at(ir.IDX),
                    ir.MSK_COMMON_VARS.indexed_at(ir.IDX),
                ),
            ],
        ),
        ir.Comment("END SETUP"),
    ]
    assert received == expected


def test_codegen_setup_combined_with_fdh():
    master_key_vars = [Var("alpha", [Idx("l")], [Quant("l", QSet.AUTHORITIES)])]
    common_vars = [
        Var(
            "b",
            [Idx("l")],
            [Quant("l", QSet.AUTHORITIES)],
        )
    ]

    group_map = GroupMap()
    group_map[common_vars[0]] = Group.H
    fdh_map = FdhMap()
    fdh_map[common_vars[0]] = 7

    received = compile_setup(master_key_vars, common_vars, group_map, fdh_map)

    expected = [
        ir.Comment("BEGIN SETUP"),
        ir.Loop(
            "l",
            ir.IrType.AUTHORITY,
            QSet.AUTHORITIES,
            [
                ir.SetIndex(""),
                ir.AppendIndexLiteral("alpha"),
                ir.AppendIndexLiteral("_{"),
                ir.AppendIndex(ir.IrVar("l"), ir.IrFunc.AUTHORITY_TO_STRING),
                ir.AppendIndexLiteral("}"),
                ir.SampleZ(ir.MSK_ALPHAS.indexed_at(ir.IDX)),
                ir.LiftGt(
                    ir.MPK_ALPHAS.indexed_at(ir.IDX),
                    ir.MSK_ALPHAS.indexed_at(ir.IDX),
                ),
            ],
        ),
        ir.Comment("END SETUP"),
    ]
    assert received == expected
