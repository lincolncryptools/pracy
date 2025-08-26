import pytest

from pracy.analysis.common_vars import analyze_common_vars
from pracy.analysis.errors import (
    CommonVarsEmptyError,
    CommonVarsIllegalQuantError,
    CommonVarsIllegalSpecialVarError,
    CommonVarsNonUniqueError,
    CommonVarsOverlapMasterKeyVarsError,
    CommonVarsTypeError,
    CommonVarsUnusedQuantsError,
)
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var


def test_common_vars_non_empty():
    common_vars = []
    var_type_map = VarTypeMap()
    with pytest.raises(CommonVarsEmptyError):
        _ = analyze_common_vars(var_type_map, common_vars)


def test_common_vars_unique_equiv():
    common_vars = [
        Var("b", [Idx("x")], [Quant("x", QSet.LABELS)]),
        Var("b", [Idx("y")], [Quant("y", QSet.LABELS)]),
    ]
    var_type_map = VarTypeMap()
    with pytest.raises(CommonVarsNonUniqueError):
        _ = analyze_common_vars(var_type_map, common_vars)


def test_common_vars_unique_sim():
    common_vars = [
        Var("b", [Idx("x")], [Quant("x", QSet.LABELS)]),
        Var("b", [Idx("y")], [Quant("y", QSet.AUTHORITIES)]),
    ]
    var_type_map = VarTypeMap()
    with pytest.raises(CommonVarsNonUniqueError):
        _ = analyze_common_vars(var_type_map, common_vars)


def test_common_vars_ok():
    common_vars = [
        Var("b'", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
    ]
    var_type_map = VarTypeMap()
    expected = [
        Var("b'", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
    ]
    received = analyze_common_vars(var_type_map, common_vars)
    assert received == expected
    assert len(var_type_map) == 1
    assert var_type_map[common_vars[0]] == VarType.COMMON_VAR


def test_common_vars_illegal_qset():
    common_vars = [
        Var("b'", [Idx("l")], [Quant("l", QSet.USER_ATTRIBUTES)]),
    ]
    var_type_map = VarTypeMap()
    with pytest.raises(CommonVarsIllegalQuantError):
        _ = analyze_common_vars(var_type_map, common_vars)


def test_common_vars_typecheck():
    common_vars = [
        Var(
            "b",
            [Idx("idx", IMap.TO_ATTR)],
            [Quant("idx", QSet.LABELS)],
        ),
    ]
    var_type_map = VarTypeMap()
    with pytest.raises(CommonVarsTypeError):
        _ = analyze_common_vars(var_type_map, common_vars)


def test_common_vars_no_unused_quants():
    common_vars = [
        Var(
            "b'",
            [Idx("k")],
            [Quant("l", QSet.AUTHORITIES)],
        ),
    ]
    var_type_map = VarTypeMap()
    with pytest.raises(CommonVarsUnusedQuantsError):
        _ = analyze_common_vars(var_type_map, common_vars)


def test_common_vars_var_no_special_symbol():
    common_vars = [Var("<epsilon>", [])]
    var_type_map = VarTypeMap()
    with pytest.raises(CommonVarsIllegalSpecialVarError):
        _ = analyze_common_vars(var_type_map, common_vars)


def test_common_vars_var_overlap_master_key_vars():
    master_key_vars = [Var("x", [Idx("l")], [Quant("l", QSet.AUTHORITIES)])]
    common_vars = [Var("x", [Idx("l")], [Quant("l", QSet.AUTHORITIES)])]
    var_type_map = VarTypeMap()
    var_type_map[master_key_vars[0]] = VarType.MASTER_KEY_VAR
    with pytest.raises(CommonVarsOverlapMasterKeyVarsError):
        _ = analyze_common_vars(var_type_map, common_vars)
