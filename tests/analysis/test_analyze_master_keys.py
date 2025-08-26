import pytest

from pracy.analysis.errors import (
    MasterKeyVarsEmptyError,
    MasterKeyVarsIllegalQuantError,
    MasterKeyVarsIllegalSpecialVarError,
    MasterKeyVarsNonUniqueError,
    MasterKeyVarsTypeError,
    MasterKeyVarsUnusedQuantsError,
)
from pracy.analysis.master_keys import analyze_master_key_vars
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var


def test_master_keys_non_empty():
    master_keys = []
    var_type_map = VarTypeMap()
    with pytest.raises(MasterKeyVarsEmptyError):
        _ = analyze_master_key_vars(var_type_map, master_keys)


def test_master_keys_non_unique_equiv():
    master_keys = [
        Var("alpha", [Idx("x")], [Quant("x", QSet.LABELS)]),
        Var("alpha", [Idx("y")], [Quant("y", QSet.LABELS)]),
    ]
    var_type_map = VarTypeMap()
    with pytest.raises(MasterKeyVarsNonUniqueError):
        _ = analyze_master_key_vars(var_type_map, master_keys)


def test_master_keys_non_unique_sim():
    master_keys = [
        Var("alpha", [Idx("x")], [Quant("x", QSet.LABELS)]),
        Var("alpha", [Idx("y")], [Quant("y", QSet.AUTHORITIES)]),
    ]
    var_type_map = VarTypeMap()
    with pytest.raises(MasterKeyVarsNonUniqueError):
        _ = analyze_master_key_vars(var_type_map, master_keys)


def test_master_keys_ok():
    master_keys = [
        Var("alpha", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
    ]
    var_type_map = VarTypeMap()
    expected = [
        Var("alpha", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
    ]
    received = analyze_master_key_vars(var_type_map, master_keys)
    assert received == expected
    assert len(var_type_map) == 1
    assert var_type_map[master_keys[0]] == VarType.MASTER_KEY_VAR


def test_master_key_illegal_qset():
    master_keys = [
        Var("alpha", [Idx("l")], [Quant("l", QSet.NEG_LSSS_ROWS)]),
    ]
    var_type_map = VarTypeMap()
    with pytest.raises(MasterKeyVarsIllegalQuantError):
        _ = analyze_master_key_vars(var_type_map, master_keys)


def test_master_key_typechecks():
    master_keys = [
        Var(
            "alpha",
            [Idx("l", IMap.TO_ATTR)],
            [Quant("l", QSet.ATTRIBUTE_UNIVERSE)],
        ),
    ]
    var_type_map = VarTypeMap()
    with pytest.raises(MasterKeyVarsTypeError):
        _ = analyze_master_key_vars(var_type_map, master_keys)


def test_master_key_no_unused_quants():
    master_keys = [
        Var(
            "alpha",
            [Idx("k")],
            [Quant("l", QSet.AUTHORITIES)],
        ),
    ]
    var_type_map = VarTypeMap()
    with pytest.raises(MasterKeyVarsUnusedQuantsError):
        _ = analyze_master_key_vars(var_type_map, master_keys)


def test_master_key_var_no_special_symbol():
    master_keys = [Var("<rgid>", [])]
    var_type_map = VarTypeMap()
    with pytest.raises(MasterKeyVarsIllegalSpecialVarError):
        _ = analyze_master_key_vars(var_type_map, master_keys)
