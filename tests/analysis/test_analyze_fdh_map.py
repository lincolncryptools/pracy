import pytest

from pracy.analysis.errors import (
    FdhMapIllegalQuantError,
    FdhMapIllegalSpecialVarError,
    FdhMapIllegalVarTypeError,
    FdhMapInvalidIndexError,
    FdhMapNonUniqueError,
    FdhMapTypeError,
    FdhMapUnusedQuantsError,
)
from pracy.analysis.fdh_map import analyze_fdh_map
from pracy.core.fdh import FdhEntry, FdhMap
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var


def test_analyze_fdh_map_empty():
    entries = []
    var_type_map = VarTypeMap()

    expected = FdhMap()
    received = analyze_fdh_map(var_type_map, entries)
    assert received == expected


def test_analyze_fdh_map_single():
    v = Var("b", [Idx("l")], [Quant("l", QSet.ATTRIBUTE_UNIVERSE)])
    entries = [
        FdhEntry(v, 3),
    ]
    common_vars = [v]
    var_type_map = VarTypeMap()
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    expected = FdhMap()
    expected[v] = 3
    received = analyze_fdh_map(var_type_map, entries)
    assert received == expected


def test_analyze_fdh_map_multi():
    u = Var("b", [Idx("auth")], [Quant("auth", QSet.AUTHORITIES)])
    v = Var(
        "b'", [Idx("l")], [Quant("l", QSet.ATTRIBUTE_UNIVERSE, QMap.ATTRIBUTE_TO_LABEL)]
    )
    w = Var("r", [])
    entries = [FdhEntry(u, 3), FdhEntry(v, 1), FdhEntry(w, 4)]
    common_vars = [u, v, w]
    var_type_map = VarTypeMap()
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    expected = FdhMap()
    expected[u] = 3
    expected[v] = 1
    expected[w] = 4
    received = analyze_fdh_map(var_type_map, entries)
    assert received == expected


def test_analyze_fdh_map_illegal_var_type_error():
    v = Var("alpha", [Idx("auth")], [Quant("auth", QSet.AUTHORITIES)])
    entries = [FdhEntry(v, 3)]
    var_type_map = VarTypeMap()

    with pytest.raises(FdhMapIllegalVarTypeError):
        _ = analyze_fdh_map(var_type_map, entries)


def test_analyze_fdh_map_non_unique_error_equiv():
    u = Var("b", [Idx("auth")], [Quant("auth", QSet.AUTHORITIES)])
    v = Var("b", [Idx("x")], [Quant("x", QSet.AUTHORITIES)])
    entries = [FdhEntry(u, 3), FdhEntry(v, 3)]
    common_vars = [u, v]
    var_type_map = VarTypeMap()
    var_type_map[common_vars[0]] = VarType.COMMON_VAR

    with pytest.raises(FdhMapNonUniqueError):
        _ = analyze_fdh_map(var_type_map, entries)


def test_analyze_fdh_map_non_unique_error_sim():
    u = Var("b", [Idx("auth")], [Quant("auth", QSet.AUTHORITIES)])
    v = Var("b", [Idx("1")])
    entries = [FdhEntry(u, 3), FdhEntry(v, 3)]
    common_vars = [u, v]
    var_type_map = VarTypeMap()
    var_type_map[common_vars[0]] = VarType.COMMON_VAR
    var_type_map[common_vars[1]] = VarType.COMMON_VAR

    with pytest.raises(FdhMapNonUniqueError):
        _ = analyze_fdh_map(var_type_map, entries)


def test_analyze_fdh_map_illegal_quant_error():
    v = Var("r", [Idx("j")], [Quant("j", QSet.LSSS_ROWS)])
    entries = [FdhEntry(v, 2)]
    common_vars = []
    key_non_lone_randoms = []
    var_type_map = VarTypeMap()
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    for nlr in key_non_lone_randoms:
        var_type_map[nlr] = VarType.KEY_NON_LONE_RANDOM_VAR

    with pytest.raises(FdhMapIllegalQuantError):
        _ = analyze_fdh_map(var_type_map, entries)


def test_analyze_fdh_map_illegal_special_var_error():
    v = Var("<rgid>", [])
    entries = [FdhEntry(v, 2)]
    common_vars = []
    key_non_lone_randoms = []
    var_type_map = VarTypeMap()
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    for nlr in key_non_lone_randoms:
        var_type_map[nlr] = VarType.KEY_NON_LONE_RANDOM_VAR

    with pytest.raises(FdhMapIllegalSpecialVarError):
        _ = analyze_fdh_map(var_type_map, entries)


def test_analyze_fdh_map_type_error():
    v = Var(
        "r",
        [Idx("l", IMap.TO_AUTHORITY)],
        [Quant("l", QSet.ATTRIBUTE_UNIVERSE, QMap.ATTRIBUTE_TO_LABEL)],
    )
    entries = [FdhEntry(v, 9)]
    common_vars = []
    key_non_lone_randoms = []
    var_type_map = VarTypeMap()
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    for nlr in key_non_lone_randoms:
        var_type_map[nlr] = VarType.KEY_NON_LONE_RANDOM_VAR

    with pytest.raises(FdhMapTypeError):
        _ = analyze_fdh_map(var_type_map, entries)


def test_analyze_fdh_map_unused_quants_error():
    v = Var("r", [], [Quant("j", QSet.ATTRIBUTE_UNIVERSE)])
    entries = [FdhEntry(v, 200)]
    common_vars = []
    key_non_lone_randoms = []
    var_type_map = VarTypeMap()
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR
    for nlr in key_non_lone_randoms:
        var_type_map[nlr] = VarType.KEY_NON_LONE_RANDOM_VAR

    with pytest.raises(FdhMapUnusedQuantsError):
        _ = analyze_fdh_map(var_type_map, entries)


def test_analyze_fdh_map_invalid_index():
    v = Var("b", [Idx("l")], [Quant("l", QSet.ATTRIBUTE_UNIVERSE)])
    entries = [
        FdhEntry(v, -3),
    ]
    common_vars = [v]
    var_type_map = VarTypeMap()
    for cv in common_vars:
        var_type_map[cv] = VarType.COMMON_VAR

    with pytest.raises(FdhMapInvalidIndexError):
        _ = analyze_fdh_map(var_type_map, entries)
