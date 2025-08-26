import pytest

from pracy.analysis.typechecking import TypeError, typecheck_idx
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant


def test_typecheck_empty_quants_ok():
    idx = Idx("k")
    quants = []
    expected = None
    received = typecheck_idx(idx, quants)
    assert expected == received


def test_typecheck_unquantified_ok():
    idx = Idx("k")
    quants = [Quant("j", QSet.AUTHORITIES)]
    expected = None
    received = typecheck_idx(idx, quants)
    assert expected == received


def test_typecheck_quantified_ok():
    idx = Idx("k")
    quants = [Quant("k", QSet.LSSS_ROWS)]
    expected = None
    received = typecheck_idx(idx, quants)
    assert expected == received


def test_typecheck_global_map_ok():
    idx = Idx("k")
    quants = [Quant("k", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_LABEL)]
    expected = None
    received = typecheck_idx(idx, quants)
    assert expected == received


def test_typecheck_local_map_ok():
    idx = Idx("k", IMap.TO_AUTHORITY)
    quants = [Quant("k", QSet.LSSS_ROWS)]
    expected = None
    received = typecheck_idx(idx, quants)
    assert expected == received


def test_typecheck_combined_ok():
    idx = Idx("p", IMap.TO_AUTHORITY)
    quants = [Quant("p", QSet.LSSS_ROWS, QMap.LSSS_ROW_TO_ATTR)]
    expected = None
    received = typecheck_idx(idx, quants)
    assert expected == received


def test_typecheck_global_map_error():
    idx = Idx("n")
    quants = [Quant("n", QSet.LSSS_ROWS, QMap.ATTRIBUTE_TO_XATTR)]
    expected = TypeError(QSet.LSSS_ROWS, global_map=QMap.ATTRIBUTE_TO_XATTR)
    received = typecheck_idx(idx, quants)
    assert expected == received


def test_typecheck_local_map_error():
    idx = Idx("n", IMap.TO_ATTR)
    quants = [Quant("n", QSet.ATTRIBUTE_UNIVERSE)]
    expected = TypeError(QSet.ATTRIBUTE_UNIVERSE, local_map=IMap.TO_ATTR)
    received = typecheck_idx(idx, quants)
    assert expected == received


def test_typecheck_multi_quants_raises():
    with pytest.raises(ValueError):
        idx = Idx("n")
        quants = [Quant("n", QSet.ATTRIBUTE_UNIVERSE), Quant("n", QSet.LABELS)]
        _ = typecheck_idx(idx, quants)
