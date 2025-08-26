import pytest

from pracy.analysis.errors import (
    AbeSchemeVariantAmbiguousError,
    AbeSchemeVariantContradictoryError,
)
from pracy.analysis.variant import AbeVariant, analyze_variant
from pracy.core.qset import QSet
from pracy.core.quant import Quant


def test_analyze_variant_ambigious():
    keygen_quants = []
    cipher_quants = []

    with pytest.raises(AbeSchemeVariantAmbiguousError):
        _ = analyze_variant(keygen_quants, cipher_quants)


def test_analyze_variant_contradictory():
    keygen_quants = [Quant("k", QSet.LSSS_ROWS)]
    cipher_quants = [Quant("j", QSet.NEG_LSSS_ROWS)]

    with pytest.raises(AbeSchemeVariantContradictoryError):
        _ = analyze_variant(keygen_quants, cipher_quants)


def test_analyze_variant_kp():
    keygen_quants = [Quant("k", QSet.POS_LSSS_ROWS)]
    cipher_quants = [
        Quant("j", QSet.USER_ATTRIBUTES),
        Quant("j", QSet.ATTRIBUTE_UNIVERSE),
    ]

    expected = AbeVariant.KP_ABE
    received = analyze_variant(keygen_quants, cipher_quants)
    assert received == expected


def test_analyze_variant_cp():
    keygen_quants = [Quant("k", QSet.AUTHORITIES)]
    cipher_quants = [Quant("j", QSet.POS_LSSS_ROWS), Quant("j", QSet.NEG_LSSS_ROWS)]

    expected = AbeVariant.CP_ABE
    received = analyze_variant(keygen_quants, cipher_quants)
    assert received == expected
