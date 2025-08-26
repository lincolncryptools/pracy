from enum import StrEnum, auto

from pracy.analysis.errors import (
    AbeSchemeVariantAmbiguousError,
    AbeSchemeVariantContradictoryError,
)
from pracy.core.qset import QSet


class AbeVariant(StrEnum):
    KP_ABE = auto()
    CP_ABE = auto()

    def allowed_quants_keygen(self):
        match self:
            case AbeVariant.KP_ABE:
                return [
                    QSet.ATTRIBUTE_UNIVERSE,
                    QSet.LABELS,
                    QSet.AUTHORITIES,
                    QSet.LSSS_ROWS,
                    QSet.POS_LSSS_ROWS,
                    QSet.NEG_LSSS_ROWS,
                    QSet.DEDUPLICATION_INDICES,
                ]
            case AbeVariant.CP_ABE:
                return [
                    QSet.ATTRIBUTE_UNIVERSE,
                    QSet.USER_ATTRIBUTES,
                    QSet.LABELS,
                    QSet.AUTHORITIES,
                ]

    def allowed_quants_encrypt(self):
        match self:
            case AbeVariant.KP_ABE:
                return AbeVariant.CP_ABE.allowed_quants_keygen()
            case AbeVariant.CP_ABE:
                return AbeVariant.KP_ABE.allowed_quants_keygen()


def analyze_variant(keygen_quants, cipher_quants) -> AbeVariant:
    """
    Heuristically determines whether an ABE scheme is a CP- or KP-ABE
    scheme.

    The functions expects lists of all quantifications used during
    key generation (i.e. quantifications on key polys) and all quantifications
    used during encryption (i.e. quantifications on cipher polys).
    """

    keygen_qsets = {q.base_set for q in keygen_quants}
    cipher_qsets = {q.base_set for q in cipher_quants}

    keygen_kp_ref = AbeVariant.KP_ABE.allowed_quants_keygen()
    keygen_cp_ref = AbeVariant.CP_ABE.allowed_quants_keygen()
    encrypt_kp_ref = AbeVariant.KP_ABE.allowed_quants_encrypt()
    encrypt_cp_ref = AbeVariant.CP_ABE.allowed_quants_encrypt()

    could_be_kp = keygen_qsets.issubset(keygen_kp_ref) and cipher_qsets.issubset(
        encrypt_kp_ref
    )
    could_be_cp = keygen_qsets.issubset(keygen_cp_ref) and cipher_qsets.issubset(
        encrypt_cp_ref
    )

    if could_be_kp and not could_be_cp:
        return AbeVariant.KP_ABE
    if not could_be_kp and could_be_cp:
        return AbeVariant.CP_ABE
    if could_be_kp and could_be_cp:
        raise AbeSchemeVariantAmbiguousError()
    raise AbeSchemeVariantContradictoryError()
