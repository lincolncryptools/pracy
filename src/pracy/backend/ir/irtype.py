from enum import StrEnum

from pracy.core.qtype import QType


class IrType(StrEnum):
    STRING = "-STRING-"
    Z = "-Z-"
    G = "-G-"
    H = "-H-"
    GT = "-GT-"
    ATTRIBUTE = "-ATTR-"
    LABEL = "-LBL-"
    AUTHORITY = "-AUTH-"
    LSSS_ROW = "-LSSS_ROW-"
    DEDUP_INDEX = "-DEDUP_IDX-"
    ALT_ATTR = "-ALT_ATTR-"
    XATTR = "-XATTR-"

    @staticmethod
    def from_qtype(qtype: QType) -> "IrType":
        res = None
        match qtype:
            case QType.ATTRIBUTE:
                res = IrType.ATTRIBUTE
            case QType.LABEL:
                res = IrType.LABEL
            case QType.AUTHORITY:
                res = IrType.AUTHORITY
            case QType.LSSS_ROW:
                res = IrType.LSSS_ROW
            case QType.LINEAR_COMBINATION:
                res = IrType.LSSS_ROW
            case QType.DEDUP_INDICES:
                res = IrType.DEDUP_INDEX
            case QType.ALT_ATTR:
                res = IrType.ALT_ATTR
            case QType.XATTR:
                res = IrType.XATTR
        return res
