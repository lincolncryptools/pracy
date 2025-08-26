from enum import StrEnum

from pracy.backend.ir.irtype import IrType
from pracy.core.qmap import QMap
from pracy.core.qtype import QType


class IrFunc(StrEnum):
    ATTRIBUTE_TO_LABEL = "attr_to_lbl"
    ATTRIBUTE_TO_AUTHORITY = "attr_to_auth"
    ATTRIBUTE_TO_XATTR = "attr_to_xattr"
    LSSS_ROW_TO_AUTHORITY = "ls_row_to_auth"
    LSSS_ROW_TO_LABEL = "ls_row_to_lbl"
    LSSS_ROW_TO_ATTR = "ls_row_to_attr"
    LSSS_ROW_TO_ALT_ATTR = "ls_row_to_alt_attr"
    LSSS_ROW_TO_DEDUP_INDICES = "ls_row_to_dedup"

    ATTRIBUTE_TO_STRING = "attr_to_str"
    LABEL_TO_STRING = "lbl_to_str"
    AUTHORITY_TO_STRING = "auth_to_str"
    LSSS_ROW_TO_STRING = "lsss_row_to_str"
    DEDUP_IDX_TO_STRING = "dedup_idx_to_str"

    @staticmethod
    def to_string_conversion(ir_type: IrType):
        match ir_type:
            case IrType.ATTRIBUTE:
                return IrFunc.ATTRIBUTE_TO_STRING
            case IrType.ALT_ATTR:
                return IrFunc.ATTRIBUTE_TO_STRING
            case IrType.LABEL:
                return IrFunc.LABEL_TO_STRING
            case IrType.AUTHORITY:
                return IrFunc.AUTHORITY_TO_STRING
            case IrType.LSSS_ROW:
                return IrFunc.LSSS_ROW_TO_STRING
            case IrType.DEDUP_INDEX:
                return IrFunc.DEDUP_IDX_TO_STRING
            case _:
                return None

    @staticmethod
    def from_qmap(qmap: QMap):
        match qmap:
            case QMap.ATTRIBUTE_TO_LABEL:
                return IrFunc.ATTRIBUTE_TO_LABEL
            case QMap.ATTRIBUTE_TO_AUTHORITY:
                return IrFunc.ATTRIBUTE_TO_AUTHORITY
            case QMap.ATTRIBUTE_TO_XATTR:
                return IrFunc.ATTRIBUTE_TO_XATTR
            case QMap.LSSS_ROW_TO_AUTHORITY:
                return IrFunc.LSSS_ROW_TO_AUTHORITY
            case QMap.LSSS_ROW_TO_LABEL:
                return IrFunc.LSSS_ROW_TO_LABEL
            case QMap.LSSS_ROW_TO_ATTR:
                return IrFunc.LSSS_ROW_TO_ATTR
            case QMap.LSSS_ROW_TO_ALT_ATTR:
                return IrFunc.LSSS_ROW_TO_ALT_ATTR
            case QMap.LSSS_ROW_TO_DEDUP_INDICES:
                return IrFunc.LSSS_ROW_TO_DEDUP_INDICES

    @staticmethod
    def from_domain_codomain(domain: QType, codomain: QType):
        match domain, codomain:
            case QType.ATTRIBUTE, QType.LABEL:
                return IrFunc.ATTRIBUTE_TO_LABEL
            case QType.ATTRIBUTE, QType.AUTHORITY:
                return IrFunc.ATTRIBUTE_TO_AUTHORITY
            case QType.ATTRIBUTE, QType.XATTR:
                return IrFunc.ATTRIBUTE_TO_XATTR
            case QType.LSSS_ROW, QType.AUTHORITY:
                return IrFunc.LSSS_ROW_TO_AUTHORITY
            case QType.LSSS_ROW, QType.LABEL:
                return IrFunc.LSSS_ROW_TO_LABEL
            case QType.LSSS_ROW, QType.ATTRIBUTE:
                return IrFunc.LSSS_ROW_TO_ATTR
            case QType.LSSS_ROW, QType.ALT_ATTR:
                return IrFunc.LSSS_ROW_TO_ALT_ATTR
            case QType.LSSS_ROW, QType.DEDUP_INDICES:
                return IrFunc.LSSS_ROW_TO_DEDUP_INDICES
