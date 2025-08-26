from enum import StrEnum

from pracy.core.qtype import QType


class QMap(StrEnum):
    """
    A `QMap` is a mapping function which can be applied to base sets
    of quantifications of variables or polynomials.
    """

    ATTRIBUTE_TO_LABEL = "attr_to_lbl"
    ATTRIBUTE_TO_AUTHORITY = "attr_to_auth"
    ATTRIBUTE_TO_XATTR = "attr_to_xattr"
    LSSS_ROW_TO_AUTHORITY = "ls_row_to_auth"
    LSSS_ROW_TO_LABEL = "ls_row_to_lbl"
    LSSS_ROW_TO_ATTR = "ls_row_to_attr"
    LSSS_ROW_TO_ALT_ATTR = "ls_row_to_alt_attr"
    LSSS_ROW_TO_DEDUP_INDICES = "ls_row_to_dedup"
    LSSS_ROW_TO_XATTR = "ls_row_to_xattr"

    def get_domain_type(self) -> QType:
        """Get the element type of the domain of `self.` (i.e. *before* mapping)."""
        res = None
        match self:
            case QMap.ATTRIBUTE_TO_LABEL:
                res = QType.ATTRIBUTE
            case QMap.ATTRIBUTE_TO_AUTHORITY:
                res = QType.ATTRIBUTE
            case QMap.ATTRIBUTE_TO_XATTR:
                res = QType.ATTRIBUTE
            case QMap.LSSS_ROW_TO_AUTHORITY:
                res = QType.LSSS_ROW
            case QMap.LSSS_ROW_TO_LABEL:
                res = QType.LSSS_ROW
            case QMap.LSSS_ROW_TO_ATTR:
                res = QType.LSSS_ROW
            case QMap.LSSS_ROW_TO_ALT_ATTR:
                res = QType.LSSS_ROW
            case QMap.LSSS_ROW_TO_DEDUP_INDICES:
                res = QType.LSSS_ROW
            case QMap.LSSS_ROW_TO_XATTR:
                res = QType.LSSS_ROW
        return res

    def get_codomain_type(self) -> QType:
        """Get the element type of the codomain of `self` (i.e. *after* mapping)."""
        res = None
        match self:
            case QMap.ATTRIBUTE_TO_LABEL:
                res = QType.LABEL
            case QMap.ATTRIBUTE_TO_AUTHORITY:
                res = QType.AUTHORITY
            case QMap.ATTRIBUTE_TO_XATTR:
                res = QType.ATTRIBUTE
            case QMap.LSSS_ROW_TO_AUTHORITY:
                res = QType.AUTHORITY
            case QMap.LSSS_ROW_TO_LABEL:
                res = QType.LABEL
            case QMap.LSSS_ROW_TO_ATTR:
                res = QType.ATTRIBUTE
            case QMap.LSSS_ROW_TO_ALT_ATTR:
                res = QType.ALT_ATTR
            case QMap.LSSS_ROW_TO_DEDUP_INDICES:
                res = QType.DEDUP_INDICES
            case QMap.LSSS_ROW_TO_XATTR:
                res = QType.ATTRIBUTE
        return res
