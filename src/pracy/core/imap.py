from enum import StrEnum

from pracy.core.qtype import QType


class IMap(StrEnum):
    """
    A `IMap` is a mapping function which can be applied to indices
    of variables or polynomials.
    """

    TO_ATTR = "attr"
    TO_LABEL = "lbl"
    TO_AUTHORITY = "auth"
    TO_XATTR = "xattr"
    TO_ALT_ATTR = "alt_attr"
    TO_DEDUP_INDICES = "dedup"

    def get_allowed_domain_types(self) -> list[QType]:
        """
        Get the allowed element types of the domain of `self.`
        (i.e. *before* mapping).
        """
        match self:
            case IMap.TO_LABEL:
                return [QType.ATTRIBUTE, QType.LSSS_ROW]
            case IMap.TO_AUTHORITY:
                return [QType.ATTRIBUTE, QType.LSSS_ROW]
            case IMap.TO_XATTR:
                return [QType.ATTRIBUTE, QType.LSSS_ROW]
            case IMap.TO_ATTR:
                return [QType.LSSS_ROW]
            case IMap.TO_ALT_ATTR:
                return [QType.LSSS_ROW]
            case IMap.TO_DEDUP_INDICES:
                return [QType.LSSS_ROW]

    def get_codomain_type(self) -> QType:
        """Get the element type of the codomain of `self` (i.e. *after* mapping)."""
        res = None
        match self:
            case IMap.TO_LABEL:
                res = QType.LABEL
            case IMap.TO_AUTHORITY:
                res = QType.AUTHORITY
            case IMap.TO_XATTR:
                res = QType.ATTRIBUTE
            case IMap.TO_AUTHORITY:
                res = QType.AUTHORITY
            case IMap.TO_LABEL:
                res = QType.LABEL
            case IMap.TO_ATTR:
                res = QType.ATTRIBUTE
            case IMap.TO_ALT_ATTR:
                res = QType.ALT_ATTR
            case IMap.TO_DEDUP_INDICES:
                res = QType.DEDUP_INDICES
            case IMap.TO_XATTR:
                res = QType.ATTRIBUTE
        return res
