from enum import StrEnum

from pracy.core.qtype import QType


class QSet(StrEnum):
    """
    A `QSet` is one of the possible sets over which variables
    and/or polynomials of the ABE scheme may be quantified.
    """

    ATTRIBUTE_UNIVERSE = "ATTR_UNI"
    USER_ATTRIBUTES = "USER_ATTRS"
    LABELS = "LABELS"
    AUTHORITIES = "AUTHS"
    LSSS_ROWS = "LSSS_ROWS"
    POS_LSSS_ROWS = "POS_LSSS_ROWS"
    NEG_LSSS_ROWS = "NEG_LSSS_ROWS"
    DEDUPLICATION_INDICES = "DEDUP_IDCS"
    LINEAR_COMBINATION_INDICES = "LIN_COMB"
    POS_LINEAR_COMBINATION_INDICES = "POS_LIN_COMB"
    NEG_LINEAR_COMBINATION_INDICES = "NEG_LIN_COMB"

    def get_element_type(self) -> QType:
        """
        Return the type of the elements of a `QSet`.

        Note that different sets contain elements of the same type,
        e.g., both the `attributeUniverse` and `userAttributes` contain
        "attributes".
        """
        res = None
        match self:
            case QSet.ATTRIBUTE_UNIVERSE:
                res = QType.ATTRIBUTE
            case QSet.USER_ATTRIBUTES:
                res = QType.ATTRIBUTE
            case QSet.LABELS:
                res = QType.LABEL
            case QSet.AUTHORITIES:
                res = QType.AUTHORITY
            case QSet.LSSS_ROWS:
                res = QType.LSSS_ROW
            case QSet.POS_LSSS_ROWS:
                res = QType.LSSS_ROW
            case QSet.NEG_LSSS_ROWS:
                res = QType.LSSS_ROW
            case QSet.DEDUPLICATION_INDICES:
                res = QType.DEDUP_INDICES
            case QSet.LINEAR_COMBINATION_INDICES:
                res = QType.LSSS_ROW
            case QSet.POS_LINEAR_COMBINATION_INDICES:
                res = QType.LSSS_ROW
            case QSet.NEG_LINEAR_COMBINATION_INDICES:
                res = QType.LSSS_ROW
        return res
