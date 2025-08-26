from enum import StrEnum


class QType(StrEnum):
    """
    A `QType` models the "type" of an index, such as `attribute` or `authority`.

    This is useful to determine equivalence of quantified variables, since their
    actual index name may differ (e.g., consider `a_{i} for all i in S` and
    `a_{k} for all k in S`.

    This is also required to perform "type checking" between the `QSet` and the
    global and/or local `QMap` given for a quantification and some indices.
    """

    ATTRIBUTE = "*ATTR*"
    LABEL = "*LBL*"
    AUTHORITY = "*AUTH*"
    LSSS_ROW = "*LSSS_ROW*"
    LINEAR_COMBINATION = "*LIN_COMB*"
    DEDUP_INDICES = "*DEDUP_IDCS*"
    XATTR = "*XATTR*"
    ALT_ATTR = "*ALT_ATTR*"
