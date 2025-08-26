from pracy.analysis import common
from pracy.analysis.errors import (
    FdhMapIllegalQuantError,
    FdhMapIllegalSpecialVarError,
    FdhMapIllegalVarTypeError,
    FdhMapInvalidIndexError,
    FdhMapNonUniqueError,
    FdhMapTypeError,
    FdhMapUnusedQuantsError,
)
from pracy.core.fdh import FdhEntry, FdhMap
from pracy.core.qset import QSet
from pracy.core.type import VarType, VarTypeMap


def analyze_fdh_map(var_type_map: VarTypeMap, raw_entries: list[FdhEntry]):
    """
    Analyze the FDH mappings of an ABE scheme.

    Concretely, this function enforces that
    - each entry is unique (regarding similarity of variables)
    - each hashed variable is either a common var or a non-lone key var
    - each variable type check w.r.t. its indices and quantifications
    - no illegal base sets are used for quantifications
    - no superfluous quantifications appear
    - the FDH index is > 0
    - no special variables are denoted to be hashed.
    """
    allowed_qsets = [
        QSet.ATTRIBUTE_UNIVERSE,
        QSet.USER_ATTRIBUTES,
        QSet.LABELS,
        QSet.AUTHORITIES,
    ]
    vars = [e.var for e in raw_entries]
    if not common.validate_unique_sim(vars):
        raise FdhMapNonUniqueError()
    if not common.validate_all_quants_used(vars):
        raise FdhMapUnusedQuantsError()
    if not common.validate_special_vars(vars):
        raise FdhMapIllegalSpecialVarError()
    if not common.validate_types(vars):
        raise FdhMapTypeError()
    if not common.validate_quants(vars, allowed_qsets):
        raise FdhMapIllegalQuantError()

    def is_common_var(v):
        return var_type_map.get(v, None) == VarType.COMMON_VAR

    def is_non_lone_random(v):
        return var_type_map.get(v, None) == VarType.KEY_NON_LONE_RANDOM_VAR

    fdh_map = FdhMap()
    for e in raw_entries:
        if e.idx <= 0:
            raise FdhMapInvalidIndexError()
        if is_common_var(e.var) or is_non_lone_random(e.var):
            fdh_map[e.var] = e.idx
        else:
            raise FdhMapIllegalVarTypeError()
    return fdh_map
