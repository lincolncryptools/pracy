"""This module provides analysis functions to analyze and verify the common
variables of an ABE scheme spec.
"""

from pracy.analysis import common
from pracy.analysis.errors import (
    CommonVarsEmptyError,
    CommonVarsIllegalQuantError,
    CommonVarsIllegalSpecialVarError,
    CommonVarsNonUniqueError,
    CommonVarsOverlapMasterKeyVarsError,
    CommonVarsTypeError,
    CommonVarsUnusedQuantsError,
)
from pracy.core.qset import QSet
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var


def analyze_common_vars(var_type_map: VarTypeMap, cvs: list[Var]) -> list[Var]:
    """
    Analyzes the common variables of an ABE scheme.

    Concretely, this functions enforces that
    - there is at least one common var
    - all common vars are "unique" (regarding similarity of variables)
    - no illegal base sets are used for quantifications
    - each common var type checks
    - no superfluous quantifications appear
    - no common var is similar to any variable of another type
    - no common var is a special variable.

    Common variables are also registered as such in the `VarTypeMap` for
    later queries.
    """
    allowed_qsets = [QSet.ATTRIBUTE_UNIVERSE, QSet.AUTHORITIES, QSet.LABELS]
    if not cvs:
        raise CommonVarsEmptyError()
    if not common.validate_unique_sim(cvs):
        raise CommonVarsNonUniqueError()
    if not common.validate_quants(cvs, allowed_qsets):
        raise CommonVarsIllegalQuantError()
    if not common.validate_types(cvs):
        raise CommonVarsTypeError()
    if not common.validate_all_quants_used(cvs):
        raise CommonVarsUnusedQuantsError()
    if not common.validate_special_vars(cvs):
        raise CommonVarsIllegalSpecialVarError()
    for cv in cvs:
        var_type_map.expect(
            cv, VarType.COMMON_VAR, CommonVarsOverlapMasterKeyVarsError()
        )
    return cvs
