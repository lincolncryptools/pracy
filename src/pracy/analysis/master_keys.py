"""This module provides analysis functions to analyze and verify the master key
variables of an ABE scheme spec.
"""

from pracy.analysis import common
from pracy.analysis.errors import (
    MasterKeyVarsEmptyError,
    MasterKeyVarsIllegalQuantError,
    MasterKeyVarsIllegalSpecialVarError,
    MasterKeyVarsNonUniqueError,
    MasterKeyVarsTypeError,
    MasterKeyVarsUnusedQuantsError,
)
from pracy.core.qset import QSet
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var


def analyze_master_key_vars(var_type_map: VarTypeMap, msks: list[Var]) -> list[Var]:
    """
    Analyze the master key variables of an ABE scheme.

    Concretely, this functions enforces that
    - there is at least one master key var
    - all master keys are "unique" (regarding similarity of variables)
    - no illegal base sets are used for quantifications
    - each master key var type checks
    - no superfluous quantifications appear
    - no master key var is a special variable.

    Master key variables are also registered as such in the `VarTypeMap` for
    later queries.
    """
    allowed_qsets = [QSet.ATTRIBUTE_UNIVERSE, QSet.AUTHORITIES, QSet.LABELS]
    if not msks:
        raise MasterKeyVarsEmptyError()
    if not common.validate_unique_sim(msks):
        raise MasterKeyVarsNonUniqueError()
    if not common.validate_quants(msks, allowed_qsets):
        raise MasterKeyVarsIllegalQuantError()
    if not common.validate_types(msks):
        raise MasterKeyVarsTypeError()
    if not common.validate_all_quants_used(msks):
        raise MasterKeyVarsUnusedQuantsError()
    if not common.validate_special_vars(msks):
        raise MasterKeyVarsIllegalSpecialVarError()
    for msk in msks:
        var_type_map[msk] = VarType.MASTER_KEY_VAR
    return msks
