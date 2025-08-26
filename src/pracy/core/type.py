from enum import StrEnum, auto

from pracy.core.equiv import EquivMap
from pracy.core.var import Var


class VarType(StrEnum):
    """An enum to represent what type (i.e., "type") a variable is."""

    MASTER_KEY_VAR = auto()
    COMMON_VAR = auto()
    KEY_LONE_RANDOM_VAR = auto()
    KEY_NON_LONE_RANDOM_VAR = auto()
    KEY_POLY = auto()
    CIPHER_LONE_RANDOM = auto()
    CIPHER_NON_LONE_RANDOM = auto()
    CIPHER_SPECIAL_LONE_RANDOM = auto()
    CIPHER_PRIMARY_POLY = auto()
    CIPHER_SECONDARY_POLY = auto()
    CIPHER_BLINDING_POLY = auto()


class VarTypeMap(EquivMap):
    """
    Stores the "general" types of variables of an ABE scheme.
    """

    def is_master_key_var(self, candidate: Var) -> bool:
        """
        Returns true, iff the given var is equivalent to a known master
        key variable.
        """
        return self.get(candidate, None) == VarType.MASTER_KEY_VAR

    def is_common_var(self, candidate: Var) -> bool:
        """Returns true, iff the given var is equivalent to a known common var."""
        return self.get(candidate, None) == VarType.COMMON_VAR

    def expect(self, var, expectation, on_mismatch):
        """
        Tries to add a (key, value) association to self if it is conflict-free.

        If self contains no matching key, the pair is added.
        If self contains a matching (key, value) pair nothing happens.
        If self contains a conflicting (key, value) pair the exception on_mismatch
        is raised.
        """
        try:
            curr_type = self[var]
            if curr_type != expectation:
                raise on_mismatch
        except KeyError:
            self[var] = expectation
