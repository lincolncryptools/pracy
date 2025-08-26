from dataclasses import dataclass

from pracy.core.equiv import EquivMap
from pracy.core.var import Var


@dataclass
class FdhEntry:
    var: Var
    idx: int


class FdhMap(EquivMap):
    """
    Stores which variables (i.e. common or random variables) are produced by an
    FDH in the ABE scheme.

    The index `0` indicates, that a variable is *not* hashed, whereas an index  `i > 0`
    indicates that the corresponding variable is produced by hash function `i`.
    """

    def __init__(self):
        super().__init__(default=lambda _: 0)

    def is_hashed(self, var):
        return var in self and self[var] != 0
