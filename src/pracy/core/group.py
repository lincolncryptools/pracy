from enum import StrEnum

from pracy.core.equiv import EquivMap


class Group(StrEnum):
    """An enum to represent the three groups of pairing-based ABE schemes."""

    G = "G"
    H = "H"
    GT = "Gt"

    def flip(self) -> "Group":
        """Compute the "opposite" group of self in a pairing."""
        match self:
            case Group.G:
                return Group.H
            case Group.H:
                return Group.G
            case _:
                raise ValueError("Cannot flip other groups than G and H.")


class GroupMap(EquivMap):
    """
    Stores which variables (e.g. common variables, key polys, etc.) belong to which
    group in the ABE scheme.
    """

    def __init__(self):
        super().__init__(default=lambda _: None)
