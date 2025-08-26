from dataclasses import dataclass, field

from pracy.core.idx import Idx
from pracy.core.quant import Quant


@dataclass
class Var:
    name: str
    idcs: list[Idx]
    quants: list[Quant] = field(default_factory=list)

    def is_special(self):
        """Returns `true`, iff `self` is a special variable."""
        return self.name.startswith("<") and self.name.endswith(">")

    def quantify(self, quants: list[Quant]) -> "Var":
        """
        Return a new variable equal to `self` but with the given quantifications added.
        """
        qs = [] if quants is None else quants
        return Var(self.name, self.idcs, self.quants + qs)
