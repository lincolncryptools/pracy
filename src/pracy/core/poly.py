from dataclasses import dataclass

from sympy import Expr, simplify

from pracy.core.group import Group
from pracy.core.idx import Idx
from pracy.core.quant import Quant


@dataclass
class Poly:
    name: str
    idcs: list[Idx]
    quants: list[Quant]
    expr: Expr
    group: Group

    def __eq__(self, other):
        if isinstance(other, Poly):
            return (
                self.name == other.name
                and self.idcs == other.idcs
                and self.quants == other.quants
                and simplify(self.expr - other.expr) == 0
                and self.group == other.group
            )
        return False
