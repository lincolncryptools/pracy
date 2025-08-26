from dataclasses import dataclass

from pracy.backend.ir.irfunc import IrFunc
from pracy.backend.ir.irvar import IrVar


class IrExpr:
    pass


@dataclass
class Call(IrExpr):
    func: IrFunc
    args: list[IrExpr]


@dataclass
class Read(IrExpr):
    source: IrVar


@dataclass
class StringLiteral(IrExpr):
    text: str


@dataclass
class IntLiteral(IrExpr):
    value: int
