from dataclasses import dataclass

from pracy.backend.ir.irexpr import IrExpr
from pracy.backend.ir.irfunc import IrFunc
from pracy.backend.ir.irtype import IrType
from pracy.backend.ir.irvar import IrVar
from pracy.core.qset import QSet


class IrStmt:
    pass


@dataclass
class Comment(IrStmt):
    text: str


@dataclass
class Loop(IrStmt):
    var: str
    type: IrType
    set: QSet
    body: list[IrStmt]


@dataclass
class Alloc(IrStmt):
    target: IrVar
    type: IrType
    expr: IrExpr


@dataclass
class Store(IrStmt):
    target: IrVar
    source: IrVar


@dataclass
class StoreExpr(IrStmt):
    target: IrVar
    expr: IrExpr


@dataclass
class ResetZ(IrStmt):
    target: IrVar


@dataclass
class ResetG(IrStmt):
    target: IrVar


@dataclass
class ResetH(IrStmt):
    target: IrVar


@dataclass
class ResetGt(IrStmt):
    target: IrVar


@dataclass
class SampleZ(IrStmt):
    target: IrVar


@dataclass
class AddZ(IrStmt):
    target: IrVar
    lhs: IrVar
    rhs: IrVar


@dataclass
class MulZ(IrStmt):
    target: IrVar
    lhs: IrVar
    rhs: IrVar


@dataclass
class SetZ(IrStmt):
    target: IrVar
    value: str


@dataclass
class NegZ(IrStmt):
    target: IrVar
    source: IrVar


@dataclass
class InvZ(IrStmt):
    target: IrVar
    source: IrVar


@dataclass
class LiftG(IrStmt):
    target: IrVar
    source: IrVar


@dataclass
class AddG(IrStmt):
    target: IrVar
    lhs: IrVar
    rhs: IrVar


@dataclass
class ScaleG(IrStmt):
    target: IrVar
    coeff: IrVar
    source: IrVar


@dataclass
class FdhG(IrStmt):
    target: IrVar
    idx: int
    arg: IrVar


@dataclass
class LiftH(IrStmt):
    target: IrVar
    source: IrVar


@dataclass
class AddH(IrStmt):
    target: IrVar
    lhs: IrVar
    rhs: IrVar


@dataclass
class ScaleH(IrStmt):
    target: IrVar
    coeff: IrVar
    source: IrVar


@dataclass
class FdhH(IrStmt):
    target: IrVar
    idx: int
    arg: IrVar


@dataclass
class LiftGt(IrStmt):
    target: IrVar
    source: IrVar


@dataclass
class AddGt(IrStmt):
    target: IrVar
    lhs: IrVar
    rhs: IrVar


@dataclass
class ScaleGt(IrStmt):
    target: IrVar
    coeff: IrVar
    source: IrVar


@dataclass
class InvGt(IrStmt):
    target: IrVar
    source: IrVar


@dataclass
class Pair(IrStmt):
    target: IrVar
    source_g: IrVar
    source_h: IrVar


@dataclass
class GetRgidG(IrStmt):
    target: IrVar


@dataclass
class GetRgidH(IrStmt):
    target: IrVar


@dataclass
class GetMu(IrStmt):
    target: IrVar
    idx: IrVar


@dataclass
class GetLambda(IrStmt):
    target: IrVar
    idx: IrVar


@dataclass
class GetEpsilon(IrStmt):
    target: IrVar
    idx: IrVar


@dataclass
class GetXAttr(IrStmt):
    target: IrVar
    idx: IrVar


@dataclass
class GetXAttrAlt(IrStmt):
    target: IrVar
    idx: IrVar


@dataclass
class GetSecret(IrStmt):
    target: IrVar


@dataclass
class SetIndex(IrStmt):
    literal: str


@dataclass
class AppendIndexLiteral(IrStmt):
    literal: str


@dataclass
class AppendIndex(IrStmt):
    source: IrVar
    conversion: IrFunc
