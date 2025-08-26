from dataclasses import dataclass

from sympy import Expr

from pracy.core.fdh import FdhEntry
from pracy.core.poly import Poly
from pracy.core.quant import Quant
from pracy.core.var import Var


@dataclass
class RawSingle:
    entry: Var
    expr: Expr
    quants: list[Quant]


@dataclass
class RawPair:
    lhs: Var
    rhs: Var
    expr: Expr
    quants: list[Quant]


@dataclass
class RawScheme:
    """
    A raw representation of an ABE scheme just after parsing it from JSON.
    In particular, no semantic validation has been performed: the data has
    only been parsed to higher level stuctures.
    """

    master_key_vars: list[Var]
    common_vars: list[Var]
    key_polys: list[Poly]
    cipher_polys: list[Poly]
    decrypt_vec: list[RawSingle]
    decrypt_mat: list[RawPair]
    fdh_map: list[FdhEntry]
