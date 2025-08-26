"""
This module provides functions to analyze and verify the "singles" of
an ABE scheme spec.
"""

from dataclasses import dataclass

from pracy.analysis import common
from pracy.analysis.errors import (
    SingleInconsistentVarType,
    SingleInvalidExpressionError,
    SinglesIllegalSpecialVarError,
    SinglesTypeError,
    SingleUnusedQuantsError,
)
from pracy.analysis.expr import Term, analyze_expr
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var
from pracy.frontend.parsing import parse_var


@dataclass
class Single:
    """
    A Single models a secondary cipher poly which is exponentiated with a
    custom exponent. It corresponds to the c'*e part of the correctness
    equation c'*e + sEk + cE'r.
    """

    entry: Var
    coeff: list[Term]
    quants: list[Quant]


def analyze_singles(var_type_map: VarTypeMap, raw_singles) -> list[Single]:
    """
    Analyzes the singles of an ABE scheme.

    Concretely, this function enforces that
    - the expresssion is well formed
    - no unexpected special vars are used
    - no superfluous quantifications appear
    - the sec. cipher polynomial and the vars in the expression all type check
    - all singles only refer to sec. cipher polys
    """
    singles = []
    for s in raw_singles:
        try:
            terms = analyze_expr(s.expr)
        except ValueError as exc:
            raise SingleInvalidExpressionError() from exc
        except NotImplementedError as exc:
            raise SingleInvalidExpressionError() from exc

        if var_type_map[s.entry.quantify(s.quants)] != VarType.CIPHER_SECONDARY_POLY:
            raise SingleInconsistentVarType()

        all_vars = [s.entry]
        for t in terms:
            for c in t.coeffs:
                if isinstance(c.num, str):
                    all_vars.append(parse_var(c.num).quantify(s.quants))
                for d in c.denom:
                    if isinstance(d, str):
                        all_vars.append(parse_var(d).quantify(s.quants))

        if not common.validate_types(all_vars):
            raise SinglesTypeError()

        if not common.validate_all_quants_occur(all_vars, s.quants):
            raise SingleUnusedQuantsError()

        allowed_special_vars = [
            "<rgid>",
            "<epsilon>",
        ]

        for var in all_vars:
            if var.name.startswith("<") and var.name not in allowed_special_vars:
                raise SinglesIllegalSpecialVarError()

        single = Single(s.entry, terms, s.quants)
        singles.append(single)
    return singles
