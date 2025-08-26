"""
This module provides functions to analyze and verify the "pairs" of
an ABE scheme spec.
"""

from dataclasses import dataclass

from pracy.analysis import common
from pracy.analysis.errors import (
    PairIllegalGroupCombination,
    PairInconsistentVarTypeError,
    PairInvalidExpressionError,
    PairsIllegalSpecialVarError,
    PairsTypeError,
    PairUnusedQuantsError,
)
from pracy.analysis.expr import Term, analyze_expr
from pracy.core.group import Group
from pracy.core.quant import Quant
from pracy.core.type import VarType
from pracy.core.var import Var
from pracy.frontend.parsing import parse_var


@dataclass
class Pair:
    """
    A Pair models two variables which need to be paired during decryption.
    The associated quantifications (e.g. `QSet.POS_LSSS_ROWS` or `QSet.NEG_LSSS_ROWS`)
    can be used to control "conditional" usage during decryption.

    Each Pair corresponds to either `sEK` or `cE'r` of the correctness equation
    `c'*e + sEk + cE'r` and complementes the `Single`s.
    """

    arg_g: Var
    arg_h: Var
    terms: list[Term]
    quants: list[Quant]


def analyze_pairs(var_type_map, group_map, raw_pairs) -> list[Pair]:
    """
    Analyzes the pairs of an ABE scheme.

    Concretely, this function enforces that
    - the expression is well formed
    - no unexpected special vars are used
    - no superfluous quantifications appear
    - each pairing argument and all vars in the expression type check
    - all pairing arguments have matching var types
      - cipher non-lone vars are paired with key polys (either order)
      - key non-lone vars are paired with primary cipher polys (either order)
    - the arguments are in opposite source groups

    The pairing arguments are "normalized" which means that the order is "fixed"
    to first have the argument in G and then the one in H.
    """
    pairs = []
    for p in raw_pairs:
        try:
            terms = analyze_expr(p.expr)
        except ValueError as exc:
            raise PairInvalidExpressionError() from exc
        except NotImplementedError as exc:
            raise PairInvalidExpressionError() from exc
        arg_g, arg_h = _normalize_pair(p, group_map)

        _validate_var_types(var_type_map, arg_g, arg_h, p.quants)

        all_vars = [arg_g.quantify(p.quants), arg_h.quantify(p.quants)]
        for t in terms:
            for c in t.coeffs:
                if isinstance(c.num, str):
                    all_vars.append(parse_var(c.num).quantify(p.quants))

        if not common.validate_types(all_vars):
            raise PairsTypeError()

        if not common.validate_all_quants_occur(all_vars, p.quants or []):
            raise PairUnusedQuantsError()

        allowed_special_vars = ["<rgid>", "<epsilon>", "<secret>"]

        for var in all_vars:
            if var.name.startswith("<") and var.name not in allowed_special_vars:
                raise PairsIllegalSpecialVarError()

        pair = Pair(arg_g, arg_h, terms, p.quants)
        pairs.append(pair)
    return pairs


def _normalize_pair(pair, group_map):
    if pair.lhs.is_special() or pair.rhs.is_special():
        return _normalize_special_pair(pair, group_map)

    lhs_group = group_map[pair.lhs.quantify(pair.quants)]
    rhs_group = group_map[pair.rhs.quantify(pair.quants)]

    match lhs_group, rhs_group:
        case Group.G, Group.H:
            return pair.lhs, pair.rhs
        case Group.H, Group.G:
            return pair.rhs, pair.lhs
        case _:
            raise PairIllegalGroupCombination()


def _normalize_special_pair(pair, group_map):

    if pair.lhs.is_special() and not pair.rhs.is_special():
        if pair.lhs.name == "<rgid>":
            lhs_group = group_map[pair.lhs]
            rhs_group = group_map[pair.rhs.quantify(pair.quants)]
            if lhs_group == rhs_group:
                raise PairIllegalGroupCombination()
            if lhs_group == Group.G:
                return pair.lhs, pair.rhs
            return pair.rhs, pair.lhs
        else:
            if group_map[pair.rhs.quantify(pair.quants)] == Group.H:
                return pair.lhs, pair.rhs
            return pair.rhs, pair.lhs
    elif not pair.lhs.is_special() and pair.rhs.is_special():
        if pair.rhs.name == "<rgid>":
            lhs_group = group_map[pair.lhs.quantify(pair.quants)]
            rhs_group = group_map[pair.rhs]
            if lhs_group == rhs_group:
                raise PairIllegalGroupCombination()
            if lhs_group == Group.G:
                return pair.lhs, pair.rhs
            return pair.rhs, pair.lhs
        else:
            if group_map[pair.lhs.quantify(pair.quants)] == Group.H:
                return pair.rhs, pair.lhs
            return pair.lhs, pair.rhs
    raise NotImplementedError()


def _validate_var_types(var_type_map, lhs, rhs, quants):
    if lhs.is_special() or rhs.is_special():
        return

    lhs_type = var_type_map[lhs.quantify(quants)]
    rhs_type = var_type_map[rhs.quantify(quants)]

    match lhs_type, rhs_type:
        case VarType.KEY_NON_LONE_RANDOM_VAR, VarType.CIPHER_PRIMARY_POLY:
            pass
        case VarType.CIPHER_PRIMARY_POLY, VarType.KEY_NON_LONE_RANDOM_VAR:
            pass

        case VarType.KEY_POLY, VarType.CIPHER_NON_LONE_RANDOM:
            pass
        case VarType.CIPHER_NON_LONE_RANDOM, VarType.KEY_POLY:
            pass

        case _:
            raise PairInconsistentVarTypeError()
