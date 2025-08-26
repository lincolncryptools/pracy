"""This module provides analysis functions to analyze and verify the primary cipher
polynomials of an ABE scheme spec.
"""

from dataclasses import dataclass, field
from typing import Optional

from pracy.analysis import common
from pracy.analysis.errors import (
    PrimaryPolyIllegalQuantsError,
    PrimaryPolyIllegalSpecialVarError,
    PrimaryPolyInconsistentLoneRandomVarError,
    PrimaryPolyInconsistentNonLoneRandomVarError,
    PrimaryPolyInconsistentPolyError,
    PrimaryPolyInvalidBinaryTermError,
    PrimaryPolyInvalidExpressionError,
    PrimaryPolyInvalidTermError,
    PrimaryPolyInvalidUnaryTermError,
    PrimaryPolyIsSpecialError,
    PrimaryPolyNonUniqueError,
    PrimaryPolysEmptyError,
    PrimaryPolyTypeError,
    PrimaryPolyUnusedQuantsError,
)
from pracy.analysis.expr import Coeff, Term, analyze_expr
from pracy.analysis.variant import AbeVariant
from pracy.core.equiv import EquivSet
from pracy.core.group import Group, GroupMap
from pracy.core.idx import Idx
from pracy.core.poly import Poly
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var
from pracy.frontend.parsing import parse_var


@dataclass
class PrimaryCipherPoly:
    """
    A PrimaryCipherPoly models a single polynomial c_i specified by EncCt of GPES
    (Definition 7).
    """

    @dataclass
    class LoneRandomTerm:
        """
        A LoneRandomTerm models a single summand in a PrimaryCipherPoly which consists
        of a lone random variable and a coefficient (c.f. first sum of c_i in
        Definition 7).
        """

        random_var: Var
        factor: Term = field(default_factory=lambda: Term(Coeff(1)), kw_only=True)

    @dataclass
    class CommonTerm:
        """
        A CommonTerm models a single summand in a PrimaryCipherPoly which consists of a
        non-lone random variable multiplied with a common variable and a coefficient
        (c.f. second sum of c_i in Definition 7).
        """

        random_var: Var
        common_var: Var
        factor: Term = field(default_factory=lambda: Term(Coeff(1)), kw_only=True)

    name: str
    idcs: list[Idx]
    quants: list[Quant]
    group: Group
    lone_random_terms: list[LoneRandomTerm]
    common_terms_plain: list[CommonTerm]
    common_terms_hashed: list[CommonTerm]


def analyze_primary_cipher_polys(
    variant: AbeVariant,
    var_type_map: VarTypeMap,
    group_map: GroupMap,
    cipher_lone_randoms: EquivSet,
    cipher_non_lone_randoms: EquivSet,
    polys: list[Poly],
):
    """
    Analyzes the primary cipher polys of an ABE scheme.

    Concretely, this function enforces that
    - there is at least one primary cipher poly
    - all prim. cipher polys are unique (regarding similarity of variables)
    - all prim. cipher polys are either mapped to G or H
    - each polynomial and all occuring variables type check
    - no prim. cipher polynomial is similar to any variable of another type
    - no (newly discovered) lone var is similar to any var of another type
    - no (newly discovered) non-lone var is similar to any var of another type
    - no prim. cipher poly is a special var
    - no unexpected special vars are used
    - no superfluous quantifications appear
    - no illegal base sets are used for quantifications
    - the expression denoting the polynomial is well formed
    - each term in the expression is either a lone-random or a common-term.

    All primary cipher polys as well as any (newly discovered) variables are also
    registered as such in the `VarTypeMap` for later queries.

    NOTE: all terms are considered not to involve FDH. This is "fixed" later by
    `post_analyze_primary_cipher_polys`.
    """
    if len(polys) == 0:
        raise PrimaryPolysEmptyError()
    if not common.validate_unique_sim(polys):
        raise PrimaryPolyNonUniqueError()
    cipher_polys = []
    analyzer = PrimaryCipherPolyAnalyser(
        variant, var_type_map, group_map, cipher_lone_randoms, cipher_non_lone_randoms
    )
    for prim in polys:
        cp = analyzer.analyze(prim)
        vars = [cp]
        for t in cp.lone_random_terms:
            vars.append(t.random_var.quantify(cp.quants))
        for t in cp.common_terms_plain:
            vars.append(t.random_var.quantify(cp.quants))
            vars.append(t.common_var.quantify(cp.quants))
        for t in cp.common_terms_hashed:
            vars.append(t.random_var.quantify(cp.quants))
            vars.append(t.common_var.quantify(cp.quants))

        if not common.validate_types(vars):
            raise PrimaryPolyTypeError()

        if not common.validate_all_quants_occur(vars, cp.quants):
            raise PrimaryPolyUnusedQuantsError()
        cipher_polys.append(cp)
    return cipher_polys


def post_analyze_primary_cipher_polys(cipher_polys, fdh_map):
    """
    Given a verified FDH map, "fix" the cipher polys by correctly storing terms with FDH
    generated variables.
    """

    def is_hashed(var, poly):
        return fdh_map.is_hashed(var.quantify(poly.quants))

    for poly in cipher_polys:
        terms = poly.common_terms_plain
        poly.common_terms_plain = []
        for t in terms:
            if is_hashed(t.common_var, poly):
                poly.common_terms_hashed.append(t)
            else:
                poly.common_terms_plain.append(t)
    return cipher_polys


class PrimaryCipherPolyAnalyser:

    def __init__(
        self,
        variant: AbeVariant,
        var_type_map: VarTypeMap,
        group_map: GroupMap,
        cipher_lone_randoms: EquivSet,
        cipher_non_lone_randoms: EquivSet,
    ):
        self._variant = variant
        self._var_type_map = var_type_map
        self._group_map = group_map
        self._cipher_lone_randoms = cipher_lone_randoms
        self._cipher_non_lone_randoms = cipher_non_lone_randoms
        self._poly: Optional[Poly] = None
        self._lone_random_terms: list[PrimaryCipherPoly.LoneRandomTerm] = []
        self._common_terms_plain: list[PrimaryCipherPoly.CommonTerm] = []
        self._common_terms_hashed: list[PrimaryCipherPoly.CommonTerm] = []

    def _reset(self):
        self._lone_random_terms = []
        self._common_terms_plain = []
        self._common_terms_hashed = []

    def _is_master_key_var(self, var):
        return self._var_type_map.is_master_key_var(var.quantify(self._poly.quants))

    def _is_common_var(self, var):
        return self._var_type_map.is_common_var(var.quantify(self._poly.quants))

    def analyze(self, poly: Poly) -> PrimaryCipherPoly:
        self._reset()
        self._poly = poly
        if self._poly.name.startswith("<"):
            raise PrimaryPolyIsSpecialError()
        self._var_type_map.expect(
            poly, VarType.CIPHER_PRIMARY_POLY, PrimaryPolyInconsistentPolyError()
        )
        self._group_map[poly] = poly.group
        allowed_q_sets = self._variant.allowed_quants_encrypt()
        if not common.validate_quants([poly], allowed_q_sets):
            raise PrimaryPolyIllegalQuantsError()
        try:
            for t in analyze_expr(poly.expr):
                self._analyze_term(t)

            return PrimaryCipherPoly(
                poly.name,
                poly.idcs,
                poly.quants,
                poly.group,
                self._lone_random_terms,
                self._common_terms_plain,
                self._common_terms_hashed,
            )
        except ValueError as exc:
            raise PrimaryPolyInvalidExpressionError() from exc

    def _analyze_term(self, term):
        # TODO: systematize what counts as "proper" variable and what is a
        # coefficient only
        def is_sym(s):
            return (
                not s.startswith("<")
                or s.startswith("<mu")
                or s.startswith("<secret")
                or s.startswith("<lambda")
            )

        nums = [c for c in term.coeffs if isinstance(c.num, int)]
        specs = [c for c in term.coeffs if isinstance(c.num, str) and not is_sym(c.num)]
        syms = [c for c in term.coeffs if isinstance(c.num, str) and is_sym(c.num)]

        allowed_special_vars = ["<rgid>", "<xattr>", "<lambda>", "<mu>"]
        for s in specs:
            v = parse_var(s.num)
            if v.name not in allowed_special_vars:
                raise PrimaryPolyIllegalSpecialVarError()

        if len(syms) == 1:
            self._analyze_unary_term(nums, specs, syms)
        elif len(syms) == 2:
            self._analyze_binary_term(nums, specs, syms)
        else:
            raise PrimaryPolyInvalidTermError()

    def _analyze_unary_term(self, nums, specs, syms):
        factor = Term(*(nums + specs)) if nums or specs else Term(Coeff(1))
        var = parse_var(syms[0].num)
        if self._is_common_var(var) or self._is_master_key_var(var):
            raise PrimaryPolyInvalidUnaryTermError()
        lone_term = PrimaryCipherPoly.LoneRandomTerm(var, factor=factor)
        self._lone_random_terms.append(lone_term)
        self._process_lone_random(var)

    def _analyze_binary_term(self, nums, specs, syms):
        factor = Term(*(nums + specs)) if nums or specs else Term(Coeff(1))
        lhs, rhs = [parse_var(c.num) for c in syms]
        if self._is_master_key_var(lhs) or self._is_master_key_var(rhs):
            raise PrimaryPolyInvalidBinaryTermError()
        if self._is_common_var(lhs) and not self._is_common_var(rhs):
            random_var = rhs
            common_var = lhs
        elif not self._is_common_var(lhs) and self._is_common_var(rhs):
            random_var = lhs
            common_var = rhs
        else:
            raise PrimaryPolyInvalidBinaryTermError()
        if not random_var.is_special():
            self._process_non_lone_random(random_var)
        common_term = PrimaryCipherPoly.CommonTerm(
            random_var, common_var, factor=factor
        )
        self._common_terms_plain.append(common_term)

    def _process_lone_random(self, var):
        var = var.quantify(self._poly.quants)
        if not var.is_special():
            self._cipher_lone_randoms.update(var)
            self._var_type_map.expect(
                var,
                VarType.CIPHER_LONE_RANDOM,
                PrimaryPolyInconsistentLoneRandomVarError(),
            )

    def _process_non_lone_random(self, var):
        var = var.quantify(self._poly.quants)
        self._cipher_non_lone_randoms.update(var)
        self._var_type_map.expect(
            var,
            VarType.CIPHER_NON_LONE_RANDOM,
            PrimaryPolyInconsistentNonLoneRandomVarError(),
        )
