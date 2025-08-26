"""This module provides analysis functions to analyze and verify the key
polynomials of an ABE scheme spec.
"""

from dataclasses import dataclass, field
from typing import Any, Optional

from pracy.analysis import common
from pracy.analysis.errors import (
    KeyPolyIllegalQuantsError,
    KeyPolyIllegalSpecialVarError,
    KeyPolyInconsistentLoneRandomVar,
    KeyPolyInconsistentNonLoneRandomVar,
    KeyPolyInconsistentPoly,
    KeyPolyInvalidBinaryTermError,
    KeyPolyInvalidExpressionError,
    KeyPolyInvalidGroupError,
    KeyPolyInvalidTermError,
    KeyPolyInvalidUnaryTermError,
    KeyPolyIsSpecialError,
    KeyPolysEmptyError,
    KeyPolysNonUniqueError,
    KeyPolyTypeError,
    KeyPolyUncomputableTermError,
    KeyPolyUnusedQuantsError,
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
class KeyPoly:
    """
    A KeyPoly models a single polynomials k_i specified by EncKey of GPES
    (Definition 7).
    """

    @dataclass
    class MasterKeyTerm:
        """
        A MasterKeyTerm models a single summand in a KeyPoly which consists of a
        master key variable and a coefficient (c.f. first sum of k_i in
        Definition 7).
        """

        master_key_var: Var
        factor: Term = field(default_factory=lambda: Term(Coeff(1)), kw_only=True)

    @dataclass
    class LoneRandomTerm:
        """
        A LoneRandomTerm models a single summand in a KeyPoly which consists of a lone
        random variable and a coefficient (c.f. second sum of k_i in Definition 7).
        """

        random_var: Var
        factor: Term = field(default_factory=lambda: Term(Coeff(1)), kw_only=True)

    @dataclass
    class CommonTerm:
        """
        A CommonTerm models a single summand in a KeyPoly which consists of a non-lone
        random variable multiplied with a common variable and a coefficient (c.f. third
        sum of k_i in Definition 7).
        """

        random_var: Var
        common_var: Var
        factor: Term = field(default_factory=lambda: Term(Coeff(1)), kw_only=True)

    name: str
    idcs: list[Idx]
    quants: list[Quant]
    group: Group
    master_key_terms: list[MasterKeyTerm]
    lone_random_terms: list[LoneRandomTerm]
    common_terms_plain: list[CommonTerm]
    common_terms_random_hashed: list[CommonTerm]
    common_terms_common_hashed: list[CommonTerm]


def analyze_key_polys(
    variant: AbeVariant,
    var_type_map: VarTypeMap,
    group_map: GroupMap,
    key_lone_randoms: EquivSet,
    key_non_lone_randoms: EquivSet,
    raw_polys: list[Poly],
):
    """
    Analyzes the key polys of an ABE scheme.

    Concretely, this function enforces that
    - there is at least one key polynomial
    - all key polys are "unique" (regarding similarity of variables)
    - all key polys are either mapped to G or H
    - each polynomial and all occuring variables type check
    - no key polynomial is similar to any variable of another type
    - no (newly discovered) lone var is similar to any var of another type
    - no (newly discovered) non-lone var is simiar to any var of another type
    - no key polynomial is a special var
    - no unexpected special vars are used
    - no superfluous quantifications appear
    - no illegal base sets are used for quantifications
    - the expression denoting the polynomial is well formed
    - each term in the expression is either a master-key, lone-random or common-term

    All key polys as well as any (newly discovered) variables are also registered as
    such in the `VarTypeMap` for later queries.

    NOTE: all terms are considered not to involve FDH. This is "fixed" later by
    `post_analyze_key_polys`.
    """
    if len(raw_polys) == 0:
        raise KeyPolysEmptyError()
    if not common.validate_unique_sim(raw_polys):
        raise KeyPolysNonUniqueError()
    key_polys = []
    analyzer = _KeyPolyAnalyser(
        variant, var_type_map, group_map, key_lone_randoms, key_non_lone_randoms
    )
    for p in raw_polys:
        kp = analyzer.analyze(p)
        all_vars: list[Any] = [p]
        for t in kp.master_key_terms:
            all_vars.append(t.master_key_var.quantify(p.quants))
        for t in kp.lone_random_terms:
            all_vars.append(t.random_var.quantify(p.quants))
        for t in kp.common_terms_plain:
            all_vars.append(t.random_var.quantify(p.quants))
            all_vars.append(t.common_var.quantify(p.quants))
        if not common.validate_types(all_vars):
            raise KeyPolyTypeError()

        if not common.validate_all_quants_occur(all_vars, p.quants):
            raise KeyPolyUnusedQuantsError()

        key_polys.append(kp)

    return key_polys


def post_analyze_key_polys(key_polys, fdh_map):
    """
    Given a verified FDH map, "fix" the key polys by correctly storing terms with FDH
    generated variables.

    This function also enforces that not both components (i.e., random and common var)
    are hashed, as such a term is not computable.
    """

    def is_hashed(var, poly):
        return fdh_map.is_hashed(var.quantify(poly.quants))

    for poly in key_polys:
        terms = poly.common_terms_plain
        poly.common_terms_plain = []
        for t in terms:
            if t.random_var.name == "<rgid>":
                if is_hashed(t.common_var, poly):
                    raise KeyPolyUncomputableTermError()
                poly.common_terms_random_hashed.append(t)
            else:
                match is_hashed(t.random_var, poly), is_hashed(t.common_var, poly):
                    case False, False:
                        poly.common_terms_plain.append(t)
                    case True, False:
                        poly.common_terms_random_hashed.append(t)
                    case False, True:
                        poly.common_terms_common_hashed.append(t)
                    case True, True:
                        raise KeyPolyUncomputableTermError()
    return key_polys


class _KeyPolyAnalyser:

    def __init__(
        self,
        variant: AbeVariant,
        var_type_map: VarTypeMap,
        group_map: GroupMap,
        key_lone_randoms: EquivSet,
        key_non_lone_randoms: EquivSet,
    ):
        self._variant = variant
        self._var_type_map = var_type_map
        self._group_map = group_map
        self._key_lone_randoms = key_lone_randoms
        self._key_non_lone_randoms = key_non_lone_randoms
        self._poly: Optional[Poly] = None
        self._master_key_terms: list[KeyPoly.MasterKeyTerm] = []
        self._lone_random_terms: list[KeyPoly.LoneRandomTerm] = []
        self._common_terms: list[KeyPoly.CommonTerm] = []

    def _reset(self):
        self._master_key_terms = []
        self._lone_random_terms = []
        self._common_terms = []

    def _is_master_key_var(self, var):
        return self._var_type_map.is_master_key_var(var.quantify(self._poly.quants))

    def _is_common_var(self, var):
        return self._var_type_map.is_common_var(var.quantify(self._poly.quants))

    def analyze(self, poly: Poly) -> KeyPoly:
        self._reset()
        self._poly = poly
        if self._poly.name.startswith("<"):
            raise KeyPolyIsSpecialError()
        self._var_type_map.expect(poly, VarType.KEY_POLY, KeyPolyInconsistentPoly())
        if poly.group not in [Group.G, Group.H]:
            raise KeyPolyInvalidGroupError()
        self._group_map[poly] = poly.group
        allowed_qsets = self._variant.allowed_quants_keygen()
        if not common.validate_quants([poly], allowed_qsets):
            raise KeyPolyIllegalQuantsError()
        try:
            for t in analyze_expr(poly.expr):
                self._analyze_term(t)

            return KeyPoly(
                poly.name,
                poly.idcs,
                poly.quants,
                poly.group,
                self._master_key_terms,
                self._lone_random_terms,
                self._common_terms,
                [],
                [],
            )
        except ValueError as exc:
            raise KeyPolyInvalidExpressionError() from exc

    def _analyze_term(self, term):
        # TODO: systematize what counts as "proper" variable and
        # what is a coefficient only
        def is_sym(s):
            return not s.startswith("<") or s.startswith("<rgid")

        nums = [c for c in term.coeffs if isinstance(c.num, int)]
        specs = [c for c in term.coeffs if isinstance(c.num, str) and not is_sym(c.num)]
        syms = [c for c in term.coeffs if isinstance(c.num, str) and is_sym(c.num)]

        allowed_special_vars = ["<rgid>", "<xattr>"]
        for s in specs:
            v = parse_var(s.num)
            if v.name not in allowed_special_vars:
                raise KeyPolyIllegalSpecialVarError()

        if len(syms) == 1:
            self._analyze_unary_term(nums, specs, syms)
        elif len(syms) == 2:
            self._analyze_binary_term(nums, specs, syms)
        else:
            raise KeyPolyInvalidTermError()

    def _analyze_unary_term(self, nums, specs, syms):
        factor = Term(*(nums + specs)) if nums or specs else Term(Coeff(1))
        var = parse_var(syms[0].num)
        if self._is_master_key_var(var):
            master_term = KeyPoly.MasterKeyTerm(var, factor=factor)
            self._master_key_terms.append(master_term)
        elif self._is_common_var(var):
            raise KeyPolyInvalidUnaryTermError()
        else:
            lone_term = KeyPoly.LoneRandomTerm(var, factor=factor)
            self._lone_random_terms.append(lone_term)
            self._process_lone_random(var)

    def _analyze_binary_term(self, nums, specs, syms):
        factor = Term(*(nums + specs)) if nums or specs else Term(Coeff(1))
        lhs, rhs = [parse_var(c.num) for c in syms]
        if self._is_common_var(lhs) and not self._is_common_var(rhs):
            random_var = rhs
            common_var = lhs
        elif not self._is_common_var(lhs) and self._is_common_var(rhs):
            random_var = lhs
            common_var = rhs
        else:
            raise KeyPolyInvalidBinaryTermError()
        self._process_non_lone_random(random_var)
        common_term = KeyPoly.CommonTerm(random_var, common_var, factor=factor)
        self._common_terms.append(common_term)

    def _process_lone_random(self, var):
        var = var.quantify(self._poly.quants)
        self._key_lone_randoms.update(var)
        self._var_type_map.expect(
            var, VarType.KEY_LONE_RANDOM_VAR, KeyPolyInconsistentLoneRandomVar()
        )

    def _process_non_lone_random(self, var):
        if not var.is_special():
            var = var.quantify(self._poly.quants)
            self._key_non_lone_randoms.update(var)
            self._var_type_map.expect(
                var,
                VarType.KEY_NON_LONE_RANDOM_VAR,
                KeyPolyInconsistentNonLoneRandomVar(),
            )
        elif var.name == "<rgid>":
            self._group_map[var] = self._poly.group
