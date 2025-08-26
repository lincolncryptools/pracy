from dataclasses import dataclass, field
from typing import Optional

from pracy.analysis import common
from pracy.analysis.errors import (
    BlindingPolyAmbigiousError,
    BlindingPolyIllegalSpecialVarError,
    BlindingPolyInconsistentNonLoneRandomVarError,
    BlindingPolyInconsistentPolyError,
    BlindingPolyInconsistentSpecialLoneRandomVarError,
    BlindingPolyInvalidBinaryTermError,
    BlindingPolyInvalidExpressionError,
    BlindingPolyInvalidGroupError,
    BlindingPolyInvalidNameError,
    BlindingPolyInvalidTermError,
    BlindingPolyInvalidUnaryTermError,
    BlindingPolyIsIndexedError,
    BlindingPolyIsQuantifiedError,
    BlindingPolyIsSpecialError,
    BlindingPolyMissingError,
    BlindingPolyTypeError,
)
from pracy.analysis.expr import Coeff, Term, analyze_expr
from pracy.core.equiv import EquivSet
from pracy.core.group import Group
from pracy.core.idx import Idx
from pracy.core.poly import Poly
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var
from pracy.frontend.parsing import parse_var


@dataclass
class BlindingPoly:
    """
    The BlindingPoly models the polynomial c_m specified by EncCt of GPES
    (Definition 7).
    """

    @dataclass
    class SpecialLoneRandomTerm:
        """
        A SpecialLoneRandomTerm models a single summand in a BlindingCpoly which
        consists of a special-lone random variable and a coefficient (c.f. first sum of
        c_m in Definition 7).
        """

        random_var: Var
        factor: Term = field(default_factory=lambda: Term(Coeff(1)), kw_only=True)

    @dataclass
    class MasterKeyTerm:
        """
        A MasterKeyTerm models a single summand in a BlindingPoly which consists
        of a non-lone random variable multiplied with a master key variable and a
        coefficient (c.f. second sum of c_m in Definition 7).
        """

        random_var: Var
        master_key_var: Var
        factor: Term = field(default_factory=lambda: Term(Coeff(1)), kw_only=True)

    name: str
    idcs: list[Idx]
    quants: list[Quant]
    group: Group
    special_lone_random_terms: list[SpecialLoneRandomTerm]
    master_key_terms: list[MasterKeyTerm]


def analyze_blinding_poly(
    var_type_map: VarTypeMap,
    cipher_non_lone_randoms: EquivSet,
    cipher_special_lone_randoms: EquivSet,
    polys: list[Poly],
):
    """
    Analyzes the blinding poly of an ABE scheme.

    Concretely, this function enforces that
    - there is exactly one blinding polynomial given
    - the blinding poly is mapped to Gt
    - the blinding poly is not quantified
    - the blinding poly has no indices
    - the blinding poly is named "cm"
    - the blinding poly is not a special var itself
    - no unexpected special vars are used
    - the expression denoting the polynomial is well-formed
    - each term in the expression is either a master-key term or a special-lone random
      term
    - the blinding poly is not similar to any variable of another type
    - no (newly discovered) non-lone var is similar to any variable of another type
    - no (newly discovered) special-lone var is similar to any var of another type
    - the blinding poly and all occuring variables type check

    The blinding poly as well as an (newly discovered) variables are also
    registered as such in the `VarTypeMap` for later queries.
    """
    if len(polys) == 0:
        raise BlindingPolyMissingError()
    if len(polys) > 1:
        raise BlindingPolyAmbigiousError()
    b = polys[0]
    if b.group != Group.GT:
        raise BlindingPolyInvalidGroupError()
    if len(b.quants) > 0:
        raise BlindingPolyIsQuantifiedError()
    if len(b.idcs) > 0:
        raise BlindingPolyIsIndexedError()

    analyzer = BlindingPolyAnalyser(
        var_type_map, cipher_non_lone_randoms, cipher_special_lone_randoms
    )
    cm = analyzer.analyze(b)
    vars = [b]
    for t in cm.master_key_terms:
        vars.append(t.master_key_var.quantify(b.quants))
        vars.append(t.random_var.quantify(b.quants))
    for t in cm.special_lone_random_terms:
        vars.append(t.random_var.quantify(b.quants))

    if not common.validate_types(vars):
        raise BlindingPolyTypeError()

    return cm


# TODO: make this a subclass of SecondaryCipherPolyAnalyser since they have (almost)
# identical logic
class BlindingPolyAnalyser:

    def __init__(
        self,
        var_type_map: VarTypeMap,
        cipher_non_lone_randoms: EquivSet,
        cipher_special_lone_randoms: EquivSet,
    ):
        self._var_type_map = var_type_map
        self._cipher_non_lone_randoms = cipher_non_lone_randoms
        self._cipher_special_lone_randoms = cipher_special_lone_randoms
        self._poly: Optional[Poly] = None
        self._special_lone_random_terms: list[BlindingPoly.SpecialLoneRandomTerm] = []
        self._master_key_terms: list[BlindingPoly.MasterKeyTerm] = []

    def _reset(self):
        self._special_lone_random_terms = []
        self._master_key_terms = []

    def _is_master_key_var(self, var):
        return self._var_type_map.is_master_key_var(var.quantify(self._poly.quants))

    def _is_common_var(self, var):
        return self._var_type_map.is_common_var(var.quantify(self._poly.quants))

    def analyze(self, poly: Poly) -> BlindingPoly:
        self._reset()
        self._poly = poly
        if self._poly.name.startswith("<"):
            raise BlindingPolyIsSpecialError()
        if self._poly.name != "cm":
            raise BlindingPolyInvalidNameError()
        self._var_type_map.expect(
            poly, VarType.CIPHER_BLINDING_POLY, BlindingPolyInconsistentPolyError()
        )
        try:
            for t in analyze_expr(poly.expr):
                self._analyze_term(t)

            return BlindingPoly(
                poly.name,
                poly.idcs,
                poly.quants,
                poly.group,
                self._special_lone_random_terms,
                self._master_key_terms,
            )
        except ValueError as exc:
            raise BlindingPolyInvalidExpressionError() from exc

    def _analyze_term(self, term):
        # TODO: systematize what counts as "proper" variable and what is a
        # coefficient only
        def is_sym(s):
            return not s.startswith("<epsilon")

        nums = [c for c in term.coeffs if isinstance(c.num, int)]
        specs = [c for c in term.coeffs if isinstance(c.num, str) and not is_sym(c.num)]
        syms = [c for c in term.coeffs if isinstance(c.num, str) and is_sym(c.num)]

        allowed_special_vars = ["<rgid>", "<secret>"]
        for s in specs:
            v = parse_var(s.num)
            if v.name not in allowed_special_vars:
                raise BlindingPolyIllegalSpecialVarError()

        if len(syms) == 1:
            self._analyze_unary_term(nums, specs, syms)
        elif len(syms) == 2:
            self._analyze_binary_term(nums, specs, syms)
        else:
            raise BlindingPolyInvalidTermError()

    def _analyze_unary_term(self, nums, specs, syms):
        factor = Term(*(nums + specs)) if nums or specs else Term(Coeff(1))
        var = parse_var(syms[0].num)
        if self._is_master_key_var(var) or self._is_common_var(var):
            raise BlindingPolyInvalidUnaryTermError()
        lone_term = BlindingPoly.SpecialLoneRandomTerm(var, factor=factor)
        self._special_lone_random_terms.append(lone_term)
        self._process_special_lone_random(var)

    def _analyze_binary_term(self, nums, specs, syms):
        factor = Term(*(nums + specs)) if nums or specs else Term(Coeff(1))
        lhs, rhs = [parse_var(c.num) for c in syms]
        if self._is_common_var(lhs) or self._is_common_var(rhs):
            raise BlindingPolyInvalidBinaryTermError()
        if self._is_master_key_var(lhs) and not self._is_master_key_var(rhs):
            random_var = rhs
            master_key_var = lhs
        elif not self._is_master_key_var(lhs) and self._is_master_key_var(rhs):
            random_var = lhs
            master_key_var = rhs
        else:
            raise BlindingPolyInvalidBinaryTermError()
        self._process_non_lone_random(random_var)
        master_term = BlindingPoly.MasterKeyTerm(
            random_var, master_key_var, factor=factor
        )
        self._master_key_terms.append(master_term)

    def _process_special_lone_random(self, var):
        var = var.quantify(self._poly.quants)
        if not var.is_special():
            self._cipher_special_lone_randoms.update(var)
            self._var_type_map.expect(
                var,
                VarType.CIPHER_SPECIAL_LONE_RANDOM,
                BlindingPolyInconsistentSpecialLoneRandomVarError(),
            )

    def _process_non_lone_random(self, var):
        if not var.is_special() or var.name == "<secret>":
            var = var.quantify(self._poly.quants)
            self._cipher_non_lone_randoms.update(var)
            self._var_type_map.expect(
                var,
                VarType.CIPHER_NON_LONE_RANDOM,
                BlindingPolyInconsistentNonLoneRandomVarError(),
            )
