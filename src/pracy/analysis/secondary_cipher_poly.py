from dataclasses import dataclass, field
from typing import Optional

from pracy.analysis import common
from pracy.analysis.errors import (
    SecondaryPolyIllegalQuantsError,
    SecondaryPolyIllegalSpecialVarError,
    SecondaryPolyInconsistentNonLoneRandomVarError,
    SecondaryPolyInconsistentPolyError,
    SecondaryPolyInconsistentSpecialLoneRandomVarError,
    SecondaryPolyInvalidBinaryTermError,
    SecondaryPolyInvalidExpressionError,
    SecondaryPolyInvalidGroupError,
    SecondaryPolyInvalidNameError,
    SecondaryPolyInvalidTermError,
    SecondaryPolyInvalidUnaryTermError,
    SecondaryPolyIsSpecialError,
    SecondaryPolyNonUniqueError,
    SecondaryPolyTypeError,
    SecondaryPolyUnusedQuantsError,
)
from pracy.analysis.expr import Coeff, Term, analyze_expr
from pracy.analysis.variant import AbeVariant
from pracy.core.equiv import EquivSet
from pracy.core.group import Group
from pracy.core.idx import Idx
from pracy.core.poly import Poly
from pracy.core.quant import Quant
from pracy.core.type import VarType, VarTypeMap
from pracy.core.var import Var
from pracy.frontend.parsing import parse_var


@dataclass
class SecondaryCipherPoly:
    """
    A SecondaryCipherPoly models a single polynomial c'_i specified by EncCt of GPES
    (Definition 7).
    """

    @dataclass
    class MasterKeyTerm:
        """
        A MasterKeyTerm models a single summand in a SecondaryCipherPoly which consists
        of a non-lone random variable multiplied with a master key variable and a
        coefficient (c.f. first sum of c'_i in Definition 7).
        """

        random_var: Var
        master_key_var: Var
        factor: Term = field(default_factory=lambda: Term(Coeff(1)), kw_only=True)

    @dataclass
    class SpecialLoneRandomTerm:
        """
        A SpecialLoneRandomTerm models a single summand in a SecondaryCipherPoly which
        consists of a special-lone random variable and a coefficient (c.f. second sum of
        c'_i in Definition 7).
        """

        random_var: Var
        factor: Term = field(default_factory=lambda: Term(Coeff(1)), kw_only=True)

    name: str
    idcs: list[Idx]
    quants: list[Quant]
    group: Group
    master_key_terms: list[MasterKeyTerm]
    special_lone_random_terms: list[SpecialLoneRandomTerm]


def analyze_secondary_cipher_polys(
    variant: AbeVariant,
    var_type_map: VarTypeMap,
    cipher_non_lone_randoms: EquivSet,
    cipher_special_lone_randoms: EquivSet,
    polys: list[Poly],
):
    """
    Analyzes the secondary cipher polys of an ABE scheme.

    Concretely, this function enforces that
    - all sec. cipher polys are unique (regarding similarity of variables)
    - all sec. cipher polys are mapped to Gt
    - no sec. cipher poly is named "cm" (reserved for the `BlindingPoly`)
    - each polynomial and all occuring variables type check
    - no sec. cipher poly is similar to any variable of another type
    - no (newly discovered) non-lone var is similar to any variable of another type
    - no (newly discovered) special-lone var is similar to any variable of another type
    - no sec. cipher poly is a special var
    - no unexpected special vars are used
    - no superfluous quantifications appear
    - no illegal base sets are used for quantifications
    - the expression denoting the polynomial is well formed
    - each term in the expression is either a master-key term or a special-lone random
      term

    All secondary cipher polys as well as any (newly discovered) variables are also
    registered as such in the `VarTypeMap` for later queries.
    """
    if not common.validate_unique_sim(polys):
        raise SecondaryPolyNonUniqueError()
    cipher_polys = []
    analyzer = SecondaryCipherPolyAnalyser(
        variant, var_type_map, cipher_non_lone_randoms, cipher_special_lone_randoms
    )
    for s in polys:
        cp = analyzer.analyze(s)
        vars = [s]
        for t in cp.master_key_terms:
            vars.append(t.master_key_var.quantify(s.quants))
            vars.append(t.random_var.quantify(s.quants))
        for t in cp.special_lone_random_terms:
            vars.append(t.random_var.quantify(s.quants))

        if not common.validate_types(vars):
            raise SecondaryPolyTypeError()

        if not common.validate_all_quants_occur(vars, s.quants):
            raise SecondaryPolyUnusedQuantsError()

        cipher_polys.append(cp)
    return cipher_polys


class SecondaryCipherPolyAnalyser:

    def __init__(
        self,
        variant: AbeVariant,
        var_type_map: VarTypeMap,
        cipher_non_lone_randoms: EquivSet,
        cipher_special_lone_randoms: EquivSet,
    ):
        self._variant = variant
        self._var_type_map = var_type_map
        self._cipher_non_lone_randoms = cipher_non_lone_randoms
        self._cipher_special_lone_randoms = cipher_special_lone_randoms
        self._poly: Optional[Poly] = None
        self._master_key_terms: list[SecondaryCipherPoly.MasterKeyTerm] = []
        self._special_lone_random_terms: list[
            SecondaryCipherPoly.SpecialLoneRandomTerm
        ] = []

    def _reset(self):
        self._master_key_terms = []
        self._special_lone_random_terms = []

    def _is_master_key_var(self, var):
        return self._var_type_map.is_master_key_var(var.quantify(self._poly.quants))

    def _is_common_var(self, var):
        return self._var_type_map.is_common_var(var.quantify(self._poly.quants))

    def analyze(self, poly: Poly) -> SecondaryCipherPoly:
        self._reset()
        self._poly = poly
        if self._poly.name.startswith("<"):
            raise SecondaryPolyIsSpecialError()
        if self._poly.name == "cm":
            raise SecondaryPolyInvalidNameError()
        if self._poly.group != Group.GT:
            raise SecondaryPolyInvalidGroupError()
        self._var_type_map.expect(
            poly, VarType.CIPHER_SECONDARY_POLY, SecondaryPolyInconsistentPolyError()
        )
        allowed_q_sets = self._variant.allowed_quants_encrypt()
        if not common.validate_quants([poly], allowed_q_sets):
            raise SecondaryPolyIllegalQuantsError()
        try:
            for t in analyze_expr(poly.expr):
                self._analyze_term(t)

            return SecondaryCipherPoly(
                poly.name,
                poly.idcs,
                poly.quants,
                poly.group,
                self._master_key_terms,
                self._special_lone_random_terms,
            )
        except ValueError as exc:
            raise SecondaryPolyInvalidExpressionError() from exc

    def _analyze_term(self, term):
        # TODO: systematize what counts as "proper" variable and what is a
        # coefficient only
        def is_sym(s):
            return not s.startswith("<epsilon")

        nums = [c for c in term.coeffs if isinstance(c.num, int)]
        specs = [c for c in term.coeffs if isinstance(c.num, str) and not is_sym(c.num)]
        syms = [c for c in term.coeffs if isinstance(c.num, str) and is_sym(c.num)]

        allowed_special_vars = ["<rgid>", "<xattr>", "<lambda>", "<mu>"]
        for s in specs:
            v = parse_var(s.num)
            if v.name not in allowed_special_vars:
                raise SecondaryPolyIllegalSpecialVarError()

        if len(syms) == 1:
            self._analyze_unary_term(nums, specs, syms)
        elif len(syms) == 2:
            self._analyze_binary_term(nums, specs, syms)
        else:
            raise SecondaryPolyInvalidTermError()

    def _analyze_unary_term(self, nums, specs, syms):
        factor = Term(*(nums + specs)) if nums or specs else Term(Coeff(1))
        var = parse_var(syms[0].num)
        if self._is_master_key_var(var) or self._is_common_var(var):
            raise SecondaryPolyInvalidUnaryTermError()
        lone_term = SecondaryCipherPoly.SpecialLoneRandomTerm(var, factor=factor)
        self._special_lone_random_terms.append(lone_term)
        self._process_special_lone_random(var)

    def _analyze_binary_term(self, nums, specs, syms):
        factor = Term(*(nums + specs)) if nums or specs else Term(Coeff(1))
        lhs, rhs = [parse_var(c.num) for c in syms]
        if self._is_common_var(lhs) or self._is_common_var(rhs):
            raise SecondaryPolyInvalidBinaryTermError()
        if self._is_master_key_var(lhs) and not self._is_master_key_var(rhs):
            random_var = rhs
            master_key_var = lhs
        elif not self._is_master_key_var(lhs) and self._is_master_key_var(rhs):
            random_var = lhs
            master_key_var = rhs
        else:
            raise SecondaryPolyInvalidTermError()
        if not random_var.is_special():
            self._process_non_lone_random(random_var)
        master_term = SecondaryCipherPoly.MasterKeyTerm(
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
                SecondaryPolyInconsistentSpecialLoneRandomVarError(),
            )

    def _process_non_lone_random(self, var):
        var = var.quantify(self._poly.quants)
        self._cipher_non_lone_randoms.update(var)
        self._var_type_map.expect(
            var,
            VarType.CIPHER_NON_LONE_RANDOM,
            SecondaryPolyInconsistentNonLoneRandomVarError(),
        )
