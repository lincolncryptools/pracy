from sympy import Add, Integer, Mul, Pow, Symbol, expand
from sympy.core.numbers import Half, Rational


class Coeff:

    def __init__(self, num: int | str, denom: list[int | str] = None):
        self.num = num
        if denom is None:
            denom = []
        self.denom = denom

    def __eq__(self, other):
        if not isinstance(other, Coeff):
            return False
        return self.num == other.num and self.denom == other.denom

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return f"Coeff(num={self.num}, denom={self.denom})"


class Term:

    def __init__(self, *coeffs):
        self.coeffs = list(coeffs)

    def __eq__(self, other):
        if not isinstance(other, Term):
            return False
        todo = self.coeffs.copy()
        for c in other.coeffs:
            try:
                idx = todo.index(c)
                # we found c common in both, mark as "done"
                todo.pop(idx)
            except ValueError:
                # we found c in other which is not in self
                return False
        return len(todo) == 0

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return f"Term(coeffs={self.coeffs})"


def analyze_expr(expr) -> list[Term]:
    """Convert a sympy expression to a list of terms."""
    res = expand(expr)
    match res:
        case Integer():
            return [Term(Coeff(int(res)))]
        case Symbol():
            return [Term(Coeff(res.name))]
        case Mul():
            coeffs = []
            for arg in res.args:
                if isinstance(arg, Integer):
                    coeffs.append(Coeff(int(arg)))
                elif isinstance(arg, Symbol):
                    coeffs.append(Coeff(arg.name))
                elif isinstance(arg, Rational):
                    if arg.numerator < 0:
                        coeffs.append(Coeff(-1))
                    coeffs.append(Coeff(abs(arg.numerator)))
                    coeffs.append(Coeff(1, denom=[[arg.denominator]]))
                elif isinstance(arg, Pow):
                    assert len(arg.args) == 2
                    base = arg.args[0]
                    exp = arg.args[1]
                    assert isinstance(exp, Integer)
                    if exp == -1:
                        if isinstance(base, Symbol):
                            coeffs.append(Coeff(1, denom=[[base.name]]))
                        elif isinstance(base, Integer):
                            coeffs.append(Coeff(1, denom=[[int(base)]]))
                        elif isinstance(base, Add):
                            denom = []
                            for s in base.args:
                                if isinstance(s, Integer):
                                    denom.append([1])
                                elif isinstance(s, Symbol):
                                    denom.append([s.name])
                                elif isinstance(s, Mul):
                                    d = []
                                    for f in s.args:
                                        if isinstance(f, Integer):
                                            d.append(int(f))
                                        elif isinstance(f, Symbol):
                                            d.append(f.name)
                                        else:
                                            raise ValueError("Unexpected term")
                                    denom.append(d)
                            coeffs.append(Coeff(1, denom=denom))
                        else:
                            raise ValueError("Unexpected term")
                    else:
                        # Higher powers (like square) should only ever occur with
                        # symbols as multiplications of numbers are
                        # computed immediately
                        assert isinstance(base, Symbol)
                        for _ in range(exp):
                            coeffs.append(Coeff(base.name))
                else:
                    raise ValueError("Unexpected term")
            return [Term(*coeffs)]
        case Pow():
            assert len(res.args) == 2
            base = res.args[0]
            exp = res.args[1]
            assert isinstance(base, (Integer, Symbol))
            assert isinstance(exp, Integer) and exp == -1
            if isinstance(base, Symbol):
                return [Term(Coeff(1, denom=[[base.name]]))]
            if isinstance(base, Integer):
                return [Term(Coeff(1, denom=[[int(base)]]))]
            raise ValueError("Unexpected term")
        case Rational():
            assert isinstance(res.numerator, int) and res.numerator >= 0
            assert isinstance(res.denominator, int) and res.denominator >= 1
            return [Term(Coeff(res.numerator, denom=[[int(res.denominator)]]))]
        case Add():
            terms = []
            for arg in res.args:
                if isinstance(arg, Integer):
                    terms.append(Term(Coeff(int(arg))))
                elif isinstance(arg, Symbol):
                    terms.append(Term(Coeff(arg.name)))
                elif isinstance(arg, Mul):
                    coeffs = []
                    for a in arg.args:
                        if isinstance(a, Integer):
                            coeffs.append(Coeff(int(a)))
                        elif isinstance(a, Symbol):
                            coeffs.append(Coeff(a.name))
                        elif isinstance(a, Half):
                            coeffs.append(Coeff(1, denom=[[2]]))
                        elif isinstance(a, Pow):
                            assert len(a.args) == 2
                            base = a.args[0]
                            exp = a.args[1]
                            assert isinstance(base, (Integer, Symbol))
                            # assert isinstance(exp, Integer) and exp == -1
                            if exp == -1:
                                if isinstance(base, Symbol):
                                    coeffs.append(Coeff(1, denom=[[base.name]]))
                                elif isinstance(base, Integer):
                                    coeffs.append(Coeff(1, denom=[[int(base)]]))
                                else:
                                    raise ValueError("Unexpected term")
                            else:
                                assert isinstance(base, Symbol)
                                for _ in range(exp):
                                    coeffs.append(Coeff(base.name))
                        else:
                            raise ValueError("Unexpected term")
                    terms.append(Term(*coeffs))
                elif isinstance(arg, Pow):
                    assert len(arg.args) == 2
                    base = arg.args[0]
                    exp = arg.args[1]
                    assert isinstance(exp, Integer) and exp == -1
                    if isinstance(base, Symbol):
                        terms.append(Term(Coeff(1, denom=[[base.name]])))
                    elif isinstance(base, Integer):
                        terms.append(Term(Coeff(1, denom=[[int(base)]])))
                    elif isinstance(base, Add):
                        denom = []
                        for s in base.args:
                            if isinstance(s, Integer):
                                denom.append([int(s)])
                            elif isinstance(s, Symbol):
                                denom.append([s.name])
                            else:
                                raise ValueError("Unexpected term")
                        terms.append(Term(Coeff(1, denom=denom)))
                    else:
                        raise ValueError("Unexpected term")
                else:
                    raise ValueError("Unexpected term")
            return terms
        case _:
            raise NotImplementedError()
