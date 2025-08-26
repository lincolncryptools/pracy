from sympy import Add, Mul, Pow, Symbol

from pracy.core.group import Group
from pracy.core.idx import Idx
from pracy.core.poly import Poly
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.frontend.parsing import parse_poly


def test_parse_poly_simple():
    alpha = Symbol("alpha_{l}")
    b = Mul(Mul(2, Pow(3, -1)), Symbol("b_{l}"))
    name = "k"
    idcs = [Idx("l")]
    quants = [Quant("l", QSet.AUTHORITIES)]
    expr = Add(Add(alpha, b), 1)
    expected = Poly(name, idcs, quants, expr, Group.G)
    received = parse_poly("(k_{l} : G = alpha_{l} + 2 / 3 * b_{l} + 1)_[l:AUTHS]")
    assert received == expected


def test_parse_poly_special_var():
    name = "k"
    idcs = [Idx("1"), Idx("l")]
    quants = [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)]
    alpha = Symbol("alpha_{l}")
    rgid = Symbol("<rgid>")
    b = Symbol("b_{l}")
    r = Symbol("r_{l}")
    b_prime = Symbol("b'_{l}")
    expr = Add(Add(alpha, Mul(rgid, b)), Mul(r, b_prime))
    expected = Poly(name, idcs, quants, expr, Group.H)
    received = parse_poly(
        "(k_{1, l} : H = alpha_{l} + "
        "<rgid>*b_{l} + r_{l}*b'_{l})_[l:attr_to_auth(USER_ATTRS)]"
    )
    assert received == expected


def test_parse_poly_no_quant():
    name = "c'"
    idcs = [Idx("j")]
    quants = []
    lambda_ = Symbol("<lambda>_{j}")
    alpha = Symbol("alpha_{j.auth}")
    s = Symbol("s_{1,j}")
    expr = Add(lambda_, Mul(alpha, s))
    expected = Poly(name, idcs, quants, expr, Group.GT)
    received = parse_poly("c'_{j} : Gt = <lambda>_{j} + alpha_{j.auth}*s_{1,j}")
    assert received == expected


def test_parse_poly_minimal():
    secret = Symbol("<secret>")
    expected = Poly("cm", [], [], secret, Group.GT)
    received = parse_poly("cm : Gt = <secret>")
    assert received == expected
