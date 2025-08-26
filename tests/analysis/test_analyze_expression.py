from sympy import Add, Mul, Pow, Symbol

from pracy.analysis.expr import Coeff, Term, analyze_expr


def test_analyze_num():
    expr = 4
    received = analyze_expr(expr)
    expected = [Term(Coeff(4))]
    assert received == expected


def test_analyze_num_neg():
    expr = -2
    received = analyze_expr(expr)
    expected = [Term(Coeff(-2))]
    assert received == expected


def test_analyze_symbol():
    expr = Symbol("x")
    received = analyze_expr(expr)
    expected = [Term(Coeff("x"))]
    assert received == expected


def test_analyze_symbol_complex():
    expr = Symbol("y_{foo(2)}")
    received = analyze_expr(expr)
    expected = [Term(Coeff("y_{foo(2)}"))]
    assert received == expected


def test_analyze_product_nums():
    expr = Mul(5, 3, evaluate=False)
    received = analyze_expr(expr)
    expected = [Term(Coeff(15))]
    assert received == expected


def test_analyze_product_with_one():
    expr = Mul(Symbol("x"), 1, evaluate=False)
    received = analyze_expr(expr)
    expected = [Term(Coeff("x"))]
    assert received == expected


def test_analyze_product_vars():
    expr = Mul(Symbol("x"), Symbol("y"), evaluate=False)
    received = analyze_expr(expr)
    expected = [Term(Coeff("x"), Coeff("y"))]
    assert received == expected


def test_analyze_product_large():
    expr = Mul(
        Symbol("x"), 4, Symbol("y"), 3, 6, Symbol("very_long_name"), evaluate=False
    )
    received = analyze_expr(expr)
    expected = [Term(Coeff(4 * 3 * 6), Coeff("very_long_name"), Coeff("x"), Coeff("y"))]
    assert received == expected


def test_analyze_product_nested():
    expr = Mul(Mul(Symbol("x"), 1), Symbol("y"), Mul(2, 2, Symbol("z")), evaluate=False)
    received = analyze_expr(expr)
    expected = [Term(Coeff(1 * 2 * 2), Coeff("x"), Coeff("y"), Coeff("z"))]
    assert received == expected


def test_analyze_product_repeats():
    expr = Mul(Symbol("x"), Symbol("y"), Mul(3, Symbol("x")), evaluate=False)
    received = analyze_expr(expr)
    expected = [Term(Coeff(3), Coeff("x"), Coeff("x"), Coeff("y"))]
    assert received == expected


def test_analyze_sum_nums():
    expr = Add(2, 3, 5)
    received = analyze_expr(expr)
    expected = [Term(Coeff(2 + 3 + 5))]
    assert received == expected


def test_analyze_sum_vars():
    expr = Add(Symbol("x"), Symbol("y"))
    received = analyze_expr(expr)
    expected = [Term(Coeff("x")), Term(Coeff("y"))]
    assert received == expected


def test_analyze_sum_of_prods():
    expr = Add(7, Mul(Symbol("x"), 1), Symbol("x"), 3, Mul(Symbol("y"), Symbol("z")))
    received = analyze_expr(expr)
    expected = [
        Term(Coeff(7 + 3)),
        Term(Coeff("x"), Coeff(2)),
        Term(Coeff("y"), Coeff("z")),
    ]
    assert received == expected


def test_analyze_prod_of_sums():
    expr = Mul(Add(5, Symbol("y")), 3, Add(Mul(2, Symbol("x")), Symbol("z")))
    received = analyze_expr(expr)
    expected = [
        Term(Coeff(5 * 3), Coeff("z")),
        Term(Coeff(5 * 3 * 2), Coeff("x")),
        Term(Coeff(3), Coeff("y"), Coeff("z")),
        Term(Coeff(3 * 2), Coeff("x"), Coeff("y")),
    ]
    assert received == expected


def test_analyze_div_simple():
    expr = Mul(1, Pow(Symbol("x"), -1))
    received = analyze_expr(expr)
    expected = [Term(Coeff(1, denom=[["x"]]))]
    assert received == expected


def test_analyze_div_vars():
    expr = Mul(Mul(5, Pow(Symbol("x"), -1)), Mul(Symbol("y"), Pow(Symbol("z"), -1)))
    received = analyze_expr(expr)
    expected = [
        Term(Coeff(5), Coeff("y"), Coeff(1, denom=[["x"]]), Coeff(1, denom=[["z"]])),
    ]
    assert received == expected


def test_analyze_div_sum():
    expr = Mul(Add(1, Symbol("y")), Pow(Symbol("x"), -1))
    received = analyze_expr(expr)
    expected = [
        Term(Coeff(1, denom=[["x"]])),
        Term(Coeff("y"), Coeff(1, denom=[["x"]])),
    ]
    assert received == expected


def test_analyze_div_complex():
    expr = Mul(-1, Symbol("x"), Pow(Add(Symbol("y"), Mul(-1, Symbol("z"))), -1))
    received = analyze_expr(expr)
    expected = [Term(Coeff(-1), Coeff("x"), Coeff(1, denom=[["y"], [-1, "z"]]))]
    assert received == expected


def test_analyze_div_nested():
    expr = Add(
        3,
        Pow(Mul(-1, Symbol("x")), -1),
        Mul(2, Symbol("x"), Add(Symbol("x"), 3)),
        Pow(Add(Symbol("y"), Symbol("x")), -1),
    )
    received = analyze_expr(expr)
    expected = [
        Term(Coeff(3)),
        Term(Coeff(1, denom=[["x"], ["y"]])),
        Term(Coeff(-1), Coeff(1, denom=[["x"]])),
        Term(Coeff(2), Coeff("x"), Coeff("x")),
        Term(Coeff(6), Coeff("x")),
    ]
    assert received == expected
