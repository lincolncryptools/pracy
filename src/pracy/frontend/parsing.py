import json

from lark import Lark, Transformer
from lark.visitors import merge_transformers
from sympy import Add, Expr, Mul, Pow, Symbol

from pracy.core.fdh import FdhEntry
from pracy.core.group import Group
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.poly import Poly
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.var import Var
from pracy.frontend.raw_scheme import RawPair, RawScheme, RawSingle


def parse_json(data: str) -> RawScheme:
    """
    Parses a complete scheme specification given in JSON format as a raw
    representation.
    """
    spec = json.loads(data)["spec"]
    master_key_vars = [parse_var(v) for v in spec["master_key_vars"]]
    common_vars = [parse_var(v) for v in spec["common_vars"]]
    key_polys = [parse_poly(p) for p in spec["key_polys"]]
    cipher_polys = [parse_poly(p) for p in spec["cipher_polys"]]
    decrypt_vec = [parse_vector_entry(e) for e in spec["e_vec"]]
    decrypt_mat = [parse_matrix_entry(e) for e in spec["e_mat"]]
    fdh_map = [parse_fdh_entry(e) for e in spec["fdh_map"]]
    raw_scheme = RawScheme(
        master_key_vars,
        common_vars,
        key_polys,
        cipher_polys,
        decrypt_vec,
        decrypt_mat,
        fdh_map,
    )
    return raw_scheme


class BaseTransformer(Transformer):
    """
    The `BaseTransformer` groups common syntactical components (for example indices
    or arithemtic expression) shared among different structures like `Var`, `Poly` and
    `FdhEntry`.
    """

    def idcs(self, idcs) -> list[Idx]:
        return list(idcs)

    def plain_idx(self, idx) -> Idx:
        return Idx(idx[0])

    def num_idx(self, idx) -> Idx:
        return idx[0].value

    def mapped_idx(self, map) -> Idx:
        var, map = map
        return Idx(var, map)

    def quants(self, quants) -> list[Quant]:
        return list(quants)

    def quant(self, q) -> Quant:
        name, (set, map) = q
        return Quant(name, set, map)

    def plain_quant(self, q):
        return q[0], None

    def mapped_quant(self, q):
        return q[1], q[0]

    def qset(self, s) -> QSet:
        return QSet(s[0].value)

    def qmap(self, m) -> QMap:
        return QMap(m[0].value)

    def imap(self, m) -> IMap:
        return IMap(m[0].value)

    def ident(self, i):
        return i[0]

    def special_ident(self, i):
        return "".join(i.value for i in i)

    def normal_ident(self, i):
        return "".join(i.value for i in i)

    def symbol(self, v) -> Expr:
        if len(v) == 2:
            name, idcs = v
        else:
            name = v[0]
            idcs = []
        s = name

        def to_str(idx):
            if idx.local_map:
                return f"{idx.name}.{idx.local_map.value}"
            return idx.name

        if idcs:
            s += "_{"
            s += ",".join([to_str(i) for i in idcs])
            s += "}"
        return Symbol(s)

    def num(self, n) -> int:
        return int(n[0].value)

    def add(self, args) -> Expr:
        return Add(args[0], args[1])

    def sub(self, args) -> Expr:
        return Add(args[0], Mul(-1, args[1]))

    def mul(self, args) -> Expr:
        return Mul(args[0], args[1])

    def neg(self, args) -> Expr:
        return Add(0, Mul(-1, args[0]))

    def div(self, args) -> Expr:
        return Mul(args[0], Pow(args[1], -1))


def parse_fdh_entry(str: str) -> FdhEntry:
    """
    Parses a single entry of a user-specified FDH map.

    The entry format is
        `(varname_{indicies}_[quantifications]) # integer`.

    The variable name as well as the optional indices and quantification have the same
    format as specified for `parse_var`. If either is omitted, the leading underscore
    must also be omitted.

    The integer specifies the index of the FDH function to use and must be unsigned.
    """
    fdh_parser = Lark.open("fdh_entry.lark", rel_to=__file__, start="fdh")
    fdh = fdh_parser.parse(str)

    class FdhBuilder(Transformer):
        def fdh_idx(self, f):
            return int(f[0])

        def fdh(self, v):
            return FdhEntry(v[0], v[1])

        def var(self, v):
            name, idcs, quants = v
            if idcs is None:
                idcs = []
            if quants is None:
                quants = []
            return Var(name, idcs, quants)

    transformer = merge_transformers(FdhBuilder(), base=BaseTransformer())
    return transformer.transform(fdh)


def parse_matrix_entry(str: str) -> RawPair:
    """
    Parses a single entry of the decryption matrix.

    The general format is
        `(varname_{indices} ~ varname_{indices} = expr)_[quantifications]`.

    This indicates, that for decryption the left and right arguments to the tilde
    operators shall be "paired". Their format is identical as specified in
    `parse_var`.

    If the quantifications are omitted, the surrounding parentheses must also be
    removed.

    The expression may be any arithmetic expression consisting of standard operators,
    parenthesis, integer literals and (possibly indexed) variables.
    """
    entry_parser = Lark.open("matrix_entry.lark", rel_to=__file__, start="entry")
    entry = entry_parser.parse(str)

    class EntryBuilder(Transformer):
        def entry(self, e):
            lhs, idcs_l, rhs, idcs_r, expr, quants = e
            idcs_l = [] if not idcs_l else idcs_l
            idcs_r = [] if not idcs_r else idcs_r
            lhs = Var(lhs, idcs_l)
            rhs = Var(rhs, idcs_r)
            return RawPair(lhs, rhs, expr, quants)

        def var(self, v):
            name, idcs = v
            if not idcs:
                return name, []
            return name, idcs

    transformer = merge_transformers(EntryBuilder(), base=BaseTransformer())
    return transformer.transform(entry)


def parse_vector_entry(str: str) -> RawSingle:
    """
    Parses a single entry of the decryption vector.

    The general format is
        `varname_{indices} = expr` or
        `(varname_{indices} = expr)_[quantifications]`.

    The `varname` component is an identifier. If the indices are missing, the
    leading underscore must be omitted. Otherwise, the indices follow the same
    format as explained for `parse_var`.

    If the entry should be quantified, is must be wrapped in parenthesis, and the
    quantification(s) must be given as specified for `parse_var`.

    The expression may contain arithmetic operators, parenthesis, variables and
    integer literals.
    """
    entry_parser = Lark.open("vector_entry.lark", rel_to=__file__, start="entry")
    entry = entry_parser.parse(str)

    class EntryBuilder(Transformer):
        def entry(self, e):
            name, idcs, expr, quants = e
            return RawSingle(Var(name, idcs), expr, quants)

        def var(self, v):
            name, idcs = v
            if not idcs:
                return name, []
            else:
                return name, idcs

    transformer = merge_transformers(EntryBuilder(), base=BaseTransformer())
    return transformer.transform(entry)


def parse_poly(str: str) -> Poly:
    """
    Parses a string as a possibly quantified `Poly`.

    The general polynomial specification format is
        `polyname : group = expr` or
        `(polyname : group = expr)_[quantifications]`.

    The `polyname` must be a (possibly indexed) identifier consisting of
    alphabetic characters. For the syntax of indices, see `parse_var`.

    The `group` specified must be either `G`, `H` or `Gt`.

    The expression must be an arithmetic expression consisting of `+`, `-`, `*` and `/`
    as well as parenthesis to change precedence. The terms may either be integers
    or (possibly indexed) variables. Special variables, i.e. those enclosed in angle
    brackets `<` and `>` are also allowed.

    If the polynomial should be quantified, the entire specification must be enclosed
    in parenthesis and followed by quantifications. See `parse_var` for detailed syntax
    description.
    """
    poly_parser = Lark.open("poly.lark", rel_to=__file__, start="poly")
    poly = poly_parser.parse(str)

    class PolyBuilder(Transformer):
        def poly(self, p):
            (name, idcs) = p[0]
            group = p[1]
            expr = p[2]
            quants = p[3] if len(p) == 4 else []
            return Poly(name, idcs, quants, expr, group)

        def var(self, v):
            name, idcs = v
            if not idcs:
                return name, []
            return name, idcs

        def group(self, g):
            return Group(g[0].value)

    transformer = merge_transformers(PolyBuilder(), base=BaseTransformer())
    return transformer.transform(poly)


def parse_var(str: str) -> Var:
    """
    Parses a string as a possibly indexed and/or quantified `Var`.

    The general variable specification format is
        `varname_{indices}_[quantifications]`.

    The first component `varname` is mandatory and must a non-empty sequence of
    alphabetic characters.

    If `indices` is missing, then the leading `_` and the braces must be omitted.
    Otherwise, one can specify a comma-separated sequence of identifiers or numbers
    as indices. Each index may additional be *mapped*, i.e., instead of
    `x` we have `f(x)`. The valid valued for `f` are determined by `IMap`.

    If `quantifications` is missing, the leading `_` and the brackets must be omitted.
    Otherwise, one can give a comma-separated sequence of identifier-base set pairs,
    e.g., `x:AUTHS`.
    Each base set may be mapped and specified as `f(base_set)` instead, where `f`
    is a `QMap`.
    """
    var_parser = Lark.open("var.lark", rel_to=__file__, start="var")
    var = var_parser.parse(str)

    class VarBuilder(Transformer):
        def var(self, v):
            name, idcs, quants = v
            if not idcs:
                idcs = []
            if not quants:
                quants = []
            return Var(name, idcs, quants)

    transformer = merge_transformers(VarBuilder(), base=BaseTransformer())
    return transformer.transform(var)
