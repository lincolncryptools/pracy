from sympy import Add, Mul, Symbol

from pracy.core.fdh import FdhEntry
from pracy.core.group import Group
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.core.poly import Poly
from pracy.core.qmap import QMap
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.var import Var
from pracy.frontend.parsing import parse_json
from pracy.frontend.raw_scheme import RawPair, RawScheme, RawSingle


def test_parse_json():
    json_input = """
{
    "meta": {},
    "spec": {
        "master_key_vars": [
            "alpha_{l}_[l:AUTHS]"
        ],
        "common_vars": [
            "b_{l}_[l:AUTHS]",
            "b'_{l}_[l:AUTHS]",
            "b_{att}_[att:ATTR_UNI]"
        ],
        "key_polys": [
            "(k_{1, l} : G = alpha_{l} + <rgid>*b_{l} + r_{l}*b'_{l})_[l:attr_to_auth(USER_ATTRS)]",
            "(k_{2, att} : G = r_{att.auth}*b_{att})_[att:USER_ATTRS]"
        ],
        "cipher_polys": [
            "cm : Gt = <secret>",
            "(c_{1, j} : H = <mu>_{j} + s_{1, j}*b_{j.auth})_[j:LSSS_ROWS]",
            "(c_{2, j} : H = s_{1, j}*b'_{j.auth} + s_{2, j.dedup}*b_{j.attr})_[j:LSSS_ROWS]",
            "(c'_{j} : Gt = <lambda>_{j} + alpha_{j.auth}*s_{1, j})_[j:LSSS_ROWS]"
        ],
        "e_vec": [
            "(c'_{j} = <epsilon>_{j})_[j:LIN_COMB]"
        ],
        "e_mat": [
            "(s_{2, j.dedup} ~ k_{2, j.attr} = -<epsilon>_{j})_[j:LIN_COMB]",
            "(s_{1, j} ~ k_{1, j.auth} = -<epsilon>_{j})_[j:LIN_COMB]",
            "(c_{1, j} ~ <rgid> = <epsilon>_{j})_[j:LIN_COMB]",
            "(c_{2, j} ~ r_{j.auth} = <epsilon>_{j})_[j:LIN_COMB]"
        ],
        "fdh_map": [
            "b_{l}_[l:AUTHS] # 3"
        ]
    }
}
"""  # noqa: E501
    master_key_vars = [Var("alpha", [Idx("l")], [Quant("l", QSet.AUTHORITIES)])]
    common_vars = [
        Var("b", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
        Var("b'", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]),
        Var("b", [Idx("att")], [Quant("att", QSet.ATTRIBUTE_UNIVERSE)]),
    ]
    key_polys = [
        Poly(
            "k",
            [Idx("1"), Idx("l")],
            [Quant("l", QSet.USER_ATTRIBUTES, QMap.ATTRIBUTE_TO_AUTHORITY)],
            Add(
                Add(Symbol("alpha_{l}"), Mul(Symbol("<rgid>"), Symbol("b_{l}"))),
                Mul(Symbol("r_{l}"), Symbol("b'_{l}")),
            ),
            Group.G,
        ),
        Poly(
            "k",
            [Idx("2"), Idx("att")],
            [Quant("att", QSet.USER_ATTRIBUTES)],
            Mul(Symbol("r_{att.auth}"), Symbol("b_{att}")),
            Group.G,
        ),
    ]
    cipher_polys = [
        Poly(
            "cm",
            [],
            [],
            Symbol("<secret>"),
            Group.GT,
        ),
        Poly(
            "c",
            [Idx("1"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Add(
                Symbol("<mu>_{j}"),
                Mul(Symbol("s_{1,j}"), Symbol("b_{j.auth}")),
            ),
            Group.H,
        ),
        Poly(
            "c",
            [Idx("2"), Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Add(
                Mul(Symbol("s_{1,j}"), Symbol("b'_{j.auth}")),
                Mul(Symbol("s_{2,j.dedup}"), Symbol("b_{j.attr}")),
            ),
            Group.H,
        ),
        Poly(
            "c'",
            [Idx("j")],
            [Quant("j", QSet.LSSS_ROWS)],
            Add(
                Symbol("<lambda>_{j}"),
                Mul(Symbol("alpha_{j.auth}"), Symbol("s_{1,j}")),
            ),
            Group.GT,
        ),
    ]
    decrypt_vec = [
        RawSingle(
            Var("c'", [Idx("j")]),
            Symbol("<epsilon>_{j}"),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        )
    ]
    decrypt_mat = [
        RawPair(
            Var("s", [Idx("2"), Idx("j", IMap.TO_DEDUP_INDICES)]),
            Var("k", [Idx("2"), Idx("j", IMap.TO_ATTR)]),
            Add(0, Mul(-1, Symbol("<epsilon>_{j}"))),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("s", [Idx("1"), Idx("j")]),
            Var("k", [Idx("1"), Idx("j", IMap.TO_AUTHORITY)]),
            Add(0, Mul(-1, Symbol("<epsilon>_{j}"))),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("1"), Idx("j")]),
            Var("<rgid>", []),
            Symbol("<epsilon>_{j}"),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
        RawPair(
            Var("c", [Idx("2"), Idx("j")]),
            Var("r", [Idx("j", IMap.TO_AUTHORITY)]),
            Symbol("<epsilon>_{j}"),
            [Quant("j", QSet.LINEAR_COMBINATION_INDICES)],
        ),
    ]
    fdh_map = [FdhEntry(Var("b", [Idx("l")], [Quant("l", QSet.AUTHORITIES)]), 3)]
    expected = RawScheme(
        master_key_vars,
        common_vars,
        key_polys,
        cipher_polys,
        decrypt_vec,
        decrypt_mat,
        fdh_map,
    )
    received = parse_json(json_input)
    assert received == expected
