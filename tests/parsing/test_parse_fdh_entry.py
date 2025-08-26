from pracy.core.fdh import FdhEntry
from pracy.core.idx import Idx
from pracy.core.qset import QSet
from pracy.core.quant import Quant
from pracy.core.var import Var
from pracy.frontend.parsing import parse_fdh_entry


def test_parse_fdh_entry():
    idcs = [Idx("l")]
    quants = [Quant("l", QSet.AUTHORITIES)]
    var = Var("b", idcs, quants)
    idx = 1
    expected = FdhEntry(var, idx)
    received = parse_fdh_entry("b_{l}_[l:AUTHS] # 1")
    assert received == expected
