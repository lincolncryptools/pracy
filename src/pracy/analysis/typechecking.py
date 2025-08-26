from dataclasses import dataclass, field
from typing import Optional

from pracy.core.imap import IMap
from pracy.core.qmap import QMap
from pracy.core.qset import QSet


@dataclass
class TypeError:
    """
    An instance of this class indicates a type error between an
    index and a set of quantifications.
    """

    qset: Optional[QSet]
    global_map: Optional[QMap] = field(default=None, kw_only=True)
    local_map: Optional[IMap] = field(default=None, kw_only=True)


def typecheck(idcs, quants) -> list[TypeError]:
    """
    Type-checks a list of indices using `typecheck_idx`.
    """
    errors = (typecheck_idx(i, quants) for i in idcs)
    return [e for e in errors if e is not None]


def typecheck_idx(idx, quants) -> TypeError | None:
    """
    Type-checks the given index under the quantifications.

    This functions checks whether `localMap(global_map(base_set))` is well
    typed. If any of `localMap` or `globalMap` is not present, the
    identity function is used implicitly.

    Note that type errors are not detected for quantifications that do
    not affect the given index.

    Raises:
        ValueError, if the index is quantified more than once
    """
    quants = [q for q in quants if q.name == idx.name]
    if not quants:
        if idx.local_map is not None:
            return TypeError(None, local_map=idx.local_map)
        return None
    if len(quants) > 1:
        raise ValueError("Quantification of index is ambiguous")

    qset = quants[0].base_set
    global_map = quants[0].global_map
    local_map = idx.local_map

    curr_type = qset.get_element_type()
    if global_map:
        if curr_type != global_map.get_domain_type():
            return TypeError(qset, global_map=global_map, local_map=local_map)
        curr_type = global_map.get_codomain_type()

    if local_map:
        if curr_type not in local_map.get_allowed_domain_types():
            return TypeError(qset, global_map=global_map, local_map=local_map)

    return None
