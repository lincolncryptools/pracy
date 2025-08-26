from pracy.analysis.typechecking import typecheck
from pracy.core.equiv import equiv
from pracy.core.sim import sim


def validate_unique_equiv(vars):
    for i, v in enumerate(vars):
        for j in range(i + 1, len(vars)):
            if equiv(v, vars[j]):
                return False
    return True


def validate_unique_sim(vars):
    for i, v in enumerate(vars):
        for j in range(i + 1, len(vars)):
            if sim(v, vars[j]):
                return False
    return True


def validate_quants(vars, allowed_qsets):
    for v in vars:
        qsets = (q.base_set for q in v.quants)
        if any(q not in allowed_qsets for q in qsets):
            return False
    return True


def validate_types(vars):
    for v in vars:
        if typecheck(v.idcs, v.quants):
            return False
    return True


def validate_all_quants_used(vars):
    for v in vars:
        quants = {q.name for q in v.quants}
        idcs = {i.name for i in v.idcs}
        if not idcs.issuperset(quants):
            return False
    return True


def validate_all_quants_occur(vars, quants):
    if len(quants) == 0:
        return True
    all_found = True
    for q in quants:
        curr_found = False
        for v in vars:
            curr_found |= any(i.name == q.name for i in v.idcs)
        all_found &= curr_found
    return all_found


def validate_special_vars(vars):
    if any(v.is_special() for v in vars):
        return False
    return True
