"""
This module provides analysis functions to analyze/extract the complete
group map of an ABE scheme spec based on the objects which are explicitly
assigned to either G or H.
"""

from pracy.analysis.errors import (
    GroupMapConflictingCommonVarGroups,
    GroupMapConflictingHashedKeyNonLoneRandomGroups,
    GroupMapConflictingPartnerCipherNonLoneRandomError,
    GroupMapConflictingPartnerKeyNonLoneRandomError,
    GroupMapConflictingPolyGroupsWithSharedHashedCommonVarError,
    GroupMapMissingPartnerCipherNonLoneRandomError,
    GroupMapMissingPartnerKeyNonLoneRandomError,
    GroupMapUnusedCommonVarError,
)
from pracy.core.equiv import equiv
from pracy.core.fdh import FdhMap
from pracy.core.group import GroupMap
from pracy.core.var import Var


def analyze_group_map(
    group_map: GroupMap,
    fdh_map: FdhMap,
    key_polys,
    cipher_primaries,
    common_vars,
    key_non_lone_randoms,
    cipher_non_lone_randoms,
    pairs,
):
    """
    Complete the group map of an ABE scheme by inferring the groups of objects which
    are implicitly mapped to a group.

    The function operates in 3 phases:
    1) each common var is mapped to the same group as the cipher polys which
       reference it
    2) all non-lone randoms (keygen) are mapped to the "opposite" group of their
       pairing partner
    3) all non-lone randoms (ciphertext) are mapped to the "opposite" group of their
       pairing partner
    4) all polynomials which share a hashed common variable are mapped to the same group.

    The pairing partners are (key-/cipher-) polynomials and thus explicitly assigned to
    a group.

    Concretely, this function enforces that
    - each common var is used in at least one primary cipher poly
    - all prim. polys which use a common var are mapped to the same group
    - there is exactly one pairing partner for each keygen non-lone random
    - there is exactly one pairing partner for each cipher non-lone random
    """

    for cv in common_vars:
        groups = []
        for cp in cipher_primaries:
            for term in cp.common_terms_plain + cp.common_terms_hashed:
                if equiv(term.common_var.quantify(cp.quants), cv):
                    groups.append(cp.group)
        if not groups:
            raise GroupMapUnusedCommonVarError()
        consistent = all(groups[0] == g for g in groups)
        if not consistent:
            raise GroupMapConflictingCommonVarGroups()
        group_map[cv] = groups[0]

    for nlr in key_non_lone_randoms:
        match _assign_opposite_groups(nlr, pairs, group_map):
            case "missing":
                raise GroupMapMissingPartnerKeyNonLoneRandomError()
            case "conflict":
                raise GroupMapConflictingPartnerKeyNonLoneRandomError()
            case "ok":
                pass

    for nlr in cipher_non_lone_randoms:
        match _assign_opposite_groups(nlr, pairs, group_map):
            case "missing":
                raise GroupMapMissingPartnerCipherNonLoneRandomError()
            case "conflict":
                raise GroupMapConflictingPartnerCipherNonLoneRandomError()
            case "ok":
                pass

    for cv in (v for v in common_vars if fdh_map.is_hashed(v)):
        key_polys = _find_all_usages_in_key_polys(cv, key_polys)
        cipher_primaries = _find_all_usages_in_primary_polys(cv, cipher_primaries)
        groups = [group_map[k] for k in key_polys] + [
            group_map[c] for c in cipher_primaries
        ]
        consistent = len(groups) == 0 or all(groups[0] == g for g in groups)
        if not consistent:
            raise GroupMapConflictingPolyGroupsWithSharedHashedCommonVarError()

    for kp in key_polys:
        for t in kp.common_terms_random_hashed:
            if group_map[t.random_var.quantify(kp.quants)] != kp.group:
                raise GroupMapConflictingHashedKeyNonLoneRandomGroups()


def _find_all_partners(var: Var, pairs) -> list[Var]:
    partners = []
    for p in pairs:
        lhs = p.lhs.quantify(p.quants)
        rhs = p.rhs.quantify(p.quants)
        if equiv(var, lhs) and not equiv(var, rhs):
            partners.append(rhs)
        elif not equiv(var, lhs) and equiv(var, rhs):
            partners.append(lhs)
        elif equiv(var, lhs) and equiv(var, rhs):
            raise ValueError("Invalid pairing of variable with itself.")
    return partners


def _assign_opposite_groups(var: Var, pairs, group_map: GroupMap):
    match _find_all_partners(var, pairs):
        case []:
            return "missing"
        case [p]:
            group_map[var] = group_map[p].flip()
            return "ok"
        case ps:
            groups = [group_map[p] for p in ps]
            consistent = all(groups[0] == g for g in groups)
            if not consistent:
                return "conflict"
            group_map[var] = groups[0].flip()
            return "ok"


def _find_all_usages_in_key_polys(var: Var, polys):
    usages = []
    for p in polys:
        for t in p.common_terms_common_hashed:
            if equiv(t.common_var.quantify(p.quants), var):
                usages.append(p)
    return usages


def _find_all_usages_in_primary_polys(var: Var, polys):
    usages = []
    for p in polys:
        for t in p.common_terms_hashed:
            if equiv(t.common_var.quantify(p.quants), var):
                usages.append(p)
    return usages
