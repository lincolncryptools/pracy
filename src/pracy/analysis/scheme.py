from dataclasses import dataclass

from pracy.analysis.blinding_poly import (
    BlindingPoly,
    analyze_blinding_poly,
)
from pracy.analysis.common_vars import analyze_common_vars
from pracy.analysis.fdh_map import analyze_fdh_map
from pracy.analysis.group_map import analyze_group_map
from pracy.analysis.keypoly import (
    KeyPoly,
    analyze_key_polys,
    post_analyze_key_polys,
)
from pracy.analysis.master_keys import analyze_master_key_vars
from pracy.analysis.pair import Pair, analyze_pairs
from pracy.analysis.primary_cipher_poly import (
    PrimaryCipherPoly,
    analyze_primary_cipher_polys,
    post_analyze_primary_cipher_polys,
)
from pracy.analysis.secondary_cipher_poly import (
    SecondaryCipherPoly,
    analyze_secondary_cipher_polys,
)
from pracy.analysis.single import Single, analyze_singles
from pracy.analysis.variant import AbeVariant, analyze_variant
from pracy.core.equiv import EquivSet
from pracy.core.fdh import FdhMap
from pracy.core.group import Group, GroupMap
from pracy.core.type import VarTypeMap
from pracy.core.var import Var
from pracy.frontend.raw_scheme import RawScheme


@dataclass
class Scheme:
    variant: AbeVariant

    master_key_vars: list[Var]
    common_vars: list[Var]

    key_polys: list[KeyPoly]
    key_lone_randoms: EquivSet[Var]
    key_non_lone_randoms: EquivSet[Var]

    cipher_primaries: list[PrimaryCipherPoly]
    cipher_secondaries: list[SecondaryCipherPoly]
    cipher_blinding: BlindingPoly
    cipher_lone_randoms: EquivSet[Var]
    cipher_special_lone_randoms: EquivSet[Var]
    cipher_non_lone_randoms: EquivSet[Var]

    dec_singles: list[Single]
    dec_pairs: list[Pair]

    group_map: GroupMap
    fdh_map: FdhMap
    var_type_map: VarTypeMap


def analyze_scheme(raw_scheme: RawScheme) -> Scheme:
    key_quants = (q for kp in raw_scheme.key_polys for q in kp.quants)
    cipher_quants = (q for cp in raw_scheme.cipher_polys for q in cp.quants)
    variant = analyze_variant(key_quants, cipher_quants)

    var_type_map = VarTypeMap()

    master_key_vars = analyze_master_key_vars(var_type_map, raw_scheme.master_key_vars)
    common_vars = analyze_common_vars(var_type_map, raw_scheme.common_vars)

    group_map = GroupMap()

    key_lone_randoms = EquivSet()
    key_non_lone_randoms = EquivSet()
    key_polys = analyze_key_polys(
        variant,
        var_type_map,
        group_map,
        key_lone_randoms,
        key_non_lone_randoms,
        raw_scheme.key_polys,
    )

    cipher_lone_randoms = EquivSet()
    cipher_non_lone_randoms = EquivSet()
    cipher_special_lone_randoms = EquivSet()
    cipher_polys = _categorize_cipher_polys(raw_scheme.cipher_polys)
    cipher_primaries = analyze_primary_cipher_polys(
        variant,
        var_type_map,
        group_map,
        cipher_lone_randoms,
        cipher_non_lone_randoms,
        cipher_polys[0],
    )
    cipher_secondaries = analyze_secondary_cipher_polys(
        variant,
        var_type_map,
        cipher_non_lone_randoms,
        cipher_special_lone_randoms,
        cipher_polys[1],
    )
    cipher_blinding = analyze_blinding_poly(
        var_type_map,
        cipher_non_lone_randoms,
        cipher_special_lone_randoms,
        cipher_polys[2],
    )

    fdh_map = analyze_fdh_map(var_type_map, raw_scheme.fdh_map)

    key_polys = post_analyze_key_polys(key_polys, fdh_map)
    cipher_primaries = post_analyze_primary_cipher_polys(cipher_primaries, fdh_map)

    analyze_group_map(
        group_map,
        fdh_map,
        key_polys,
        cipher_primaries,
        common_vars,
        key_non_lone_randoms,
        cipher_non_lone_randoms,
        raw_scheme.decrypt_mat,
    )

    dec_singles = analyze_singles(var_type_map, raw_scheme.decrypt_vec)
    dec_pairs = analyze_pairs(var_type_map, group_map, raw_scheme.decrypt_mat)

    return Scheme(
        variant,
        master_key_vars,
        common_vars,
        key_polys,
        key_lone_randoms,
        key_non_lone_randoms,
        cipher_primaries,
        cipher_secondaries,
        cipher_blinding,
        cipher_lone_randoms,
        cipher_special_lone_randoms,
        cipher_non_lone_randoms,
        dec_singles,
        dec_pairs,
        group_map,
        fdh_map,
        var_type_map,
    )


def _categorize_cipher_polys(raw_polys):
    primaries = [p for p in raw_polys if p.group in {Group.G, Group.H}]
    secondaries = [p for p in raw_polys if p.group == Group.GT and p.name != "cm"]
    blindings = [p for p in raw_polys if p.name == "cm"]
    return primaries, secondaries, blindings
