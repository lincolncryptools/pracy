from pracy.backend import ir
from pracy.backend.compiler.coeff import compile_coeff
from pracy.backend.ir.irbuilder import IrBuilder
from pracy.core.group import Group


def compile_keygen(lone_randoms, non_lone_randoms, key_polys, group_map, fdh_map):
    """
    Generate IR code for _keygen_ for the given random variables and key polys.

    The `lone_randoms` should be a list of unique (c.f. `equiv`) lone random
    variables excluding any special variables (e.g. "<rgid>").

    The `non_lone_randoms` should not contain duplicates (as per `equiv`) and
    also exclude any special variables.

    The `fdh_map` is used to ensure that only non-hashed non-lone randoms
    are sampled and stored as part of the user key. Its domain must at least
    encompass all `non_lone_randoms`.

    The `group_map` indicates the target groups of the non-lone randoms.
    For the key polys, the group stored in the corresponding objects is used.
    Only non-hashed non-lone randoms are queried in `group_map`.
    """
    compiler = _KeygenCompiler(group_map, fdh_map)
    return compiler.compile(lone_randoms, non_lone_randoms, key_polys)


class _KeygenCompiler:

    def __init__(self, group_map, fdh_map):
        self.group_map = group_map
        self.fdh_map = fdh_map

    def compile(self, lone_randoms, non_lone_randoms, key_polys):
        self._cg = IrBuilder()
        self._cg.comment("BEGIN KEYGEN")
        for lr in lone_randoms:
            self._compile_lone_random(lr)
        for nlr in non_lone_randoms:
            if not self.fdh_map.is_hashed(nlr):
                self._compile_non_lone_random(nlr)
        for poly in key_polys:
            self._compile_key_poly(poly)
        self._cg.comment("END KEYGEN")
        return self._cg.build()

    def _compile_lone_random(self, lr):
        def body(cg):
            cg.build_index(lr)
            cg.sample_z(ir.KEYGEN_LONE_RANDOMS.indexed_at(ir.IDX))

        self._cg.build_loops(lr, body)

    def _compile_non_lone_random(self, nlr):
        def body(cg):
            cg.build_index(nlr)
            cg.sample_z(ir.KEYGEN_NON_LONE_RANDOMS.indexed_at(ir.IDX))

            group = self.group_map[nlr]
            source = ir.KEYGEN_NON_LONE_RANDOMS.indexed_at(ir.IDX)
            targets = {
                Group.G: ir.USK_RANDOMS_G.indexed_at(ir.IDX),
                Group.H: ir.USK_RANDOMS_H.indexed_at(ir.IDX),
            }
            cg.lift(group, targets[group], source)

        self._cg.build_loops(nlr, body)

    def _compile_key_poly(self, key_poly):
        def body(cg):
            group = key_poly.group
            if group == Group.G:
                tmp = ir.TMP_G
                acc = ir.ACC_G
                target = ir.USK_POLYS_G
            else:
                tmp = ir.TMP_H
                acc = ir.ACC_H
                target = ir.USK_POLYS_H

            cg.reset_z(ir.TMP_Z)
            cg.reset_z(ir.ACC_Z)

            for term in key_poly.master_key_terms:
                self._compile_master_key_term(cg, term, key_poly)

            for term in key_poly.lone_random_terms:
                self._compile_lone_random_term(cg, term, key_poly)

            for term in key_poly.common_terms_plain:
                self._compile_plain_common_term(cg, term, key_poly)

            cg.lift(group, acc, ir.ACC_Z)

            for term in key_poly.common_terms_random_hashed:
                self._compile_hashed_random_term(cg, term, key_poly, tmp, acc, group)

            for term in key_poly.common_terms_common_hashed:
                self._compile_hashed_common_term(cg, term, key_poly, tmp, acc, group)

            cg.build_index(key_poly)
            cg.store(target.indexed_at(ir.IDX), acc)

        self._cg.build_loops(key_poly, body)

    def _compile_master_key_term(self, cg, term, poly):
        compile_coeff(cg, term.factor)
        cg.build_index(term.master_key_var.quantify(poly.quants))
        cg.mul_z(ir.TMP_Z, ir.TMP_Z, ir.MSK_ALPHAS.indexed_at(ir.IDX))
        cg.add_z(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z)

    def _compile_lone_random_term(self, cg, term, poly):
        compile_coeff(cg, term.factor)
        cg.build_index(term.random_var.quantify(poly.quants))
        cg.mul_z(ir.TMP_Z, ir.TMP_Z, ir.KEYGEN_LONE_RANDOMS.indexed_at(ir.IDX))
        cg.add_z(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z)

    def _compile_plain_common_term(self, cg, term, poly):
        compile_coeff(cg, term.factor)
        cg.build_index(term.random_var.quantify(poly.quants))
        cg.mul_z(
            ir.TMP_Z,
            ir.TMP_Z,
            ir.KEYGEN_NON_LONE_RANDOMS.indexed_at(ir.IDX),
        )
        cg.build_index(term.common_var.quantify(poly.quants))
        cg.mul_z(ir.TMP_Z, ir.TMP_Z, ir.MSK_COMMON_VARS.indexed_at(ir.IDX))
        cg.add_z(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z)

    def _compile_hashed_random_term(self, cg, term, poly, tmp, acc, group):
        compile_coeff(cg, term.factor)
        cg.build_index(term.common_var.quantify(poly.quants))
        cg.mul_z(ir.TMP_Z, ir.TMP_Z, ir.MSK_COMMON_VARS.indexed_at(ir.IDX))
        if term.random_var.name == "<rgid>":
            self._compile_get_rgid(cg, tmp, group)
        else:
            cg.build_index(term.random_var.quantify(poly.quants))
            fdh_idx = self.fdh_map[term.random_var.quantify(poly.quants)]
            cg.fdh(group, tmp, fdh_idx, ir.IDX)
        cg.scale(group, tmp, ir.TMP_Z, tmp)
        cg.add(group, acc, acc, tmp)

    def _compile_hashed_common_term(self, cg, term, poly, tmp, acc, group):
        compile_coeff(cg, term.factor)
        cg.build_index(term.random_var.quantify(poly.quants))
        cg.mul_z(
            ir.TMP_Z,
            ir.TMP_Z,
            ir.KEYGEN_NON_LONE_RANDOMS.indexed_at(ir.IDX),
        )
        cg.build_index(term.common_var.quantify(poly.quants))
        fdh_idx = self.fdh_map[term.common_var.quantify(poly.quants)]
        cg.fdh(group, tmp, fdh_idx, ir.IDX)
        cg.scale(group, tmp, ir.TMP_Z, tmp)
        cg.add(group, acc, acc, tmp)

    def _compile_get_rgid(self, cg, tmp, group):
        if group == Group.G:
            cg.get_rgid_g(tmp)
        elif group == Group.H:
            cg.get_rgid_h(tmp)
        else:
            raise ValueError("Unreachable")
