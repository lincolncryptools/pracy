from pracy.backend import ir
from pracy.backend.compiler.coeff import compile_coeff
from pracy.backend.ir.irbuilder import IrBuilder
from pracy.core.group import Group


def compile_encrypt(
    lone_randoms,
    special_lone_randoms,
    non_lone_randoms,
    primaries,
    secondaries,
    blinding,
    group_map,
    fdh_map,
):
    """
    Generate IR code for _encrypt_ for the given random variables and
    cipher polys.

    The `lone_randoms` should be a list of pairwise non-equivalent
    lone random variables excluding any special variables (e.g. "<secret>").

    Similarly, `special_lone_randoms` and `non_lone_randoms` must also
    be unique (w.r.t. `equiv`) and not contain special variables.

    The `fdh_map` determines which non-lone randoms are included in the
    user key (only those with FDH == 0). Its domain must cover at
    least all `non_lone_randoms`.

    The `group_map` is used to store the non-lone vars in the right
    field of the user key.

    The `primaries` should be a list of unique primary polynomials
    (i.e. those in G and/or H).

    The `secondaries` are the polynomials in Gt which are not the
    blinding polynomial itself.

    The `blinding` (polynomial) is the one named `cm` in Gt which is
    actually used to hide the secret message.
    """
    compiler = _EncryptCompiler(group_map, fdh_map)
    return compiler.compile(
        lone_randoms,
        special_lone_randoms,
        non_lone_randoms,
        primaries,
        secondaries,
        blinding,
    )


class _EncryptCompiler:

    def __init__(self, group_map, fdh_map):
        self.group_map = group_map
        self.fdh_map = fdh_map

    def compile(
        self,
        lone_randoms,
        special_lone_randoms,
        non_lone_randoms,
        primaries,
        secondaries,
        blinding,
    ):
        self._cg = IrBuilder()
        self._cg.comment("BEGIN ENCRYPT")
        for lr in lone_randoms:
            self._compile_lone_random(lr)
        for slr in special_lone_randoms:
            self._compile_special_lone_random(slr)
        for nlr in non_lone_randoms:
            self._compile_non_lone_random(nlr)
        for p in primaries:
            self._compile_primary(p)
        for s in secondaries:
            self._compile_secondary(s)
        self._compile_blinding(blinding)
        self._cg.comment("END ENCRYPT")
        return self._cg.build()

    def _compile_lone_random(self, lr):
        def body(cg):
            cg.build_index(lr)
            cg.sample_z(ir.ENCRYPT_LONE_RANDOMS.indexed_at(ir.IDX))

        self._cg.build_loops(lr, body)

    def _compile_special_lone_random(self, lr):
        def body(cg):
            cg.build_index(lr)
            cg.sample_z(ir.ENCRYPT_SPECIAL_LONE_RANDOMS.indexed_at(ir.IDX))

        self._cg.build_loops(lr, body)

    def _compile_non_lone_random(self, nlr):
        def body(cg):
            cg.build_index(nlr)
            cg.sample_z(ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX))

            group = self.group_map[nlr]
            source = ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX)
            targets = {
                Group.G: ir.CT_RANDOMS_G.indexed_at(ir.IDX),
                Group.H: ir.CT_RANDOMS_H.indexed_at(ir.IDX),
            }
            cg.lift(group, targets[group], source)

        if nlr.name != "<secret>":
            self._cg.build_loops(nlr, body)
        else:
            # This cannot be inside a loop
            self._cg.build_index(nlr)
            self._cg.get_secret(ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX))

            group = self.group_map[nlr]
            source = ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX)
            targets = {
                Group.G: ir.CT_RANDOMS_G.indexed_at(ir.IDX),
                Group.H: ir.CT_RANDOMS_H.indexed_at(ir.IDX),
            }
            self._cg.lift(group, targets[group], source)

    def _compile_primary(self, poly):
        def body(cg):
            group = poly.group
            if group == Group.G:
                tmp = ir.TMP_G
                acc = ir.ACC_G
                target = ir.CT_PRIMARIES_G
            else:
                tmp = ir.TMP_H
                acc = ir.ACC_H
                target = ir.CT_PRIMARIES_H

            cg.reset_z(ir.TMP_Z)
            cg.reset_z(ir.ACC_Z)
            cg.reset(group, tmp)
            cg.reset(group, acc)

            for term in poly.lone_random_terms:
                self._compile_primary_lone_random_term(cg, term, poly)

            cg.lift(group, acc, ir.ACC_Z)

            for term in poly.common_terms_plain:
                self._compile_primary_plain_common_term(cg, term, poly, tmp, acc, group)

            for term in poly.common_terms_hashed:
                self._compile_primary_hashed_common_term(
                    cg, term, poly, tmp, acc, group
                )

            cg.build_index(poly)
            cg.store(target.indexed_at(ir.IDX), acc)

        self._cg.build_loops(poly, body)

    def _compile_primary_lone_random_term(self, cg, term, poly):
        compile_coeff(cg, term.factor)
        if term.random_var.name == "<mu>":
            self._compile_get_mu(cg, term)
        elif term.random_var.name == "<lambda>":
            self._compile_get_lambda(cg, term)
        elif term.random_var.name == "<secret>":
            self._compile_get_secret(cg)
        else:
            cg.build_index(term.random_var.quantify(poly.quants))
            cg.mul_z(
                ir.TMP_Z,
                ir.TMP_Z,
                ir.ir.ENCRYPT_LONE_RANDOMS.indexed_at(ir.IDX),
            )
        cg.add_z(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z)

    def _compile_primary_plain_common_term(self, cg, term, poly, tmp, acc, group):
        compile_coeff(cg, term.factor)
        if term.random_var.name == "<lambda>":
            self._compile_get_lambda(cg, term)
        else:
            cg.build_index(term.random_var.quantify(poly.quants))
            cg.mul_z(
                ir.TMP_Z,
                ir.TMP_Z,
                ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX),
            )
        if group == Group.G:
            source = ir.MPK_COMMON_VARS_G
        else:
            source = ir.MPK_COMMON_VARS_H
        cg.build_index(term.common_var.quantify(poly.quants))
        cg.store(tmp, source.indexed_at(ir.IDX))
        cg.scale(group, tmp, ir.TMP_Z, tmp)
        cg.add(group, acc, acc, tmp)

    def _compile_primary_hashed_common_term(self, cg, term, poly, tmp, acc, group):
        compile_coeff(cg, term.factor)
        if term.random_var.name == "<lambda>":
            self._compile_get_lambda(cg, term)
        else:
            cg.build_index(term.random_var.quantify(poly.quants))
            cg.mul_z(
                ir.TMP_Z,
                ir.TMP_Z,
                ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX),
            )
        cg.build_index(term.common_var.quantify(poly.quants))
        fdh_idx = self.fdh_map[term.common_var.quantify(poly.quants)]
        cg.fdh(group, tmp, fdh_idx, ir.IDX)
        cg.scale(group, tmp, ir.TMP_Z, tmp)
        cg.add(group, acc, acc, tmp)

    def _compile_secondary(self, poly):
        def body(cg):
            cg.reset_z(ir.TMP_Z)
            cg.reset_z(ir.ACC_Z)
            cg.reset_gt(ir.TMP_GT)
            cg.reset_gt(ir.ACC_GT)

            for term in poly.special_lone_random_terms:
                self._compile_secondary_special_lone_term(cg, term, poly)

            cg.lift_gt(ir.ACC_GT, ir.ACC_Z)

            for term in poly.master_key_terms:
                self._compile_secondary_master_key_term(cg, term, poly)

            cg.build_index(poly)
            cg.store(ir.CT_SECONDARIES.indexed_at(ir.IDX), ir.ACC_GT)

        self._cg.build_loops(poly, body)

    def _compile_secondary_special_lone_term(self, cg, term, poly):
        compile_coeff(cg, term.factor)
        if term.random_var.name == "<lambda>":
            self._compile_get_lambda(cg, term)
        else:
            cg.build_index(term.random_var.quantify(poly.quants))
            cg.mul_z(
                ir.TMP_Z,
                ir.TMP_Z,
                ir.ir.ENCRYPT_SPECIAL_LONE_RANDOMS.indexed_at(ir.IDX),
            )
        cg.add_z(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z)

    def _compile_secondary_master_key_term(self, cg, term, poly):
        compile_coeff(cg, term.factor)
        cg.build_index(term.master_key_var.quantify(poly.quants))
        cg.store(ir.TMP_GT, ir.MPK_ALPHAS.indexed_at(ir.IDX))
        cg.build_index(term.random_var.quantify(poly.quants))
        cg.mul_z(
            ir.TMP_Z,
            ir.TMP_Z,
            ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX),
        )
        cg.scale_gt(ir.TMP_GT, ir.TMP_Z, ir.TMP_GT)
        cg.add_gt(ir.ACC_GT, ir.ACC_GT, ir.TMP_GT)

    def _compile_blinding(self, blinding):
        def body(cg):
            cg.reset_z(ir.TMP_Z)
            cg.reset_z(ir.ACC_Z)
            cg.reset_gt(ir.TMP_GT)
            cg.reset_gt(ir.ACC_GT)

            for term in blinding.special_lone_random_terms:
                self._compile_blinding_special_term(cg, term)

            cg.lift_gt(ir.ACC_GT, ir.ACC_Z)

            for term in blinding.master_key_terms:
                self._compile_blinding_master_key_term(cg, term, blinding)

            cg.store(ir.CT_BLINDING_POLY, ir.ACC_GT)

        self._cg.build_loops(blinding, body)

    def _compile_blinding_special_term(self, cg, term):
        compile_coeff(cg, term.factor)
        if term.random_var.name == "<secret>":
            self._compile_get_secret(cg)
        else:
            cg.build_index(term.random_var)
            cg.add_z(
                ir.TMP_Z,
                ir.TMP_Z,
                ir.IrVar.special_lone_randoms.indexed_at(ir.IDX),
            )
        cg.add_z(ir.ACC_Z, ir.ACC_Z, ir.TMP_Z)

    def _compile_blinding_master_key_term(self, cg, term, poly):
        compile_coeff(cg, term.factor)
        cg.build_index(term.master_key_var.quantify(poly.quants))
        cg.store(ir.TMP_GT, ir.MPK_ALPHAS.indexed_at(ir.IDX))
        if term.random_var.name == "<secret>":
            self._compile_get_secret(cg)
        else:
            cg.build_index(term.random_var.quantify(poly.quants))
            cg.mul_z(
                ir.TMP_Z,
                ir.TMP_Z,
                ir.ENCRYPT_NON_LONE_RANDOMS.indexed_at(ir.IDX),
            )
        cg.scale_gt(ir.TMP_GT, ir.TMP_Z, ir.TMP_GT)
        cg.add_gt(ir.ACC_GT, ir.ACC_GT, ir.TMP_GT)

    def _compile_get_mu(self, cg, term):
        i = term.random_var.idcs[0].name
        cg.get_mu(ir.AUX_Z, ir.IrVar(i))
        cg.mul_z(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z)

    def _compile_get_lambda(self, cg, term):
        i = term.random_var.idcs[0].name
        cg.get_lambda(ir.AUX_Z, ir.IrVar(i))
        cg.mul_z(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z)

    def _compile_get_secret(self, cg):
        cg.get_secret(ir.AUX_Z)
        cg.mul_z(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z)
