from pracy.backend import ir
from pracy.backend.compiler.coeff import compile_coeff
from pracy.backend.ir.irbuilder import IrBuilder
from pracy.core.group import Group
from pracy.core.type import VarType
from pracy.core.var import Var


def compile_decrypt(singles, pairs, var_type_map, fdh_map):
    compiler = _DecryptCompiler(var_type_map, fdh_map)
    return compiler.compile(singles, pairs)


class _DecryptCompiler:

    def __init__(self, var_type_map, fdh_map):
        self.var_type_map = var_type_map
        self.fdh_map = fdh_map

    def compile(self, singles, pairs):
        self._cg = IrBuilder()
        self._cg.comment("BEGIN DECRYPT")
        for single in singles:
            self._compile_single(single)

        for pair in pairs:
            self._compile_pair(pair)

        self._cg.store(ir.BLINDING_POLY, ir.ACC_GT)
        self._cg.comment("END DECRYPT")
        return self._cg.build()

    def _compile_single(self, single):
        def body(cg):
            assert len(single.coeff) == 1  # for now assume that we have products only
            compile_coeff(cg, single.coeff[0])
            cg.build_index(single.entry.quantify(single.quants))
            cg.scale_gt(
                ir.TMP_GT,
                ir.TMP_Z,
                ir.CT_SECONDARIES.indexed_at(ir.IDX),
            )
            cg.add_gt(ir.ACC_GT, ir.ACC_GT, ir.TMP_GT)

        self._cg.build_loops(single, body)

    def _compile_pair(self, pair):
        def body(cg):
            self._compile_get_g_component(cg, pair)
            self._compile_get_h_component(cg, pair)
            cg.pair(ir.TMP_GT, ir.TMP_G, ir.TMP_H)
            assert len(pair.terms) == 1  # for now assume that we have products only
            compile_coeff(cg, pair.terms[0])
            cg.scale_gt(ir.TMP_GT, ir.TMP_Z, ir.TMP_GT)
            cg.add_gt(ir.ACC_GT, ir.ACC_GT, ir.TMP_GT)

        self._cg.build_loops(pair, body)

    def _compile_get_g_component(self, cg, pair):
        if pair.arg_g.name == "<rgid>":
            cg.get_rgid_g(ir.TMP_G)
        else:
            arg_g = pair.arg_g.quantify(pair.quants)
            cg.build_index(arg_g)
            if self.fdh_map.is_hashed(arg_g):
                fdh_idx = self.fdh_map[arg_g]
                cg.fdh_g(ir.TMP_G, fdh_idx, ir.IDX)
            else:
                loc = self._get_var_location(arg_g, Group.G)
                cg.store(ir.TMP_G, loc.indexed_at(ir.IDX))

    def _compile_get_h_component(self, cg, pair):
        if pair.arg_h.name == "<rgid>":
            cg.get_rgid_h(ir.TMP_H)
        else:
            arg_h = pair.arg_h.quantify(pair.quants)
            cg.build_index(arg_h)
            if self.fdh_map.is_hashed(arg_h):
                fdh_idx = self.fdh_map[arg_h]
                cg.fdh_h(ir.TMP_H, fdh_idx, ir.IDX)
            else:
                loc = self._get_var_location(arg_h, Group.H)
                cg.store(ir.TMP_H, loc.indexed_at(ir.IDX))

    def _get_var_location(self, var: Var, group: Group) -> ir.IrVar | None:
        match group, self.var_type_map[var]:
            case Group.G, VarType.KEY_NON_LONE_RANDOM_VAR:
                return ir.USK_RANDOMS_G
            case Group.H, VarType.KEY_NON_LONE_RANDOM_VAR:
                return ir.USK_RANDOMS_H
            case Group.G, VarType.KEY_POLY:
                return ir.USK_POLYS_G
            case Group.H, VarType.KEY_POLY:
                return ir.USK_POLYS_H
            case Group.G, VarType.CIPHER_NON_LONE_RANDOM:
                return ir.CT_RANDOMS_G
            case Group.H, VarType.CIPHER_NON_LONE_RANDOM:
                return ir.CT_RANDOMS_H
            case Group.G, VarType.CIPHER_PRIMARY_POLY:
                return ir.CT_PRIMARIES_G
            case Group.H, VarType.CIPHER_PRIMARY_POLY:
                return ir.CT_PRIMARIES_H
        return None
