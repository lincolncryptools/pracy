from pracy.backend import ir
from pracy.backend.ir.irbuilder import IrBuilder
from pracy.core.group import Group


def compile_setup(master_key_vars, common_vars, group_map, fdh_map):
    """
    Generate IR code for _setup_ for the given master key and common vars.

    The given `master_key_vars` and `common_vars` should not contain
    duplicates (as per `equiv`).

    The `fdh_map` is used to determine which common vars should be excluded
    from the master key. Its domain must at least encompass all items
    of `common_vars`.

    The `group_map` is used to retrieve the target groups for the
    common vars. It is only queried for non-hashed common vars.
    Common vars can not be mapped to the target group Gt.
    """
    compiler = _SetupCompiler(group_map, fdh_map)
    return compiler.compile(master_key_vars, common_vars)


class _SetupCompiler:

    def __init__(self, group_map, fdh_map):
        self.group_map = group_map
        self.fdh_map = fdh_map

    def compile(self, master_key_vars, common_vars):
        self._cg = IrBuilder()
        self._cg.comment("BEGIN SETUP")
        for msk in master_key_vars:
            self._compile_master_key_var(msk)
        for cv in common_vars:
            if not self.fdh_map.is_hashed(cv):
                self._compile_common_var(cv)
        self._cg.comment("END SETUP")
        return self._cg.build()

    def _compile_master_key_var(self, msk):
        def body(cg):
            cg.build_index(msk)
            cg.sample_z(ir.MSK_ALPHAS.indexed_at(ir.IDX))
            cg.lift(
                Group.GT,
                ir.MPK_ALPHAS.indexed_at(ir.IDX),
                ir.MSK_ALPHAS.indexed_at(ir.IDX),
            )

        self._cg.build_loops(msk, body)

    def _compile_common_var(self, cv):
        def body(cg):
            cg.build_index(cv)
            cg.sample_z(ir.MSK_COMMON_VARS.indexed_at(ir.IDX))

            group = self.group_map[cv]
            source = ir.MSK_COMMON_VARS.indexed_at(ir.IDX)
            targets = {
                Group.G: ir.MPK_COMMON_VARS_G.indexed_at(ir.IDX),
                Group.H: ir.MPK_COMMON_VARS_H.indexed_at(ir.IDX),
            }
            cg.lift(group, targets[group], source)

        self._cg.build_loops(cv, body)
