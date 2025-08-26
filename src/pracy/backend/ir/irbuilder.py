from pracy.backend import ir
from pracy.core.group import Group


class IrBuilder:

    def __init__(self):
        self.stmts = []
        self.num_locals = 0

    def comment(self, msg):
        self.stmts.append(ir.Comment(msg))

    def build_loops(self, var, body_gen):
        self._loops(var.quants, body_gen)

    def _loops(self, quants, body_gen):
        if not quants:
            nested_gen = IrBuilder()
            body_gen(nested_gen)
            body = nested_gen.build()
            self.stmts.extend(body)
        else:
            curr = quants[0]
            if curr.global_map:
                nested_gen = IrBuilder()
                target = ir.IrVar(curr.name)
                ir_type = ir.IrType.from_qtype(curr.global_map.get_codomain_type())
                expr = ir.Call(
                    ir.IrFunc.from_qmap(curr.global_map),
                    [ir.Read(ir.IrVar(curr.name + "_global"))],
                )
                nested_gen.alloc(target, ir_type, expr)
                body_gen(nested_gen)
                body = nested_gen.build()
                name = curr.name + "_global"
                ir_type = ir.IrType.from_qtype(curr.base_set.get_element_type())
                set = curr.base_set
                self.stmts.append(ir.Loop(name, ir_type, set, body))
            else:
                nested_gen = IrBuilder()
                nested_gen._loops(quants[1:], body_gen)
                body = nested_gen.build()
                name = curr.name
                ir_type = ir.IrType.from_qtype(curr.base_set.get_element_type())
                set = curr.base_set
                self.stmts.append(ir.Loop(name, ir_type, set, body))

    def build_index(self, var):
        self.reset_index()
        self.append_index_literal(var.name)
        self.append_index_literal("_{")
        for i, idx in enumerate(var.idcs):
            if idx.local_map:
                quants = [q for q in var.quants if q.name == idx.name]
                if not quants or len(quants) > 1:
                    raise ValueError(
                        "Cannot build index with local map if indexed is not"
                        "quantified or ambiguous."
                    )
                quant = quants[0]
                base_set = quant.base_set
                global_map = quant.global_map
                domain_type = base_set.get_element_type()
                if global_map:
                    if global_map.get_domain_type() == domain_type:
                        domain_type = global_map.get_codomain_type()
                    else:
                        raise ValueError(
                            "Unreachable: type error found while building index."
                        )

                codomain_type = idx.local_map.get_codomain_type()
                conversion = ir.IrFunc.from_domain_codomain(domain_type, codomain_type)
                ir_type = ir.IrType.from_qtype(codomain_type)
                to_string = ir.IrFunc.to_string_conversion(ir_type)
                target = ir.IrVar(idx.name + f"_local_{self.num_locals}")
                self.num_locals += 1
                expr = ir.Call(conversion, [ir.Read(ir.IrVar(idx.name))])
                self.alloc(target, ir_type, expr)
                self.append_index(target, to_string)
            else:
                if idx.is_quantified(var.quants):
                    ir_type = ir.IrType.from_qtype(idx.get_type(var.quants))
                    to_string = ir.IrFunc.to_string_conversion(ir_type)
                    self.append_index(ir.IrVar(idx.name), to_string)
                else:
                    self.append_index_literal(idx.name)

            if i < len(var.idcs) - 1:
                self.append_index_literal(",")
        self.append_index_literal("}")

    def alloc(self, target, type, source):
        self.stmts.append(ir.Alloc(target, type, source))

    def store(self, target, source):
        self.stmts.append(ir.Store(target, source))

    def store_expr(self, target, expr):
        self.stmts.append(ir.StoreExpr(target, expr))

    def reset_z(self, target):
        self.stmts.append(ir.ResetZ(target))

    def reset_g(self, target):
        self.stmts.append(ir.ResetG(target))

    def reset_h(self, target):
        self.stmts.append(ir.ResetH(target))

    def reset_gt(self, target):
        self.stmts.append(ir.ResetGt(target))

    def sample_z(self, target: ir.IrVar):
        self.stmts.append(ir.SampleZ(target))

    def add_z(self, target, lhs, rhs):
        self.stmts.append(ir.AddZ(target, lhs, rhs))

    def mul_z(self, target, lhs, rhs):
        self.stmts.append(ir.MulZ(target, lhs, rhs))

    def set_z(self, target, value):
        self.stmts.append(ir.SetZ(target, value))

    def neg_z(self, target, source):
        self.stmts.append(ir.NegZ(target, source))

    def inv_z(self, target, source):
        self.stmts.append(ir.InvZ(target, source))

    def lift_g(self, target: ir.IrVar, source: ir.IrVar):
        self.stmts.append(ir.LiftG(target, source))

    def add_g(self, target: ir.IrVar, lhs: ir.IrVar, rhs: ir.IrVar):
        self.stmts.append(ir.AddG(target, lhs, rhs))

    def scale_g(self, target: ir.IrVar, coeff: ir.IrVar, source: ir.IrVar):
        self.stmts.append(ir.ScaleG(target, coeff, source))

    def fdh_g(self, target: ir.IrVar, idx: int, arg: ir.IrVar):
        self.stmts.append(ir.FdhG(target, idx, arg))

    def lift_h(self, target: ir.IrVar, source: ir.IrVar):
        self.stmts.append(ir.LiftH(target, source))

    def add_h(self, target: ir.IrVar, lhs: ir.IrVar, rhs: ir.IrVar):
        self.stmts.append(ir.AddH(target, lhs, rhs))

    def scale_h(self, target: ir.IrVar, coeff: ir.IrVar, source: ir.IrVar):
        self.stmts.append(ir.ScaleH(target, coeff, source))

    def fdh_h(self, target: ir.IrVar, idx: int, arg: ir.IrVar):
        self.stmts.append(ir.FdhH(target, idx, arg))

    def lift_gt(self, target: ir.IrVar, source: ir.IrVar):
        self.stmts.append(ir.LiftGt(target, source))

    def add_gt(self, target: ir.IrVar, lhs: ir.IrVar, rhs: ir.IrVar):
        self.stmts.append(ir.AddGt(target, lhs, rhs))

    def scale_gt(self, target: ir.IrVar, coeff: ir.IrVar, source: ir.IrVar):
        self.stmts.append(ir.ScaleGt(target, coeff, source))

    def inv_gt(self, target: ir.IrVar, source: ir.IrVar):
        self.stmts.append(ir.InvGt(target, source))

    def pair(self, target: ir.IrVar, source_g: ir.IrVar, source_h: ir.IrVar):
        self.stmts.append(ir.Pair(target, source_g, source_h))

    def get_rgid_g(self, target):
        self.stmts.append(ir.GetRgidG(target))

    def get_rgid_h(self, target):
        self.stmts.append(ir.GetRgidH(target))

    def get_mu(self, target, idx):
        self.stmts.append(ir.GetMu(target, idx))

    def get_lambda(self, target, idx):
        self.stmts.append(ir.GetLambda(target, idx))

    def get_epsilon(self, target, idx):
        self.stmts.append(ir.GetEpsilon(target, idx))

    def get_xattr(self, target, idx):
        self.stmts.append(ir.GetXAttr(target, idx))

    def get_xattr_alt(self, target, idx):
        self.stmts.append(ir.GetXAttrAlt(target, idx))

    def get_secret(self, target):
        self.stmts.append(ir.GetSecret(target))

    def reset_index(self):
        self.stmts.append(ir.SetIndex(""))

    def set_index(self, str):
        self.stmts.append(ir.SetIndex(str))

    def append_index_literal(self, lit):
        self.stmts.append(ir.AppendIndexLiteral(lit))

    def append_index(self, source, conversion):
        self.stmts.append(ir.AppendIndex(source, conversion))

    def lift(self, group, target: ir.IrVar, source: ir.IrVar):
        match group:
            case Group.G:
                self.lift_g(target, source)
            case Group.H:
                self.lift_h(target, source)
            case Group.GT:
                self.lift_gt(target, source)
            case _:
                raise ValueError(
                    f"Cannot construct lift instruction for invalid group '{group}'."
                )

    def reset(self, group, target: ir.IrVar):
        match group:
            case Group.G:
                self.reset_g(target)
            case Group.H:
                self.reset_h(target)
            case Group.GT:
                self.reset_gt(target)
            case _:
                raise ValueError(
                    f"Cannot construct reset instruction for invalid group '{group}'."
                )

    def add(self, group, target: ir.IrVar, lhs: ir.IrVar, rhs: ir.IrVar):
        match group:
            case Group.G:
                self.add_g(target, lhs, rhs)
            case Group.H:
                self.add_h(target, lhs, rhs)
            case Group.GT:
                self.add_gt(target, lhs, rhs)
            case _:
                raise ValueError(
                    f"Cannot construct add instruction for invalid group '{group}'"
                )

    def scale(self, group, target: ir.IrVar, lhs: ir.IrVar, rhs: ir.IrVar):
        match group:
            case Group.G:
                self.scale_g(target, lhs, rhs)
            case Group.H:
                self.scale_h(target, lhs, rhs)
            case Group.GT:
                self.scale_gt(target, lhs, rhs)
            case _:
                raise ValueError(
                    f"Cannot construct scale instruction for invalid group '{group}'"
                )

    def fdh(self, group, target: ir.IrVar, idx: int, arg: ir.IrVar):
        match group:
            case Group.G:
                self.fdh_g(target, idx, arg)
            case Group.H:
                self.fdh_h(target, idx, arg)
            case _:
                raise ValueError(
                    f"Cannot construct fdh instruction for invalid group '{group}'"
                )

    def build(self):
        return self.stmts
