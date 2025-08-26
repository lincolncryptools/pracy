from pracy.analysis.expr import Coeff
from pracy.backend import ir
from pracy.backend.ir import IrVar
from pracy.core.idx import Idx
from pracy.core.imap import IMap
from pracy.frontend.parsing import parse_var


def compile_coeff(ir_builder, factor):
    ir_builder.set_z(ir.TMP_Z, "1")
    tmp_z_2 = IrVar("tmp_z_2")
    for c in factor.coeffs:
        if c == Coeff(1):
            continue  # skip multiplications with 1
        if c.denom:
            # TODO: generalize this to allow arbitrary denominators here
            match c.denom:
                case [[n]] if isinstance(n, int):
                    assert c.num > 0
                    ir_builder.set_z(ir.AUX_Z, int(n))
                    ir_builder.inv_z(ir.AUX_Z, ir.AUX_Z)
                case _:
                    assert c.num == 1
                    assert c.denom == [
                        ["<xattralt>_{j}"],
                        [-1, "<xattr>_{j.attr}"],
                    ]
                    ir_builder.get_xattr_alt(tmp_z_2, IrVar("j"))
                    ir_type = ir.IrType.ATTRIBUTE
                    expr = ir.Call(ir.IrFunc.LSSS_ROW_TO_ATTR, [ir.Read(IrVar("j"))])
                    ir_builder.alloc(IrVar("x_attr_aux"), ir_type, expr)
                    ir_builder.get_xattr(ir.AUX_Z, IrVar("x_attr_aux"))
                    ir_builder.neg_z(ir.AUX_Z, ir.AUX_Z)
                    ir_builder.add_z(ir.AUX_Z, tmp_z_2, ir.AUX_Z)
                    ir_builder.inv_z(ir.AUX_Z, ir.AUX_Z)
        else:
            if isinstance(c.num, int):
                ir_builder.set_z(ir.AUX_Z, c.num)
            elif isinstance(c.num, str):
                # TODO: generalize this to allow arbitrary "special" variables here
                v = parse_var(c.num)
                if v.name == "<xattr>" and v.idcs == [Idx("att")]:
                    i = v.idcs[0].name
                    ir_builder.get_xattr(ir.AUX_Z, IrVar(i))
                elif v.name == "<xattr>" and v.idcs == [Idx("a")]:
                    i = v.idcs[0].name
                    ir_builder.get_xattr(ir.AUX_Z, IrVar(i))
                elif v.name == "<xattr>" and v.idcs == [Idx("j", IMap.TO_ATTR)]:
                    i = v.idcs[0].name
                    ir_type = ir.IrType.ATTRIBUTE
                    expr = ir.Call(ir.IrFunc.LSSS_ROW_TO_ATTR, [ir.Read(IrVar(i))])
                    ir_builder.alloc(IrVar("x_attr_aux"), ir_type, expr)
                    ir_builder.get_xattr(ir.AUX_Z, IrVar("x_attr_aux"))
                elif v.name == "<epsilon>":
                    i = v.idcs[0].name
                    ir_builder.get_epsilon(ir.AUX_Z, IrVar(i))
                else:
                    raise NotImplementedError()
        ir_builder.mul_z(ir.TMP_Z, ir.TMP_Z, ir.AUX_Z)
