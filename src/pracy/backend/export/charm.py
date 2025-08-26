from pracy.backend import ir
from pracy.core.qset import QSet


class Charm:

    def export(self, stmts: list[ir.IrStmt]):
        return "\n".join(self._export_ir_stmt(s).strip("\n") for s in stmts)

    def _export_ir_stmt(self, stmt: ir.IrStmt, depth=0) -> str:
        indent = self._indent(depth)
        match stmt:
            case ir.Comment():
                return f"{indent}# {stmt.text}\n"
            case ir.Loop():
                body = "".join(self._export_ir_stmt(s, depth + 1) for s in stmt.body)
                return f"{indent}for {stmt.var} in {self._export_qset(stmt.set)}:\n{body}\n"
            case ir.Alloc():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_expr(stmt.expr)}\n"
            case ir.Store():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_var(stmt.source)}\n"
            case ir.StoreExpr():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_expr(stmt.expr)}\n"
            case ir.ResetZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.reset_z()\n"
            case ir.ResetG():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.reset_g()\n"
            case ir.ResetH():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.reset_h()\n"
            case ir.ResetGt():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.reset_gt()\n"
            case ir.SampleZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.sample_z()\n"
            case ir.AddZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_var(stmt.lhs)} + {self._export_ir_var(stmt.rhs)}\n"
            case ir.MulZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_var(stmt.lhs)} * {self._export_ir_var(stmt.rhs)}\n"
            case ir.SetZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.set_z({stmt.value})\n"
            case ir.NegZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = -{self._export_ir_var(stmt.source)}\n"
            case ir.InvZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_var(stmt.source)} ** (-1)\n"
            case ir.LiftG():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.lift_g({self._export_ir_var(stmt.source)})\n"
            case ir.AddG():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_var(stmt.lhs)} * {self._export_ir_var(stmt.rhs)}\n"
            case ir.ScaleG():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_var(stmt.source)} ** {self._export_ir_var(stmt.coeff)}\n"
            case ir.FdhG():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.fdh_g({stmt.idx}, {self._export_ir_var(stmt.arg)})\n"
            case ir.LiftH():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.lift_h({self._export_ir_var(stmt.source)})\n"
            case ir.AddH():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_var(stmt.lhs)} * {self._export_ir_var(stmt.rhs)}\n"
            case ir.ScaleH():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_var(stmt.source)} ** {self._export_ir_var(stmt.coeff)}\n"
            case ir.FdhH():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.fdh_h({stmt.idx}, {self._export_ir_var(stmt.arg)})\n"
            case ir.LiftGt():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.lift_gt({self._export_ir_var(stmt.source)})\n"
            case ir.AddGt():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_var(stmt.lhs)} * {self._export_ir_var(stmt.rhs)}\n"
            case ir.ScaleGt():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_var(stmt.source)} ** {self._export_ir_var(stmt.coeff)}\n"
            case ir.InvGt():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_var(stmt.source)} ** (-1)\n"
            case ir.Pair():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.pair_groups({self._export_ir_var(stmt.source_g)}, {self._export_ir_var(stmt.source_h)})\n"
            case ir.GetRgidG():
                return (
                    f"{indent}{self._export_ir_var(stmt.target)} = self.get_rgid_g()\n"
                )
            case ir.GetRgidH():
                return (
                    f"{indent}{self._export_ir_var(stmt.target)} = self.get_rgid_h()\n"
                )
            case ir.GetMu():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.get_maskingvalue({self._export_ir_var(stmt.idx)})\n"
            case ir.GetLambda():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.get_share({self._export_ir_var(stmt.idx)})\n"
            case ir.GetEpsilon():
                return f"{indent}{self._export_ir_var(stmt.target)} = self.get_coefficient({self._export_ir_var(stmt.idx)})\n"
            case ir.GetXAttr():
                return f"{indent}{self._export_ir_var(stmt.target)} = xattr[{self._export_ir_var(stmt.idx)}]\n"
            case ir.GetXAttrAlt():
                return f"{indent}{self._export_ir_var(stmt.target)} = xattr_alt[{self._export_ir_var(stmt.idx)}]\n"
            case ir.GetSecret():
                return (
                    f"{indent}{self._export_ir_var(stmt.target)} = self.get_secret()\n"
                )
            case ir.SetIndex():
                return f'{indent}idx = "{stmt.literal}"\n'
            case ir.AppendIndexLiteral():
                return f'{indent}idx += "{stmt.literal}"\n'
            case ir.AppendIndex():
                return f"{indent}idx += {self._export_ir_func(stmt.conversion)}({self._export_ir_var(stmt.source)})\n"
            case _:
                raise NotImplementedError()

    def _export_ir_expr(self, expr: ir.IrExpr) -> str:
        match expr:
            case ir.Call():
                match expr.func:
                    case ir.IrFunc.ATTRIBUTE_TO_LABEL:
                        return f"self.map_attribute_to_label({self._export_ir_expr(expr.args[0])})"
                    case ir.IrFunc.ATTRIBUTE_TO_AUTHORITY:
                        return f"self.map_attribute_to_authority({self._export_ir_expr(expr.args[0])})"
                    case ir.IrFunc.ATTRIBUTE_TO_XATTR:
                        return f"{self._export_ir_expr(expr.args[0])}.attr_repr.xattr"
                    case ir.IrFunc.LSSS_ROW_TO_AUTHORITY:
                        return f"LSSS_map[{self._export_ir_expr(expr.args[0])}].attr_repr.auth"
                    case ir.IrFunc.LSSS_ROW_TO_LABEL:
                        return f"LSSS_map[{self._export_ir_expr(expr.args[0])}].attr_repr.lbl"
                    case ir.IrFunc.LSSS_ROW_TO_ATTR:
                        return f"LSSS_map[{self._export_ir_expr(expr.args[0])}].attr_repr.value"
                    case ir.IrFunc.LSSS_ROW_TO_ALT_ATTR:
                        return (
                            f"{self._export_ir_expr(expr.args[0])}.attr_repr.alt_attr"
                        )
                    case ir.IrFunc.LSSS_ROW_TO_DEDUP_INDICES:
                        return f"LSSS_map[{self._export_ir_expr(expr.args[0])}].tau"
                    case _:
                        func = self._export_ir_func(expr.func)
                        args = ", ".join(self._export_ir_expr(e) for e in expr.args)
                        return f"{func}({args})"
            case ir.Read():
                return self._export_ir_var(expr.source)
            case ir.StringLiteral():
                return expr.text
            case ir.IntLiteral():
                return str(expr.value)
            case _:
                raise NotImplementedError

    def _export_ir_var(self, var: ir.IrVar) -> str:
        match var.name:
            case "idx":
                return "idx"
            case "tmp_z":
                return "tmp_z"
            case "acc_z":
                return "acc_z"
            case "tmp_g":
                return "tmp_g"
            case "acc_g":
                return "acc_g"
            case "tmp_h":
                return "tmp_h"
            case "acc_h":
                return "acc_h"
            case "tmp_gt":
                return "tmp_gt"
            case "acc_gt":
                return "acc_gt"

            case "msk.alphas":
                return f"MSK['alpha'][{self._export_ir_expr(var.index)}]"
            case "mpk.alphas":
                return f"MPK['alpha'][{self._export_ir_expr(var.index)}]"
            case "msk.common_vars":
                return f"MSK['b'][{self._export_ir_expr(var.index)}]"
            case "mpk.common_vars_g":
                return f"MPK['b_g'][{self._export_ir_expr(var.index)}]"
            case "mpk.common_vars_h":
                return f"MPK['b_h'][{self._export_ir_expr(var.index)}]"

            case "usk.polys_g":
                return f"SK['k_g'][{self._export_ir_expr(var.index)}]"
            case "usk.polys_h":
                return f"SK['k_h'][{self._export_ir_expr(var.index)}]"
            case "usk.randoms_g":
                return f"SK['r_g'][{self._export_ir_expr(var.index)}]"
            case "usk.randoms_h":
                return f"SK['r_h'][{self._export_ir_expr(var.index)}]"

            case "blinding_poly":
                return "blinding_poly"
            case "ct.blinding_poly":
                return "CT['C']"
            case "ct.primaries_g":
                return f"CT['bold_C_g'][{self._export_ir_expr(var.index)}]"
            case "ct.primaries_h":
                return f"CT['bold_C_h'][{self._export_ir_expr(var.index)}]"
            case "ct.secondaries":
                return f"CT['bold_C_prime'][{self._export_ir_expr(var.index)}]"
            case "ct.randoms_g":
                return f"CT['bold_s_g'][{self._export_ir_expr(var.index)}]"
            case "ct.randoms_h":
                return f"CT['bold_s_h'][{self._export_ir_expr(var.index)}]"

            case "lone_randoms":
                if var.index:
                    return f"{var.name}[{self._export_ir_expr(var.index)}]"
                return "lone_randoms"
            case "non_lone_randoms":
                if var.index:
                    return f"{var.name}[{self._export_ir_expr(var.index)}]"
                return "non_lone_randoms"
            case "special_lone_randoms":
                if var.index:
                    return f"{var.name}[{self._export_ir_expr(var.index)}]"
                return "special_lone_randoms"

            case _:
                return var.name

    def _export_ir_func(self, func: ir.IrFunc) -> str:
        match func:
            case ir.IrFunc.ATTRIBUTE_TO_LABEL:
                return "attr_to_lbl"
            case ir.IrFunc.ATTRIBUTE_TO_AUTHORITY:
                return "attr_to_auth"
            case ir.IrFunc.ATTRIBUTE_TO_XATTR:
                return "attr_to_xattr"
            case ir.IrFunc.LSSS_ROW_TO_AUTHORITY:
                return "ls_row_to_auth"
            case ir.IrFunc.LSSS_ROW_TO_LABEL:
                return "ls_row_to_lbl"
            case ir.IrFunc.LSSS_ROW_TO_ATTR:
                return "ls_row_to_attr"
            case ir.IrFunc.LSSS_ROW_TO_ALT_ATTR:
                return "ls_row_to_alt_attr"
            case ir.IrFunc.LSSS_ROW_TO_DEDUP_INDICES:
                return "ls_row_to_dedup"

            case ir.IrFunc.ATTRIBUTE_TO_STRING:
                return "self.string_of_attribute"
            case ir.IrFunc.LABEL_TO_STRING:
                return "str"
            case ir.IrFunc.AUTHORITY_TO_STRING:
                return "str"
            case ir.IrFunc.LSSS_ROW_TO_STRING:
                return "str"
            case ir.IrFunc.DEDUP_IDX_TO_STRING:
                return "str"

    def _export_qset(self, qset: QSet) -> str:
        match qset:
            case QSet.ATTRIBUTE_UNIVERSE:
                return "ATTRIBUTE_UNIVERSE"
            case QSet.USER_ATTRIBUTES:
                return "USER_ATTRIBUTES"
            case QSet.LABELS:
                return "LABELS"
            case QSet.AUTHORITIES:
                return "AUTHORITIES"
            case QSet.LSSS_ROWS:
                return "LSSS_ROWS"
            case QSet.POS_LSSS_ROWS:
                return "POS_LSSS_ROWS"
            case QSet.NEG_LSSS_ROWS:
                return "NEG_LSSS_ROWS"
            case QSet.DEDUPLICATION_INDICES:
                return "DEDUPLICATION_INDICES"
            case QSet.LINEAR_COMBINATION_INDICES:
                return "LINEAR_COMB_INDICES"
            case QSet.POS_LINEAR_COMBINATION_INDICES:
                return "POS_LINEAR_COMB_INDICES"
            case QSet.NEG_LINEAR_COMBINATION_INDICES:
                return "NEG_LINEAR_COMB_INDICES"

    def _export_ir_type(self, type: ir.IrType) -> str:
        res = None
        match type:
            case ir.IrType.STRING:
                res = "str"
            case ir.IrType.Z:
                res = "Z"
            case ir.IrType.G:
                res = "G"
            case ir.IrType.H:
                res = "H"
            case ir.IrType.GT:
                res = "Gt"
            case ir.IrType.ATTRIBUTE:
                res = "Attr"
            case ir.IrType.LABEL:
                res = "Lbl"
            case ir.IrType.AUTHORITY:
                res = "Auth"
            case ir.IrType.LSSS_ROW:
                res = "LsRow"
            case ir.IrType.DEDUP_INDEX:
                res = "DedupIdx"
        return res

    def _indent(self, width) -> str:
        return " " * 4 * width
