from pracy.backend import ir
from pracy.core.qset import QSet


class Relic:

    def export(self, stmts: list[ir.IrStmt]):
        return "\n".join(self._export_ir_stmt(s).strip("\n") for s in stmts)

    def _export_ir_stmt(self, stmt: ir.IrStmt, depth=0) -> str:
        indent = self._indent(depth)
        match stmt:
            case ir.Comment():
                return f"{indent}/* {stmt.text} */\n"
            case ir.Loop():
                body = "".join(self._export_ir_stmt(s, depth + 1) for s in stmt.body)
                return f"{indent}for ({self._export_ir_type(stmt.type)} {stmt.var} : {self._export_qset(stmt.set)}) {{\n{body}{indent}}}\n"
            case ir.Alloc():
                return f"{indent}{self._export_ir_type(stmt.type)} {self._export_ir_var(stmt.target)} = {self._export_ir_expr(stmt.expr)};\n"
            case ir.Store():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_var(stmt.source)};\n"
            case ir.StoreExpr():
                return f"{indent}{self._export_ir_var(stmt.target)} = {self._export_ir_expr(stmt.expr)};\n"
            case ir.ResetZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.reset_z();\n"
            case ir.ResetG():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.reset_g();\n"
            case ir.ResetH():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.reset_h();\n"
            case ir.ResetGt():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.reset_gt();\n"
            case ir.SampleZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.sample_z();\n"
            case ir.AddZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.add_z({self._export_ir_var(stmt.lhs)}, {self._export_ir_var(stmt.rhs)});\n"
            case ir.MulZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.mul_z({self._export_ir_var(stmt.lhs)}, {self._export_ir_var(stmt.rhs)});\n"
            case ir.SetZ():
                return f'{indent}{self._export_ir_var(stmt.target)} = ops.read_z("{stmt.value}");\n'
            case ir.NegZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.neg_z({self._export_ir_var(stmt.source)});\n"
            case ir.InvZ():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.inv_z({self._export_ir_var(stmt.source)});\n"
            case ir.LiftG():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.lift_g({self._export_ir_var(stmt.source)});\n"
            case ir.AddG():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.add_g({self._export_ir_var(stmt.lhs)}, {self._export_ir_var(stmt.rhs)});\n"
            case ir.ScaleG():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.scale_g({self._export_ir_var(stmt.coeff)}, {self._export_ir_var(stmt.source)});\n"
            case ir.FdhG():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.fdh_g({stmt.idx}, {self._export_ir_var(stmt.arg)});\n"
            case ir.LiftH():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.lift_h({self._export_ir_var(stmt.source)});\n"
            case ir.AddH():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.add_h({self._export_ir_var(stmt.lhs)}, {self._export_ir_var(stmt.rhs)});\n"
            case ir.ScaleH():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.scale_h({self._export_ir_var(stmt.coeff)}, {self._export_ir_var(stmt.source)});\n"
            case ir.FdhH():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.fdh_h({stmt.idx}, {self._export_ir_var(stmt.arg)});\n"
            case ir.LiftGt():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.lift_gt({self._export_ir_var(stmt.source)});\n"
            case ir.AddGt():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.add_gt({self._export_ir_var(stmt.lhs)}, {self._export_ir_var(stmt.rhs)});\n"
            case ir.ScaleGt():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.scale_gt({self._export_ir_var(stmt.coeff)}, {self._export_ir_var(stmt.source)});\n"
            case ir.InvGt():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.inv_gt({self._export_ir_var(stmt.source)});\n"
            case ir.Pair():
                return f"{indent}{self._export_ir_var(stmt.target)} = ops.pair({self._export_ir_var(stmt.source_g)}, {self._export_ir_var(stmt.source_h)});\n"
            case ir.GetRgidG():
                return (
                    f"{indent}{self._export_ir_var(stmt.target)} = env.get_rgid_g();\n"
                )
            case ir.GetRgidH():
                return (
                    f"{indent}{self._export_ir_var(stmt.target)} = env.get_rgid_h();\n"
                )
            case ir.GetMu():
                return f"{indent}{self._export_ir_var(stmt.target)} = env.get_mu({self._export_ir_var(stmt.idx)});\n"
            case ir.GetLambda():
                return f"{indent}{self._export_ir_var(stmt.target)} = env.get_lambda({self._export_ir_var(stmt.idx)});\n"
            case ir.GetEpsilon():
                return f"{indent}{self._export_ir_var(stmt.target)} = env.get_epsilon({self._export_ir_var(stmt.idx)});\n"
            case ir.GetXAttr():
                return f"{indent}{self._export_ir_var(stmt.target)} = env.get_xattr({self._export_ir_var(stmt.idx)});\n"
            case ir.GetXAttrAlt():
                return f"{indent}{self._export_ir_var(stmt.target)} = env.get_xattr_alt({self._export_ir_var(stmt.idx)});\n"
            case ir.GetSecret():
                return (
                    f"{indent}{self._export_ir_var(stmt.target)} = env.get_secret();\n"
                )
            case ir.SetIndex():
                return f'{indent}idx = "{stmt.literal}";\n'
            case ir.AppendIndexLiteral():
                return f'{indent}idx += "{stmt.literal}";\n'
            case ir.AppendIndex():
                return f"{indent}idx += {self._export_ir_func(stmt.conversion)}({self._export_ir_var(stmt.source)});\n"
            case _:
                raise NotImplementedError

    def _export_ir_expr(self, expr: ir.IrExpr) -> str:
        match expr:
            case ir.Call():
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
        name_map = {
            "usk.randoms_g": "usk.non_lone_vars_g",
            "usk.randoms_h": "usk.non_lone_vars_h",
            "ct.primaries_g": "ct.primary_polys_g",
            "ct.primaries_h": "ct.primary_polys_h",
            "ct.secondaries": "ct.secondary_polys",
            "ct.randoms_g": "ct.non_lone_vars_g",
            "ct.randoms_h": "ct.non_lone_vars_h",
        }
        name = name_map.get(var.name, var.name)
        if var.index:
            return f"{name}[{self._export_ir_expr(var.index)}]"
        return name

    def _export_ir_func(self, func: ir.IrFunc) -> str:
        res = None
        match func:
            case ir.IrFunc.ATTRIBUTE_TO_LABEL:
                res = "env.attr_to_lbl"
            case ir.IrFunc.ATTRIBUTE_TO_AUTHORITY:
                res = "env.attr_to_auth"
            case ir.IrFunc.ATTRIBUTE_TO_XATTR:
                res = "env.attr_to_xattr"
            case ir.IrFunc.LSSS_ROW_TO_AUTHORITY:
                res = "env.ls_row_to_auth"
            case ir.IrFunc.LSSS_ROW_TO_LABEL:
                res = "env.ls_row_to_lbl"
            case ir.IrFunc.LSSS_ROW_TO_ATTR:
                res = "env.ls_row_to_attr"
            case ir.IrFunc.LSSS_ROW_TO_ALT_ATTR:
                res = "env.ls_row_to_alt_attr"
            case ir.IrFunc.LSSS_ROW_TO_DEDUP_INDICES:
                res = "env.ls_row_to_dedup_idx"
            case ir.IrFunc.ATTRIBUTE_TO_STRING:
                res = "env.attr_to_string"
            case ir.IrFunc.LABEL_TO_STRING:
                res = "env.lbl_to_string"
            case ir.IrFunc.AUTHORITY_TO_STRING:
                res = "env.auth_to_string"
            case ir.IrFunc.LSSS_ROW_TO_STRING:
                res = "env.ls_row_to_string"
            case ir.IrFunc.DEDUP_IDX_TO_STRING:
                res = "env.dedup_idx_to_string"
            case _:
                raise NotImplementedError
        return res

    def _export_qset(self, qset: QSet) -> str:
        res = None
        match qset:
            case QSet.ATTRIBUTE_UNIVERSE:
                res = "env.get_attribute_universe()"
            case QSet.USER_ATTRIBUTES:
                res = "env.get_user_attributes()"
            case QSet.LABELS:
                res = "env.get_labels()"
            case QSet.AUTHORITIES:
                res = "env.get_authorities()"
            case QSet.LSSS_ROWS:
                res = "env.get_lsss_rows()"
            case QSet.POS_LSSS_ROWS:
                res = "env.get_pos_lsss_rows()"
            case QSet.NEG_LSSS_ROWS:
                res = "env.get_neg_lsss_rows()"
            case QSet.DEDUPLICATION_INDICES:
                res = "env.get_deduplication_idcs()"
            case QSet.LINEAR_COMBINATION_INDICES:
                res = "env.get_linear_combination_idcs()"
            case QSet.POS_LINEAR_COMBINATION_INDICES:
                res = "env.get_positive_linear_combination_idcs()"
            case QSet.NEG_LINEAR_COMBINATION_INDICES:
                res = "env.get_negative_linear_combination_idcs()"
        return res

    def _export_ir_type(self, type: ir.IrType) -> str:
        res = None
        match type:
            case ir.IrType.STRING:
                res = "std::string"
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
                res = "int"
            case ir.IrType.DEDUP_INDEX:
                res = "int"
            case ir.IrType.ALT_ATTR:
                res = "Attr"
        return res

    def _indent(self, width) -> str:
        return " " * 4 * width
