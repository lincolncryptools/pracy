from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

import pracy.backend.ir as ir

if TYPE_CHECKING:
    from pracy.backend.ir.irexpr import IrExpr
else:

    class IrExpr:
        pass


@dataclass
class IrVar:
    name: str
    index: Optional[IrExpr] = None

    def indexed_at(self, idx):
        if isinstance(idx, IrVar):
            return IrVar(self.name, ir.Read(idx))
        return IrVar(self.name, idx)


IDX = IrVar("idx")
TMP_Z = IrVar("tmp_z")
AUX_Z = IrVar("aux_z")
ACC_Z = IrVar("acc_z")
TMP_G = IrVar("tmp_g")
ACC_G = IrVar("acc_g")
TMP_H = IrVar("tmp_h")
ACC_H = IrVar("acc_h")
TMP_GT = IrVar("tmp_gt")
ACC_GT = IrVar("acc_gt")

MSK_ALPHAS = IrVar("msk.alphas")
MPK_ALPHAS = IrVar("mpk.alphas")
MSK_COMMON_VARS = IrVar("msk.common_vars")
MPK_COMMON_VARS_G = IrVar("mpk.common_vars_g")
MPK_COMMON_VARS_H = IrVar("mpk.common_vars_h")

USK_POLYS_G = IrVar("usk.polys_g")
USK_POLYS_H = IrVar("usk.polys_h")
USK_RANDOMS_G = IrVar("usk.randoms_g")
USK_RANDOMS_H = IrVar("usk.randoms_h")
KEYGEN_LONE_RANDOMS = IrVar("lone_randoms")
KEYGEN_NON_LONE_RANDOMS = IrVar("non_lone_randoms")

BLINDING_POLY = IrVar("blinding_poly")
CT_BLINDING_POLY = IrVar("ct.blinding_poly")
CT_PRIMARIES_G = IrVar("ct.primaries_g")
CT_PRIMARIES_H = IrVar("ct.primaries_h")
CT_SECONDARIES = IrVar("ct.secondaries")
CT_RANDOMS_G = IrVar("ct.randoms_g")
CT_RANDOMS_H = IrVar("ct.randoms_h")
ENCRYPT_LONE_RANDOMS = IrVar("lone_randoms")
ENCRYPT_NON_LONE_RANDOMS = IrVar("non_lone_randoms")
ENCRYPT_SPECIAL_LONE_RANDOMS = IrVar("special_lone_randoms")
