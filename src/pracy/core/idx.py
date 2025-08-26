from dataclasses import dataclass
from typing import Optional

from pracy.core.imap import IMap
from pracy.core.qtype import QType
from pracy.core.quant import Quant


@dataclass
class Idx:
    """
    An `Idx` is an index which can be used to annotate a variable
    or polynomial with more information, such as distinguishing
    numbers.
    Each index may optionally be "mapped": in this case, the
    value of the index is replaced with the image of a function
    when the quantifcation(s) of pertaining object (variable or polynomial)
    is (are) resolved.
    """

    name: str
    local_map: Optional[IMap] = None

    def is_quantified(self, quants: list[Quant]) -> bool:
        """Check if `self` occurs in the given quantifications."""
        return any(q.name == self.name for q in quants)

    def get_type(self, quants: list[Quant]) -> QType | None:
        """
        Get the type of `self` after the given quantifications have been
        resolved respecting global and local maps (if given).

        If `self` is not quantified or base set, global map and local map
        do not typecheck, return `None`.
        """
        quant = next((q for q in quants if q.name == self.name), None)
        if not quant:
            return None

        idx_type = quant.base_set.get_element_type()
        if quant.global_map:
            if quant.global_map.get_domain_type() == idx_type:
                idx_type = quant.global_map.get_codomain_type()
            else:
                return None
        if self.local_map:
            if idx_type in self.local_map.get_allowed_domain_types():
                idx_type = self.local_map.get_codomain_type()
            else:
                return None
        return idx_type
