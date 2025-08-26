from dataclasses import dataclass
from typing import Optional

from pracy.core.qmap import QMap
from pracy.core.qset import QSet


@dataclass
class Quant:
    """
    A `Quant` is a piece of meta-data that models mathematical "for-all"
    quantifications of variables and polynomials.
    Essentially, a `Quant` with `name = x` and `baseSet = X` represents
    "for all x in X". The set `X` may optionally be mapped with a function
    `f`, which would correspond to the mathematical
    `for all x in {f(y) | y in Y}`.

    Valid base sets and maps are given by the `QSet` and `QMap` types.
    """

    name: str
    base_set: QSet
    global_map: Optional[QMap] = None
