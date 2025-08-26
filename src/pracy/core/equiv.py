from typing import Generic, TypeVar

from pracy.core.qset import QSet
from pracy.core.qtype import QType
from pracy.core.quant import Quant
from pracy.core.var import Var


def equiv(x, y):
    """
    Determine if two variables (or polynomials) are *equivalent*.

    Two objects are considered equivalent if and only if:
    - their names are identical
    - they have the same number of indices
    - all indices at the same positions
        - are not quantified and identicial, or
        - are quantified and have the same type (see `QType`)

    Equivalence of x and y means that "the compiler cannot (does not)
    distinguish x from y".
    """
    if x.name != y.name:
        return False
    if len(x.idcs) != len(y.idcs):
        return False

    for x_idx, y_idx in zip(x.idcs, y.idcs):
        # Quantified vs. not quantified mismatch
        if x_idx.is_quantified(x.quants) != y_idx.is_quantified(y.quants):
            return False

        # Name mismatch (for not quantified idcs)
        if not x_idx.is_quantified(x.quants) and x_idx.name != y_idx.name:
            return False

        # Type mismatch (for quantified idcs)
        if x_idx.get_type(x.quants) != y_idx.get_type(y.quants):
            is_attr_x = x_idx.get_type(x.quants) in [QType.ATTRIBUTE, QType.ALT_ATTR]
            is_attr_y = y_idx.get_type(y.quants) in [QType.ATTRIBUTE, QType.ALT_ATTR]
            return is_attr_x and is_attr_y

    return True


class EquivMap:
    """
    A dictionary-like mapping based on the equivalence relation given by `equiv`.

    This map does not rely on `__hash__` or `__eq__` of its keys, as we want keys
    which are *equivalent but not equal* to collide.

    The implementation is straight-forward and thus has linear complexity for
    read and write access.
    """

    def __init__(self, default=None):
        """
        Construct an empty EquivMap.

        Args:
            default: A callable which should provide a default value for missing
                     keys.
        """
        self._mappings = []
        self._default = default

    def __setitem__(self, key, value):
        """
        Add a new key-value pair to self.

        Raises:
            ValueError, if self already contains an equivalent key.
        """
        if key in self:
            raise ValueError("Duplicate key '{key}' not allowed in EquivMap.")
        self._mappings.append((key, value))

    def __getitem__(self, key):
        """Retrieve a value by its key from self."""
        try:
            return next(v for k, v in self._mappings if equiv(k, key))
        except StopIteration as excp:
            if self._default:
                return self._default(key)
            raise KeyError("Invalid key '{key}'.") from excp

    def __len__(self):
        """Compute the number of entries in self."""
        return len(self._mappings)

    def __contains__(self, key):
        """Test if a key is associated with a value in self."""
        return self.has_key(key)

    def __iter__(self):
        """Obtain an iterator over the key-value pairs of self."""
        return iter(self._mappings)

    def __repr__(self):
        """Convert self to its string representation."""
        return (
            f"EquivMap(_mappings: {repr(self._mappings)}, "
            f"_default: {repr(self._default)})"
        )

    def keys(self):
        """Obtain a list of all keys in self."""
        return [k for k, _ in self._mappings]

    def values(self):
        """Obtain a list of all values in self."""
        return [v for _, v in self._mappings]

    def items(self):
        """Obtain a list of all key-value pairs in self."""
        return list(self._mappings)

    def clear(self):
        """Remove all entries from self."""
        self._mappings.clear()

    def has_key(self, key):
        """Return True if and only if self has a mapping for a given key."""
        return any(equiv(k, key) for k, _ in self._mappings)

    def get(self, key, default=None):
        """Retrieve a value by its key from self."""
        try:
            return self[key]
        except KeyError:
            return default

    def __eq__(self, other):
        """
        Test if two instances of EquivMap are equal.

        This implementation tests for "semantic equality" and not physically
        (identical) representation.

        Two maps are equal if and only if:
        - they have the same domain
        - they have identical (i.e. `__eq__` returns True) values for all keys
          from domain
        """
        if not isinstance(other, EquivMap):
            return False
        if not all(other.has_key(k) for k, _ in self._mappings):
            return False
        if not all(self.has_key(k) for k, _ in other._mappings):
            return False
        if not all(self[k] == other[k] for k, _ in self._mappings):
            return False
        return True


T = TypeVar("T")


class EquivSet(Generic[T]):
    """
    A set-like container based on the equivalence relation given by `equiv`.

    This set does not rely on `__hash__` or `__eq__` of its elements, as we want
    elements which are *equivalent but not equal* to collide.

    The implementation is straight-forward and thus has linear complexity for
    read and write access.
    """

    def __init__(self, elements=None):
        """
        Construct an empty EquivSet.
        """
        self._elements = []
        if elements is not None:
            for el in elements:
                self.add(el)

    def __len__(self):
        """Compute the number of entries in self."""
        return len(self._elements)

    def __getitem__(self, idx):
        if idx < 0 or idx >= len(self):
            raise IndexError()
        return self._elements[idx]

    def __contains__(self, el):
        """Test if an element is stored in self."""
        return any(equiv(el, e) for e in self._elements)

    def __iter__(self):
        """Obtain an iterator over the elements of self."""
        return iter(self._elements)

    def __repr__(self):
        """Convert self to its string representation."""
        return f"EquivSet(_elements: {repr(self._elements)})"

    def add(self, el):
        """Add a given element to self."""
        if el not in self:
            self._elements.append(el)

    def update(self, el):
        """Add or update an element to (in) self.

        This function is designed to handle repeated insertions of equivalent
        entries where the base sets of the quantifications are not idential,
        i.e., one is a subset of the other. In these cases we need "correct" the
        existing entry.
        """
        if el not in self:
            return self.add(el)

        idx, conflict = next(
            (i, v) for i, v in enumerate(self._elements) if equiv(el, v)
        )

        quants = []
        for q in conflict.quants:
            base_set = q.base_set
            global_map = q.global_map
            if base_set in [QSet.POS_LSSS_ROWS, QSet.NEG_LSSS_ROWS]:
                base_set = QSet.LSSS_ROWS
            quants.append(Quant(q.name, base_set, global_map))
        resolved = Var(conflict.name, conflict.idcs, quants)
        self._elements[idx] = resolved

    def remove(self, el):
        """Remove a given element from self."""
        if el not in self._elements:
            raise KeyError()
        idx = next(i for i, e in enumerate(self._elements) if equiv(e, el))
        del self._elements[idx]

    def clear(self):
        """Remove all entries from self."""
        self._elements = []

    def __eq__(self, other):
        """
        Test if two instances of EquivSet are equal.

        This implementation tests for "semantic equality" and not physically
        (identical) representation.

        Two sets are equal if and only if each is a subset of the other.
        """
        if not isinstance(other, EquivSet):
            return False
        if not all(e in other for e in self._elements):
            return False
        if not all(e in self for e in other._elements):
            return False
        return True
