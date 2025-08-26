def sim(x, y):
    """
    Determine if two variables (or polynomials) are *similar*.

    Two objects are considered similar if and only if:
    - their names are identical
    - they have the same number of indices
    - all indices at the same positions
        - are not quantified and identical, or
        - at least one is quantified

    Similarity of x and y means that "a backend (possibly) cannot distinguish
    x from y".
    """
    if x.name != y.name:
        return False
    if len(x.idcs) != len(y.idcs):
        return False

    for x_idx, y_idx in zip(x.idcs, y.idcs):
        x_is_fix = not x_idx.is_quantified(x.quants)
        y_is_fix = not y_idx.is_quantified(y.quants)

        if x_is_fix and y_is_fix and x_idx.name != y_idx.name:
            return False

    return True
