"""
This module contains all possible error conditions that can be detected
during the analysis of an ABE scheme specification.
"""


class AnalysisError(Exception):
    """
    An umbrella class to catch all possible errors that could happend during scheme
    analysis.
    """


class AbeSchemeVariantAmbiguousError(AnalysisError):
    """The ABE scheme cannot be unambigiously categorized as either KP- or CP-ABE."""


class AbeSchemeVariantContradictoryError(AnalysisError):
    """The ABE scheme neither fits the KP- nor the CP-ABE variant."""


class MasterKeyVarsEmptyError(AnalysisError):
    """No master key vars are specified."""


class MasterKeyVarsNonUniqueError(AnalysisError):
    """Two or more master key vars have equivalent names."""


class MasterKeyVarsIllegalQuantError(AnalysisError):
    """
    The master key var contains quantifications which reference ineligible base
    sets.
    """


class MasterKeyVarsTypeError(AnalysisError):
    """
    The indices of a master key var do not type check under the
    given quantifications.
    """


class MasterKeyVarsUnusedQuantsError(AnalysisError):
    """
    The quantifications of the master key var introduce new names which are
    never referenced.
    """


class MasterKeyVarsIllegalSpecialVarError(AnalysisError):
    """The master key var is defined as a special variable."""


class CommonVarsEmptyError(AnalysisError):
    """No common vars are specified."""


class CommonVarsNonUniqueError(AnalysisError):
    """Two or more common vars have equivalent names."""


class CommonVarsIllegalQuantError(AnalysisError):
    """
    The common var contains quantifications which reference ineligible base
    sets.
    """


class CommonVarsTypeError(AnalysisError):
    """
    The indices of a commmon var to not type check under the
    given quantifications.
    """


class CommonVarsOverlapMasterKeyVarsError(AnalysisError):
    """A common variable is equivalent to a master key variable."""


class CommonVarsUnusedQuantsError(AnalysisError):
    """
    The quantifications of the common var introduce new names which are
    never referenced.
    """


class CommonVarsIllegalSpecialVarError(AnalysisError):
    """The common var is defined as a special variable."""


class FdhMapIllegalVarTypeError(AnalysisError):
    """
    This exception indicates that a variable indicated to be hashed is neither a
    common variable, nor a non-lone random key variable.
    """


class FdhMapNonUniqueError(AnalysisError):
    """
    This exception indicates that two or more (not neccessarilry contradictory) FDH
    index specifications refer to the same variable.
    """


class FdhMapIllegalQuantError(AnalysisError):
    """
    This exception indicates an illegal QSet used in a quantified FDH index
    specification.
    """


class FdhMapIllegalSpecialVarError(AnalysisError):
    """
    This exception indicates that one or more FDH index specifications reference
    a special variable.
    """


class FdhMapTypeError(AnalysisError):
    """This exception indicates that a quantified index does not type check."""


class FdhMapUnusedQuantsError(AnalysisError):
    """
    This exception indicates that a quantification introduces a name which is not used
    anywhere.
    """


class FdhMapInvalidIndexError(AnalysisError):
    """The FDH index is zero or negative which is not allowed."""


class KeyPolyInvalidTermError(AnalysisError):
    """The key poly contains a term with an unexpected number of symbols."""


class KeyPolyUncomputableTermError(AnalysisError):
    """
    The key poly contains a term which is uncomputable since both terms
    are hashed.
    """


class KeyPolyInvalidUnaryTermError(AnalysisError):
    """
    The key poly contains a unary term which is not a master key variable or
    a lone random variable.
    """


class KeyPolyInvalidBinaryTermError(AnalysisError):
    """
    The key poly contains a binary term of which neither factor is
    a common variable.
    """


class KeyPolysNonUniqueError(AnalysisError):
    """Two or more key polynomials have equivalent names."""


class KeyPolyUnusedQuantsError(AnalysisError):
    """The key poly has quantifications which introduce a name that is never used."""


class KeyPolyIllegalQuantsError(AnalysisError):
    """The key poly contains quantifications which reference ineligible base sets."""


class KeyPolyInvalidExpressionError(AnalysisError):
    """The expression denoting the key polynomial can not be analyzed properly."""


class KeyPolyInvalidGroupError(AnalysisError):
    """The key poly is designated to be placed in a group other than G or H."""


class KeyPolyIllegalSpecialVarError(AnalysisError):
    """The key poly references illegal special variables."""


class KeyPolyIsSpecialError(AnalysisError):
    """The key poly itself is a special variable."""


class KeyPolysEmptyError(AnalysisError):
    """No key polys are given."""


class KeyPolyTypeError(AnalysisError):
    """
    The indices of a key poly or a variable in its body do not type check under the
    given quantifications.
    """


class KeyPolyInconsistentLoneRandomVar(AnalysisError):
    """
    A variable has been identified as key lone random variable but is already
    associated with another type.
    """


class KeyPolyInconsistentNonLoneRandomVar(AnalysisError):
    """
    A variable has been identified as key non-lone random variable but is already
    associated with another type.
    """


class KeyPolyInconsistentPoly(AnalysisError):
    """A key polynomial is already associated with another type."""


class PrimaryPolysEmptyError(AnalysisError):
    """No primary cipher polys are given."""


class PrimaryPolyIsSpecialError(AnalysisError):
    """The primary poly itself is a special variable."""


class PrimaryPolyInvalidExpressionError(AnalysisError):
    """The expression denoting the primary cipher poly can not be analyzed properly."""


class PrimaryPolyTypeError(AnalysisError):
    """
    The indices of a primary cipher poly or a variable in its body to not type check
    under the given quantifications.
    """


class PrimaryPolyIllegalSpecialVarError(AnalysisError):
    """The primary cipher poly references illegal special variables."""


class PrimaryPolyInvalidUnaryTermError(AnalysisError):
    """
    The primary cipher poly contains a unary term which references a common,
    non-lone or master key variable.
    """


class PrimaryPolyInvalidBinaryTermError(AnalysisError):
    """
    The primary cipher poly contains a binary term which references two variables
    of unexpected kind.
    """


class PrimaryPolyInvalidTermError(AnalysisError):
    """
    The primary cipher poly contains an unexpected term with zero or more than
    two factors.
    """


class PrimaryPolyNonUniqueError(AnalysisError):
    """Two or more primary cipher polynomials have equivalent names."""


class PrimaryPolyUnusedQuantsError(AnalysisError):
    """
    The quantifications of a primary cipher poly introduce new names which are
    never referenced.
    """


class PrimaryPolyIllegalQuantsError(AnalysisError):
    """
    The primary cipher poly is quantified of sets which are not available during
    encryption.
    """


class PrimaryPolyInconsistentPolyError(AnalysisError):
    """A primary cipher poly is already associated with another type."""


class PrimaryPolyInconsistentLoneRandomVarError(AnalysisError):
    """
    A variable has been identified as cipher lone random variable but is already
    associated with another type.
    """


class PrimaryPolyInconsistentNonLoneRandomVarError(AnalysisError):
    """
    A variable has been identified as cipher non-lone random variable but is already
    associated with another type.
    """


class SecondaryPolyInvalidExpressionError(AnalysisError):
    """
    The expression denoting the secondary cipher poly can not be analyzed properly.
    """


class SecondaryPolyTypeError(AnalysisError):
    """
    The indices of a secondary cipher poly or a variable in its body to not type check
    under the given quantifications.
    """


class SecondaryPolyIsSpecialError(AnalysisError):
    """The secondary poly itself is a special variable."""


class SecondaryPolyIllegalSpecialVarError(AnalysisError):
    """The secondary cipher poly references illegal special variables."""


class SecondaryPolyInvalidUnaryTermError(AnalysisError):
    """
    The secondary cipher poly contains a unary term which references a common,
    non-lone or master key variable.
    """


class SecondaryPolyInvalidBinaryTermError(AnalysisError):
    """
    The secondary cipher poly contains a binary term which references two variables
    of unexpected kind.
    """


class SecondaryPolyInvalidTermError(AnalysisError):
    """
    The secondary cipher poly contains an unexpected term with zero or more than
    two factors.
    """


class SecondaryPolyNonUniqueError(AnalysisError):
    """Two or more secondary cipher polynomials have equivalent names."""


class SecondaryPolyUnusedQuantsError(AnalysisError):
    """
    The quantifications of a secondary cipher poly introduce new names which are
    never referenced.
    """


class SecondaryPolyIllegalQuantsError(AnalysisError):
    """
    The secondary cipher poly is quantified of sets which are not available during
    encryption.
    """


class SecondaryPolyInconsistentPolyError(AnalysisError):
    """A secondary cipher poly is already associated with another type."""


class SecondaryPolyInvalidGroupError(AnalysisError):
    """The secondary poly is designated to be placed in a group other than Gt."""


class SecondaryPolyInvalidNameError(AnalysisError):
    """The secondary poly is named "cm" which is reserved for the blinding poly."""


class SecondaryPolyInconsistentSpecialLoneRandomVarError(AnalysisError):
    """
    A variable has been identified as cipher special-lone random variable but is already
    associated with another type.
    """


class SecondaryPolyInconsistentNonLoneRandomVarError(AnalysisError):
    """
    A variable has been identified as cipher non-lone random variable but is already
    associated with another type.
    """


class BlindingPolyInconsistentSpecialLoneRandomVarError(AnalysisError):
    """
    A variable has been identified as cipher special-lone random variable but is already
    associated with another type.
    """


class BlindingPolyInconsistentNonLoneRandomVarError(AnalysisError):
    """
    A variable has been identified as cipher non-lone random variable but is already
    associated with another type.
    """


class BlindingPolyInconsistentPolyError(AnalysisError):
    """The blinding poly is already associated with another type."""


class BlindingPolyMissingError(AnalysisError):
    """No blinding poly is specified."""


class BlindingPolyAmbigiousError(AnalysisError):
    """Multiple blinding polynomials are specified."""


class BlindingPolyInvalidTermError(AnalysisError):
    """
    The blinding poly contains an unexpected term with zero or more than
    two factors.
    """


class BlindingPolyInvalidUnaryTermError(AnalysisError):
    """
    The blinding poly contains a unary term which references a common,
    non-lone or master key variable.
    """


class BlindingPolyInvalidBinaryTermError(AnalysisError):
    """
    The blinding poly contains a binary term which references two variables
    of unexpected kind.
    """


class BlindingPolyIsQuantifiedError(AnalysisError):
    """The blinding poly is not a single value but quantified over some base sets."""


class BlindingPolyIsIndexedError(AnalysisError):
    """The blinding poly has indices."""


class BlindingPolyInvalidExpressionError(AnalysisError):
    """The expression denoting the blinding poly can not be analyzed properly."""


class BlindingPolyInvalidGroupError(AnalysisError):
    """The blinding poly is not specified to be placed in the target group."""


class BlindingPolyIllegalSpecialVarError(AnalysisError):
    """The blinding poly references illegal special variables."""


class BlindingPolyIsSpecialError(AnalysisError):
    """The blinding poly itself is a special var."""


class BlindingPolyInvalidNameError(AnalysisError):
    """The blinding poly is not named "cm" as expected."""


class BlindingPolyTypeError(AnalysisError):
    """
    The indices of a variable in the body of the blinding poly do not type check
    under the given quantifications.
    """


class GroupMapUnusedCommonVarError(AnalysisError):
    """
    A common var is not used in any primary cipher poly and can thus not be
    placed in a group unambigiously.
    """


class GroupMapConflictingCommonVarGroups(AnalysisError):
    """
    A common var is used in multiple primary cipher polys which are mapped to
    different groups.
    """


class GroupMapConflictingHashedKeyNonLoneRandomGroups(AnalysisError):
    """
    A key non-lone rnaodm variable is hashed, but the groups of its parent
    key poly and partner cipher poly clash.
    """


class GroupMapMissingPartnerKeyNonLoneRandomError(AnalysisError):
    """
    No pairing involves the key non-lone random which could be used to infer the
    group assignment of said variable.
    """


class GroupMapConflictingPartnerKeyNonLoneRandomError(AnalysisError):
    """
    Multiple pairings involve the same key non-lone random var which would
    place it in conflicting groups.
    """


class GroupMapMissingPartnerCipherNonLoneRandomError(AnalysisError):
    """
    No pairing involves the cipher non-lone random which could be used to infer
    the group assignment of said variable.
    """


class GroupMapConflictingPartnerCipherNonLoneRandomError(AnalysisError):
    """
    Multiple pairings involve the same cipher non-lone random var which would
    place it in conflicting groups.
    """


class GroupMapConflictingPolyGroupsWithSharedHashedCommonVarError(AnalysisError):
    """
    Two or more polynomials which share a hashed common variable are not
    all placed in the same group.
    """


class SingleInvalidExpressionError(AnalysisError):
    """
    The expression denoting the exponent of a (decryption) single is
    not well-formed.
    """


class SingleUnusedQuantsError(AnalysisError):
    """
    The quantifications of a single introduce new names which are
    never referenced.
    """


class SinglesIllegalSpecialVarError(AnalysisError):
    """The single contains invalid special variables."""


class SinglesTypeError(AnalysisError):
    """
    The indices of a single do not type check under the given
    quantifications.
    """


class SingleInconsistentVarType(AnalysisError):
    """
    A variable referenced in a Single is not a secondary cipher poly as
    expected.
    """


class PairInvalidExpressionError(AnalysisError):
    """
    The expression denoting the exponent of a (decryption) pair is
    not well-formed.
    """


class PairsIllegalSpecialVarError(AnalysisError):
    """The pair contains invalid special variables."""


class PairsTypeError(AnalysisError):
    """
    The indices of a pair do not type check under the given
    quantifications.
    """


class PairInconsistentVarTypeError(AnalysisError):
    """
    The arguments to a pairing are not of the expected/allowed type combinations.
    """


class PairUnusedQuantsError(AnalysisError):
    """The quantifications introduce one or more new names which are never used."""


class PairIllegalGroupCombination(AnalysisError):
    """The pair references two variables which are not in opposite source groups."""
