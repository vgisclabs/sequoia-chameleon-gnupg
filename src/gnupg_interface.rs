//! Defines the emulated GnuPG interface version.

// How to update to a new version of GnuPG.
//
// - Update VERSION.
// - Update src/gpg.option.gpg.c.fragment from GnuPG's gpg.c
// - Run make -Csrc gpg.option.inc
// - Fix problems
// - Make a commit
// - Implement changes, to taste

/// The GnuPG version we re-implement.
pub const VERSION: &str = "2.2.40";

/// Match GnuPG's behavior more strictly.
///
/// Strictly match GnuPG's output even if the protocol allows other
/// output as well (e.g. GnuPG may only emit key ids whereas
/// doc/DETAILS says fingerprints are also allowed), or where a
/// symbolic output instead of numeric output would be nicer for
/// humans on human-readable output.
///
/// Annoyingly, test suites don't understand how key handles alias, so
/// aligning more closely with GnuPG avoids a lot of false positives.
pub const STRICT_OUTPUT: bool = true;

/// Controls emitting of decryption compliance information.
///
/// This compile-time constant controls whether we should claim
/// compliance with e.g. `crate::compliance::DeVSProducer`.
///
/// Changes to GnuPG indicate that compliance is also a matter of
/// using compliant software stacks.  Therefore, until we are
/// certified to be compliant, we shouldn't claim compliance.
///
/// Happily, since GnuPG 2.2.28, newer versions of gcrypt are
/// considered to be non-compliant unless gcrypt claims compliance.
/// As of this writing, no version of gcrypt claims to be compliant,
/// so not claiming compliance is consistent with what GnuPG currently
/// does on most machines.
pub const EMIT_DECRYPTION_COMPLIANCE: bool = false;

/// Controls emitting of encryption compliance information.
///
/// This compile-time constant controls whether we should claim
/// compliance with e.g. `crate::compliance::DeVSProducer`.
///
/// Changes to GnuPG indicate that compliance is also a matter of
/// using compliant software stacks.  Therefore, until we are
/// certified to be compliant, we shouldn't claim compliance.
///
/// Although, since GnuPG 2.2.28, newer versions of gcrypt are
/// considered to be non-compliant unless gcrypt claims compliance.
/// As of this writing, no version of gcrypt claims to be compliant,
/// and GnuPG 2.2.40 stopped emitting encryption compliance
/// information if gcrypt does not claim compliance.
pub const EMIT_ENCRYPTION_COMPLIANCE: bool = false;
