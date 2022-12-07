//! Error codes from libgpg-error.

// How to update to a new version of libgpg-error.
//
// - Update src/err-codes.h.in from libgpg-error, just copy it.
// - Run make -Csrc error_codes.inc
// - Fix problems
// - Make a commit
// - Implement changes, to taste

include!("error_codes.inc");
