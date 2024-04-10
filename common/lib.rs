//! Functionality common to gpg-sq and gpgv-sq.
//!
//! Notably, this includes the command-line parser, status-fd
//! handling, and the signature verification.

use std::{
    path::{Path, PathBuf},
};

#[macro_use]
pub mod macros;
pub mod argparse;

/// Controls and configuration common to gpgv and gpg.
pub trait Common {
    /// Returns the home directory.
    fn homedir(&self) -> &Path;

    /// Returns a path that can be relative to the home directory.
    ///
    /// Canonicalizes the given path name with the property that if it
    /// contains no slash (i.e. just one component), it is interpreted
    /// as being relative to the GnuPG home directory.
    fn make_filename(&self, name: &Path) -> PathBuf {
        if name.is_relative() && name.components().count() == 1 {
            self.homedir().join(name)
        } else {
            name.into()
        }
    }
}
