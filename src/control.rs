//! Controls the execution of commands via the configuration.

use std::{
    io,
    path::Path,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    policy::Policy,
};

use crate::{
    keydb::KeyDB,
};

/// Controls common to gpgv and gpg.
pub trait Common {
    /// Returns the debug level.
    fn debug(&self) -> u32;

    /// Returns the home directory.
    fn homedir(&self) -> &Path;

    /// Returns a reference to the key database.
    fn keydb(&self) -> &KeyDB;

    /// Returns the output file.
    fn outfile(&self) -> Option<&String>;

    /// Returns the policy.
    fn policy(&self) -> &dyn Policy;

    /// Returns whether quiet operation has been requested.
    fn quiet(&self) -> bool;

    /// Returns whether verbose operation has been requested.
    fn verbose(&self) -> usize;

    /// Returns whether special filenames are enabled.
    fn special_filenames(&self) -> bool;

    /// Returns the logger stream.
    fn logger(&mut self) -> &mut dyn io::Write;

    /// Returns the status stream.
    fn status(&mut self) -> &mut dyn io::Write;
}
