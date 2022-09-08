//! Controls the execution of commands via the configuration.

use std::{
    fmt,
    io,
    path::{Path, PathBuf},
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    policy::Policy,
};

use crate::{
    keydb::KeyDB,
    status,
};

/// Controls common to gpgv and gpg.
pub trait Common {
    /// Returns the name of the program.
    fn argv0(&self) -> &'static str;

    /// Prints a warning to stderr.
    fn warn(&self, msg: fmt::Arguments) {
        eprintln!("{}: {}", self.argv0(), msg);
    }

    /// Prints an error to stderr.
    ///
    /// In contrast to Self::warn, this makes the program report a
    /// failure when exiting.
    fn error(&self, msg: fmt::Arguments);

    /// Returns the debug level.
    fn debug(&self) -> u32;

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
    fn status(&self) -> &status::Fd;
}


#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OwnerTrust {
    Undefined,
    Never,
    Marginal,
    Fully,
    Ultimate,
}

impl fmt::Display for OwnerTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use OwnerTrust::*;

        if f.alternate() {
            // Machine-readable.
            match self {
                Undefined => f.write_str("-"),
                Never => f.write_str("n"),
                Marginal => f.write_str("m"),
                Fully => f.write_str("f"),
                Ultimate => f.write_str("u"),
            }
        } else {
            // Human-readable.
            match self {
                Undefined => f.write_str("undefined"),
                Never => f.write_str("never"),
                Marginal => f.write_str("marginal"),
                Fully => f.write_str("full"),
                Ultimate => f.write_str("ultimate"),
            }
        }
    }
}

impl TryFrom<u8> for OwnerTrust {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> Result<Self> {
        use OwnerTrust::*;
        match v {
            2 => Ok(Undefined), // == TRUST_UNDEFINED
            3 => Ok(Never),     // == TRUST_NEVER
            4 => Ok(Marginal),  // == TRUST_MARGINAL
            5 => Ok(Fully),     // == TRUST_FULLY
            6 => Ok(Ultimate),  // == TRUST_ULTIMATE
            n => Err(anyhow::anyhow!("Bad ownertrust value {}", n)),
        }
    }
}

impl From<OwnerTrust> for u8 {
    fn from(ot: OwnerTrust) -> u8 {
        use OwnerTrust::*;
        match ot {
            Undefined => 2, // == TRUST_UNDEFINED
            Never => 3,     // == TRUST_NEVER
            Marginal => 4,  // == TRUST_MARGINAL
            Fully => 5,     // == TRUST_FULLY
            Ultimate => 6,  // == TRUST_ULTIMATE
        }
    }
}
