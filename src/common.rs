//! Controls the execution of commands via the configuration.

use std::{
    fmt,
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Fingerprint,
    KeyHandle,
    packet::UserID,
    policy::Policy,
};

use crate::{
    keydb::KeyDB,
    status,
};

pub mod cert;

/// Controls common to gpgv and gpg.
pub trait Common {
    /// Returns the name of the program.
    fn argv0(&self) -> &'static str;

    /// Prints a warning to stderr.
    fn warn(&self, msg: fmt::Arguments) {
        crate::with_invocation_log(
            |w| Ok(write!(w, "{}: {}", self.argv0(), msg)?));
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

    /// Returns the active trust model.
    fn trust_model_impl(&self) -> &dyn Model;

    /// Returns the current (fake) time.
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustModel {
    PGP,
    Classic,
    Always,
    Direct,
    Tofu,
    TofuPGP,
    Auto,
    Unknown(u8),
}

impl From<u8> for TrustModel {
    fn from(v: u8) -> Self {
        // See enum trust_model in g10/options.h.
        use TrustModel::*;
        match v {
            0 => Classic,
            1 => PGP,
            3 => Always,
            4 => Direct,
            5 => Auto,
            6 => Tofu,
            7 => TofuPGP,
            n => Unknown(n),
        }
    }
}

impl Default for TrustModel {
    fn default() -> Self {
        TrustModel::Auto
    }
}

impl std::str::FromStr for TrustModel {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pgp" => Ok(TrustModel::PGP),
            "classic" => Ok(TrustModel::Classic),
            "always" => Ok(TrustModel::Always),
            "direct" => Ok(TrustModel::Direct),
            "tofu" => Ok(TrustModel::Tofu),
            "tofu+pgp" => Ok(TrustModel::TofuPGP),
            "auto" => Ok(TrustModel::Auto),
            _ => Err(anyhow::anyhow!("Unknown trust model {:?}", s)),
        }
    }
}

impl fmt::Display for TrustModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TrustModel::*;
        match self {
            PGP => f.write_str("pgp"),
            Classic => f.write_str("classic"),
            Always => f.write_str("always"),
            Direct => f.write_str("direct"),
            Tofu => f.write_str("tofu"),
            TofuPGP => f.write_str("tofu+pgp"),
            Auto => f.write_str("auto"),
            Unknown(n) => write!(f, "unknown({})", n),
        }
    }
}

pub trait Model {
    fn with_policy<'a>(&'a self, config: &'a crate::Config, at: Option<SystemTime>)
                      -> Result<Box<dyn ModelViewAt + 'a>>;
}

pub fn null_model() -> Box<dyn Model> {
    struct Null(());
    impl Model for Null {
        fn with_policy<'a>(&'a self, _: &'a crate::Config, _: Option<SystemTime>)
                           -> Result<Box<dyn ModelViewAt + 'a>>
        {
            Err(anyhow::anyhow!("Cannot instantiate null model"))
        }
    }
    Box::new(Null(()))
}

pub trait ModelViewAt<'a> {
    fn kind(&self) -> TrustModel;
    fn time(&self) -> SystemTime;
    fn policy(&self) -> &dyn Policy;
    fn validity(&self, userid: &UserID, fingerprint: &Fingerprint)
                -> Result<Validity>;

    fn lookup(&self, query: &Query) -> Result<Vec<&'a Cert>>;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Validity {
    Unknown,
    Revoked, // XXX: This is a flag in GnuPG.
    Expired, // XXX: This is a flag in GnuPG.
    Undefined,
    Never,
    Marginal,
    Fully,
    Ultimate,
}

impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Validity::*;
        match self {
            Unknown => f.write_str("-"),
            Revoked => f.write_str("r"),
            Expired => f.write_str("e"),
            Undefined => f.write_str("q"),
            Never => f.write_str("n"),
            Marginal => f.write_str("m"),
            Fully => f.write_str("f"),
            Ultimate => f.write_str("u"),
        }
    }
}

impl fmt::Display for crate::babel::Fish<Validity> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Validity::*;
        match self.0 {
            Unknown => f.write_str("unknown"),
            Revoked => f.write_str("revoked"),
            Expired => f.write_str("expired"),
            Undefined => f.write_str("undefined"),
            Never => f.write_str("never"),
            Marginal => f.write_str("marginal"),
            Fully => f.write_str("full"),
            Ultimate => f.write_str("ultimate"),
        }
    }
}

/// A query for certs, e.g. for use with `--recipient` and
/// `--list-keys`.
#[derive(Clone, Debug)]
pub enum Query<'a> {
    Key(KeyHandle),
    ExactKey(KeyHandle),
    Email(String),
    UserIDFragment(memchr::memmem::Finder<'a>),
}

impl fmt::Display for Query<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Query::Key(h) => write!(f, "{}", h),
            Query::ExactKey(h) => write!(f, "{}!", h),
            Query::Email(e) => write!(f, "<{}>", e),
            Query::UserIDFragment(v) =>
                write!(f, "{}", String::from_utf8_lossy(v.needle())),
        }
    }
}

impl<'a> From<&'a str> for Query<'a> {
    fn from(s: &str) -> Query {
        if s.ends_with("!") {
            if let Ok(h) = s[..s.len()-1].parse() {
                return Query::ExactKey(h);
            }
        }

        if let Ok(h) = s.parse() {
            Query::Key(h)
        } else if s.starts_with("<") && s.ends_with(">") {
            Query::Email(s[1..s.len()-1].into())
        } else {
            Query::UserIDFragment(memchr::memmem::Finder::new(s))
        }
    }
}

impl Query<'_> {
    /// Returns whether `cert` matches this query.
    ///
    /// Note: the match must be authenticated!
    pub fn matches(&self, cert: &Cert) -> bool {
        match self {
            Query::Key(h) | Query::ExactKey(h) =>
                cert.keys().any(|k| k.key_handle().aliases(h)),
            Query::Email(e) => cert.userids().any(|u| u.email().ok().flatten().as_ref() == Some(e)),
            Query::UserIDFragment(f) =>
                cert.userids().any(|u| f.find(u.value()).is_some()),
        }
    }

    /// Returns whether a userid matches this query.
    ///
    /// Note: the match must be authenticated!
    pub fn matches_userid(&self, uid: &UserID) -> bool {
        match self {
            Query::Key(_) | Query::ExactKey(_) => false,
            Query::Email(e) => uid.email().ok().flatten().as_ref() == Some(e),
            Query::UserIDFragment(f) => f.find(uid.value()).is_some(),
        }
    }
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
