//! Controls the execution of commands via the configuration.

use std::{
    fmt,
    path::{Path, PathBuf},
    time::SystemTime,
    sync::Arc,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    KeyHandle,
    packet::UserID,
    policy::Policy,
};

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;

use crate::{
    keydb::KeyDB,
    status,
};

pub mod cert;

/// Until Sequoia 2.0, we have to match on the OID to recognize this
/// curve.
pub const BRAINPOOL_P384_OID: &[u8] =
    &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];

/// Controls common to gpgv and gpg.
pub trait Common<'store> {
    /// Returns the name of the program.
    fn argv0(&self) -> &'static str;

    /// Prints a non-prefixed message to the log stream.
    fn log(&self, msg: fmt::Arguments);

    /// Prints an informative message to stderr if we are not in quiet
    /// operation.
    fn info(&self, msg: fmt::Arguments) {
        if ! self.quiet() {
            self.warn(msg);
        }
    }

    /// Prints a warning to stderr.
    fn warn(&self, msg: fmt::Arguments) {
        crate::with_invocation_log(
            |w| Ok(write!(w, "{}: {}", self.argv0(), msg)?));
        self.log(format_args!("{}: {}", self.argv0(), msg));
    }

    /// Prints an error to stderr.
    ///
    /// In contrast to Self::warn, this makes the program report a
    /// failure when exiting.
    fn error(&self, msg: fmt::Arguments);

    /// Sets an explicit status code, and prevents the error message
    /// to be shown at the end of the main function.
    fn override_status_code(&self, _code: i32) {
        // Nop for gpgv.
    }

    /// Prints the usage and the given message and returns an error.
    fn wrong_args(&self, message: &str) -> Result<()> {
        eprintln!("usage: {} [options] {}", self.argv0(), message);
        self.override_status_code(2);
        Err(anyhow::anyhow!("Wrong arguments: {}", message))
    }

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
    fn keydb(&self) -> &KeyDB<'store>;

    /// Returns certs matching a given query using groups and the
    /// configured trust model.
    fn lookup_certs(&self, query: &Query)
                    -> anyhow::Result<Vec<(Validity, Arc<LazyCert<'store>>)>>;

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

    /// Returns the status stream.
    fn status(&self) -> &status::Fd;

    /// Returns the active trust model.
    fn trust_model_impl(&self) -> &dyn Model;

    /// Returns the current (fake) time.
    fn now(&self) -> SystemTime;

    /// Returns whether fingerprints should be included in the output.
    fn with_fingerprint(&self) -> bool;
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
    /// Creates a view under the given configuration, policy, and
    /// time.
    fn with_policy<'a, 'store>(
        &self,
        config: &'a crate::Config<'store>,
        at: Option<SystemTime>)
        -> Result<Box<dyn ModelViewAt<'a, 'store> + 'a>>
    where
        'store: 'a,
    {
        self.with_policy_and_precompute(config, at, false)
    }

    /// Creates a view under the given configuration, policy, and
    /// time, and possibly pre-compute the network.
    ///
    /// Note: when considering all or most of the certificates,
    /// pre-computing will improve performance.
    fn with_policy_and_precompute<'a, 'store>(
        &self,
        config: &'a crate::Config<'store>,
        at: Option<SystemTime>,
        precompute: bool)
        -> Result<Box<dyn ModelViewAt<'a, 'store> + 'a>>
    where
        'store: 'a;
}

pub fn null_model() -> Box<dyn Model> {
    struct Null(());
    impl Model for Null {
        fn with_policy_and_precompute<'a, 'store>(
            &self, _: &'a crate::Config,
            _: Option<SystemTime>,
            _: bool)
            -> Result<Box<dyn ModelViewAt<'a, 'store> + 'a>>
            where 'store: 'a
        {
            Err(anyhow::anyhow!("Cannot instantiate null model"))
        }
    }
    Box::new(Null(()))
}

pub trait ModelViewAt<'a, 'store> {
    fn kind(&self) -> TrustModel;
    fn time(&self) -> SystemTime;
    fn policy(&self) -> &dyn Policy;
    fn validity(&self, userid: &UserID, fingerprint: &Fingerprint)
                -> Result<Validity>;

    fn lookup(&self, query: &Query)
        -> Result<Vec<(Validity, Arc<LazyCert<'store>>)>>;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Validity {
    pub level: ValidityLevel,
    pub revoked: bool,
    pub expired: bool,
}

impl PartialOrd for Validity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

use std::cmp::Ordering;
impl Ord for Validity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.revoked.cmp(&other.revoked).reverse()
            .then_with(|| self.expired.cmp(&other.expired).reverse())
            .then_with(|| self.level.cmp(&other.level))
    }
}

impl From<ValidityLevel> for Validity {
    fn from(level: ValidityLevel) -> Self {
        Validity {
            level,
            revoked: false,
            expired: false,
        }
    }
}

impl Validity {
    /// Returns a revoked validity.
    pub fn revoked() -> Self {
        Validity {
            level: ValidityLevel::Unknown,
            revoked: true,
            expired: false,
        }
    }

    /// Returns an expired validity.
    pub fn expired() -> Self {
        Validity {
            level: ValidityLevel::Unknown,
            revoked: false,
            expired: true,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidityLevel {
    Unknown,
    Undefined,
    Never,
    Marginal,
    Fully,
    Ultimate,
}

impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.revoked {
            f.write_str("r")
        } else if self.expired {
            f.write_str("e")
        } else {
            use ValidityLevel::*;
            match self.level {
                Unknown => f.write_str("-"),
                Undefined => f.write_str("q"),
                Never => f.write_str("n"),
                Marginal => f.write_str("m"),
                Fully => f.write_str("f"),
                Ultimate => f.write_str("u"),
            }
        }
    }
}

impl fmt::Display for crate::babel::Fish<Validity> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.revoked {
            f.write_str("revoked")
        } else if self.0.expired {
            f.write_str("expired")
        } else {
            use ValidityLevel::*;
            match self.0.level {
                Unknown => f.write_str("unknown"),
                Undefined => f.write_str("undefined"),
                Never => f.write_str("never"),
                Marginal => f.write_str("marginal"),
                Fully => f.write_str("full"),
                Ultimate => f.write_str("ultimate"),
            }
        }
    }
}

/// A query for certs, e.g. for use with `--recipient` and
/// `--list-keys`.
#[derive(Clone, Debug)]
pub enum Query {
    Key(KeyHandle),
    ExactKey(KeyHandle),
    Email(String),
    UserIDFragment(String),
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Query::Key(h) => write!(f, "{}", h),
            Query::ExactKey(h) => write!(f, "{}!", h),
            Query::Email(e) => write!(f, "<{}>", e),
            Query::UserIDFragment(frag) =>
                write!(f, "{}", frag),
        }
    }
}

impl std::str::FromStr for Query {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.ends_with("!") {
            if let Ok(h) = s[..s.len()-1].parse() {
                return Ok(Query::ExactKey(h));
            }
        }

        if let Ok(h) = s.parse() {
            if let KeyHandle::Fingerprint(Fingerprint::Invalid(b)) = &h {
                if b.len() == 4 {
                    return Err(anyhow::anyhow!(
                        "Short key IDs are insecure and not supported: {}", s));
                }
            }

            Ok(Query::Key(h))
        } else if s.starts_with("<") && s.ends_with(">") {
            Ok(Query::Email(s[1..s.len()-1].to_lowercase()))
        } else {
            Ok(Query::UserIDFragment(s.to_lowercase()))
        }
    }
}

impl Query {
    /// Returns whether `cert` matches this query.
    ///
    /// Note: the match must be authenticated!
    pub fn matches(&self, cert: &Arc<LazyCert>) -> bool {
        // We do the test twice.  First, potentially on the RawCert,
        // where the binding signatures haven't been checked.  Only if
        // that matches do we canonicalize the cert, and re-do the
        // check to make sure.
        self.matches_internal(cert)
            && cert.to_cert()
            .map(|_| self.matches_internal(cert))
            .unwrap_or(false)
    }

    fn matches_internal(&self, cert: &Arc<LazyCert>) -> bool {
        match self {
            Query::Key(h) | Query::ExactKey(h) =>
                cert.keys().any(|k| k.key_handle().aliases(h)),
            Query::Email(e) => cert.userids().any(|u| u.email2().ok().flatten() == Some(e.as_str())),
            Query::UserIDFragment(f) =>
                cert.userids().any(|u| {
                    if let Ok(u) = std::str::from_utf8(u.value()) {
                        u.to_lowercase().contains(f)
                    } else {
                        false
                    }
                }),
        }
    }

    /// Returns whether a userid matches this query.
    ///
    /// Note: the match must be authenticated!
    pub fn matches_userid(&self, uid: &UserID) -> bool {
        match self {
            Query::Key(_) | Query::ExactKey(_) => false,
            Query::Email(e) => uid.email2().ok().flatten() == Some(e.as_str()),
            Query::UserIDFragment(f) =>
                if let Ok(u) = std::str::from_utf8(uid.value()) {
                    u.to_lowercase().contains(f)
                } else {
                    false
                },
        }
    }

    /// Returns the cert's User ID matching the query.
    ///
    /// This falls back to a best-effort heuristic to compute the
    /// primary User ID if the query matches a key.
    pub fn best_effort_uid(&self,
                           policy: &dyn Policy,
                           cert: &openpgp::Cert)
                           -> String
    {
        match self {
            Query::Key(_) | Query::ExactKey(_) => (),
            Query::Email(_) | Query::UserIDFragment(_) =>
                for uidb in cert.userids() {
                    if self.matches_userid(uidb.userid()) {
                        return String::from_utf8_lossy(
                            uidb.userid().value()).into();
                    }
                },
        }

        crate::utils::best_effort_primary_uid(policy, cert)
    }

    /// Returns whether this query uses a fingerprint or key ID.
    pub fn by_key_handle(&self) -> bool {
        match self {
            Query::Key(_) |
            Query::ExactKey(_) => true,
            Query::Email(_) |
            Query::UserIDFragment(_) => false
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OwnerTrust {
    level: OwnerTrustLevel,
    disabled: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OwnerTrustLevel {
    Unknown,
    Undefined,
    Never,
    Marginal,
    Fully,
    Ultimate,
}

impl From<OwnerTrustLevel> for OwnerTrust {
    fn from(level: OwnerTrustLevel) -> OwnerTrust {
        OwnerTrust {
            level,
            disabled: false,
        }
    }
}

impl OwnerTrust {
    pub fn level(&self) -> OwnerTrustLevel {
        self.level
    }

    pub fn disabled(&self) -> bool {
        self.disabled
    }
}

impl fmt::Display for OwnerTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use OwnerTrustLevel::*;

        if f.alternate() {
            // Machine-readable.
            match self.level {
                Unknown => f.write_str("-"), // XXX
                Undefined => f.write_str("-"),
                Never => f.write_str("n"),
                Marginal => f.write_str("m"),
                Fully => f.write_str("f"),
                Ultimate => f.write_str("u"),
            }
        } else {
            // Human-readable.
            match self.level {
                Unknown => f.write_str("unknown"), // XXX
                Undefined => f.write_str("undefined"),
                Never => f.write_str("never"),
                Marginal => f.write_str("marginal"),
                Fully => f.write_str("full"),
                Ultimate => f.write_str("ultimate"),
            }
        }
    }
}

/// The mask covers the type.
const OWNERTRUST_MASK: u8 = 15;

/// Not yet assigned.
const OWNERTRUST_UNKNOWN: u8 = 0;

/// Not enough information for calculation (q).
const OWNERTRUST_UNDEFINED: u8 = 2;

/// Never trust this pubkey (n).
const OWNERTRUST_NEVER: u8 = 3;

/// Marginally trusted (m).
const OWNERTRUST_MARGINAL: u8 = 4;

/// Fully trusted (f).
const OWNERTRUST_FULLY: u8 = 5;

/// Ultimately trusted (u).
const OWNERTRUST_ULTIMATE: u8 = 6;

/// Key/uid disabled (d).
const OWNERTRUST_FLAG_DISABLED: u8 = 128;

impl TryFrom<u8> for OwnerTrust {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> Result<Self> {
        use OwnerTrustLevel::*;
        let level = match v & OWNERTRUST_MASK {
            OWNERTRUST_UNKNOWN   => Ok(Unknown),
            OWNERTRUST_UNDEFINED => Ok(Undefined),
            OWNERTRUST_NEVER     => Ok(Never),
            OWNERTRUST_MARGINAL  => Ok(Marginal),
            OWNERTRUST_FULLY     => Ok(Fully),
            OWNERTRUST_ULTIMATE  => Ok(Ultimate),
            n => Err(anyhow::anyhow!("Bad ownertrust value {}", n)),
        }?;
        Ok(OwnerTrust {
            level,
            disabled: v & OWNERTRUST_FLAG_DISABLED > 0,
        })
    }
}

impl From<OwnerTrust> for u8 {
    fn from(ot: OwnerTrust) -> u8 {
        use OwnerTrustLevel::*;
        let level = match ot.level {
            Unknown =>   OWNERTRUST_UNKNOWN,
            Undefined => OWNERTRUST_UNDEFINED,
            Never =>     OWNERTRUST_NEVER,
            Marginal =>  OWNERTRUST_MARGINAL,
            Fully =>     OWNERTRUST_FULLY,
            Ultimate =>  OWNERTRUST_ULTIMATE,
        };

        level | if ot.disabled { OWNERTRUST_FLAG_DISABLED } else { 0 }
    }
}

pub enum Compliance {
    OpenPGP,
    RFC2440,
    RFC4880,
    RFC4880bis,
    PGP6,
    PGP7,
    PGP8,
    GnuPG,
    DeVs,
}

impl Default for Compliance {
    fn default() -> Self {
        Compliance::GnuPG
    }
}

impl std::str::FromStr for Compliance {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "gnupg" => Ok(Compliance::GnuPG),
            "openpgp" => Ok(Compliance::OpenPGP),
            "rfc4880bis" => Ok(Compliance::RFC4880bis),
            "rfc4880" => Ok(Compliance::RFC4880),
            "rfc2440" => Ok(Compliance::RFC2440),
            "pgp6" => Ok(Compliance::PGP6),
            "pgp7" => Ok(Compliance::PGP7),
            "pgp8" => Ok(Compliance::PGP8),
            "de-vs" => Ok(Compliance::DeVs),
            _ => Err(anyhow::anyhow!("Invalid value for option '--compliance': \
                                      {:?}", s)),
        }
    }
}

impl Compliance {
    /// Returns a flag usable for the status-fd interface.
    pub fn to_flag(&self) -> Option<usize> {
        match self {
            Compliance::GnuPG => Some(8),
            Compliance::DeVs => Some(23),
            _ => None,
        }
    }
}
