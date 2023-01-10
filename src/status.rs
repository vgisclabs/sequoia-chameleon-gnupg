//! Status-fd protocol and human-readable messaging.

use std::{
    cell::RefCell,
    convert::TryFrom,
    fmt,
    io,
    sync::Mutex,
    time::SystemTime,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    KeyHandle,
    KeyID,
    crypto::SessionKey,
    fmt::hex,
    packet::UserID,
    types::*,
};

use crate::{
    common::{
        Compliance,
        OwnerTrust,
        Query,
        TrustModel,
    },
};

/// Match GnuPG's behavior more strictly.
///
/// Strictly match GnuPG's output even if the protocol allows other
/// output as well (e.g. GnuPG may only emit key ids whereas
/// doc/DETAILS says fingerprints are also allowed.
///
/// Annoyingly, test suites don't understand how key handles alias, so
/// aligning more closely with GnuPG avoids a lot of false positives.
const STRICT_OUTPUT: bool = true;

pub struct Fd(Mutex<RefCell<Box<dyn io::Write + Send + Sync>>>);

impl<S: io::Write + Send + Sync + 'static> From<S> for Fd {
    fn from(s: S) -> Fd {
        Fd(Mutex::new(RefCell::new(Box::new(s))))
    }
}

impl Fd {
    #[allow(dead_code)]
    pub fn emit(&self, status: Status<'_>) -> Result<()> {
        crate::with_invocation_log(|sink| status.emit(sink));
        status.emit(&mut *self.0.lock().expect("not poisoned").borrow_mut())
    }
}

#[allow(dead_code)]
pub enum Status<'a> {
    // Signature related.

    NewSig {
        signers_uid: Option<Box<[u8]>>,
    },
    GoodSig {
        issuer: KeyHandle,
        primary_uid: Box<[u8]>,
    },
    ExpSig {
        issuer: KeyHandle,
        primary_uid: Box<[u8]>,
    },
    ExpKeySig {
        issuer: KeyHandle,
        primary_uid: Box<[u8]>,
    },
    RevKeySig {
        issuer: KeyHandle,
        primary_uid: Box<[u8]>,
    },
    BadSig {
        issuer: KeyHandle,
        primary_uid: Box<[u8]>,
    },
    ErrSig {
        issuer: KeyID,
        pk_algo: PublicKeyAlgorithm,
        hash_algo: HashAlgorithm,
        sig_class: SignatureType,
        creation_time: SystemTime,
        rc: ErrSigStatus,
        issuer_fingerprint: Option<Fingerprint>,
    },
    ValidSig {
        issuer: Fingerprint,
        creation_time: SystemTime,
        expire_time: Option<SystemTime>,
        version: u8,
        pk_algo: PublicKeyAlgorithm,
        hash_algo: HashAlgorithm,
        sig_class: SignatureType,
        primary: Fingerprint,
    },
    SigId {
        id: String,
        creation_time: SystemTime,
    },

    // Encryption-related.
    EncTo {
        keyid: KeyID,
        pk_algo: Option<PublicKeyAlgorithm>,
        pk_len: Option<usize>,
    },
    BeginDecryption,
    EndDecryption,
    DecryptionKey {
        fp: Fingerprint,
        cert_fp: Fingerprint,
        owner_trust: OwnerTrust,
    },
    DecryptionInfo {
        use_mdc: bool,
        sym_algo: SymmetricAlgorithm,
        aead_algo: Option<AEADAlgorithm>,
    },
    DecryptionFailed,
    DecryptionOkay,
    GoodMDC,
    SessionKey {
        algo: SymmetricAlgorithm,
        sk: SessionKey,
    },

    BeginEncryption {
        mdc_method: MDCMethod,
        cipher: SymmetricAlgorithm,
    },
    EndEncryption,

    BeginSigning(HashAlgorithm),
    SigCreated {
        typ: SigType,
        pk_algo: PublicKeyAlgorithm,
        hash_algo: HashAlgorithm,
        class: SignatureType,
        timestamp: openpgp::types::Timestamp,
        fingerprint: Fingerprint,
    },

    // Miscellaneous.
    NotationName {
        name: String,
    },

    NotationFlags {
        critical: bool,
        human_readable: bool,
    },

    NotationData {
        data: Box<[u8]>,
    },

    EncryptionComplianceMode(Compliance), // XXX: In GnuPG, it is a Vec<_>
    DecryptionComplianceMode(Compliance), // XXX: In GnuPG, it is a Vec<_>

    Plaintext {
        format: DataFormat,
        timestamp: Option<SystemTime>,
        filename: Option<Vec<u8>>,
    },

    PlaintextLength(u32),

    // Key related.

    InvalidRecipient {
        reason: InvalidKeyReason,
        query: &'a Query<'a>,
    },

    InvalidSigner {
        reason: InvalidKeyReason,
        query: &'a Query<'a>,
    },

    KeyConsidered {
        fingerprint: Fingerprint,
        not_selected: bool,
        all_expired_or_revoked: bool,
    },

    KeyExpired {
        at: SystemTime,
    },

    NoPubkey {
        issuer: KeyID,
    },

    NoSeckey {
        issuer: KeyID,
    },

    TrustUndefined,
    TrustNever,
    TrustMarginal {
        model: TrustModel,
    },
    TrustFully {
        model: TrustModel,
    },
    TrustUltimate {
        model: TrustModel,
    },

    UserIdHint {
        keyid: KeyID,
        userid: Option<&'a UserID>,
    },

    Imported {
        keyid: KeyID,
        username: String,
    },
    ImportOk {
        flags: ImportOkFlags,
        fingerprint: Option<Fingerprint>,
    },
    ImportProblem {
        reason: ImportProblem,
        fingerprint: Option<Fingerprint>,
    },
    ImportRes(ImportResult),

    Exported {
        fingerprint: Fingerprint,
    },
    ExportRes(ExportResult),

    PinentryLaunched(String),

    NoData(NoDataReason),

    Failure {
        location: &'a str,
        error: crate::error_codes::Error,
    },
}

impl Status<'_> {
    #[allow(dead_code)]
    fn emit(&self, w: &mut (impl io::Write + ?Sized)) -> Result<()> {
        w.write_all(b"[GNUPG:] ")?;

        use Status::*;
        match self {
            NewSig {
                signers_uid: None,
            } => writeln!(w, "NEWSIG")?,
            NewSig {
                signers_uid: Some(uid),
            } => {
                write!(w, "NEWSIG ")?;
                e(w, uid)?;
                writeln!(w)?;
            },

            GoodSig {
                issuer,
                primary_uid,
            } => {
                if STRICT_OUTPUT {
                    write!(w, "GOODSIG {:X} ", KeyID::from(issuer))?;
                } else {
                    write!(w, "GOODSIG {:X} ", issuer)?;
                }
                e(w, primary_uid)?;
                writeln!(w)?;
            },

            ExpSig {
                issuer,
                primary_uid,
            } => {
                if STRICT_OUTPUT {
                    write!(w, "EXPSIG {:X} ", KeyID::from(issuer))?;
                } else {
                    write!(w, "EXPSIG {:X} ", issuer)?;
                }
                e(w, primary_uid)?;
                writeln!(w)?;
            },

            ExpKeySig {
                issuer,
                primary_uid,
            } => {
                if STRICT_OUTPUT {
                    write!(w, "EXPKEYSIG {:X} ", KeyID::from(issuer))?;
                } else {
                    write!(w, "EXPKEYSIG {:X} ", issuer)?;
                }
                e(w, primary_uid)?;
                writeln!(w)?;
            },

            RevKeySig {
                issuer,
                primary_uid,
            } => {
                if STRICT_OUTPUT {
                    write!(w, "REVKEYSIG {:X} ", KeyID::from(issuer))?;
                } else {
                    write!(w, "REVKEYSIG {:X} ", issuer)?;
                }
                e(w, primary_uid)?;
                writeln!(w)?;
            },

            BadSig {
                issuer,
                primary_uid,
            } => {
                if STRICT_OUTPUT {
                    write!(w, "BADSIG {:X} ", KeyID::from(issuer))?;
                } else {
                    write!(w, "BADSIG {:X} ", issuer)?;
                }
                e(w, primary_uid)?;
                writeln!(w)?;
            },

            ErrSig {
                issuer,
                creation_time,
                pk_algo,
                hash_algo,
                sig_class,
                rc,
                issuer_fingerprint,
            } => {
                let t =
                    chrono::DateTime::<chrono::Utc>::from(*creation_time);
                write!(w, "ERRSIG {:X} {} {} {:02x} {} {}",
                       issuer,
                       u8::from(*pk_algo),
                       u8::from(*hash_algo),
                       u8::from(*sig_class),
                       t.format("%s"),
                       rc)?;
                if let Some(fp) = issuer_fingerprint {
                    write!(w, " {:X}", fp)?;
                }
                writeln!(w)?;
            },

            ValidSig {
                issuer,
                creation_time,
                expire_time,
                version,
                pk_algo,
                hash_algo,
                sig_class,
                primary,
            } => {
                let t =
                    chrono::DateTime::<chrono::Utc>::from(*creation_time);
                let e = expire_time
                    .map(|t| chrono::DateTime::<chrono::Utc>::from(t));
                writeln!(w, "VALIDSIG {:X} {} {} {} {} {} {} {} {:02x} {:X}",
                         issuer,
                         t.format("%Y-%m-%d"),
                         t.format("%s"),
                         e.map(|e| e.format("%s").to_string())
                         .unwrap_or_else(|| "0".into()),
                         version,
                         0, // Reserved.
                         u8::from(*pk_algo),
                         u8::from(*hash_algo),
                         u8::from(*sig_class),
                         primary,
                )?;
            },

            SigId {
                id,
                creation_time,
            } => {
                let t = chrono::DateTime::<chrono::Utc>::from(*creation_time);
                writeln!(w, "SIG_ID {} {} {}",
                         id,
                         t.format("%Y-%m-%d"),
                         t.format("%s"))?;
            },

            EncTo {
                keyid,
                pk_algo,
                pk_len,
            } => {
                writeln!(w, "ENC_TO {:X} {} {}",
                         keyid,
                         pk_algo.map(|a| u8::from(a)).unwrap_or(0),
                         pk_len.unwrap_or(0))?;
            },

            BeginDecryption => writeln!(w, "BEGIN_DECRYPTION")?,
            EndDecryption => writeln!(w, "END_DECRYPTION")?,

            DecryptionKey {
                fp,
                cert_fp,
                owner_trust,
            } => {
                writeln!(w, "DECRYPTION_KEY {:X} {:X} {:#}",
                         fp,
                         cert_fp,
                         owner_trust)?;
            },

            DecryptionInfo {
                use_mdc,
                sym_algo,
                aead_algo,
            } => {
                writeln!(w, "DECRYPTION_INFO {} {} {}",
                         if *use_mdc {
                             u8::from(HashAlgorithm::SHA1)
                         } else {
                             0
                         },
                         u8::from(*sym_algo),
                         aead_algo.map(|a| u8::from(a)).unwrap_or(0))?;
            },
            DecryptionFailed => writeln!(w, "DECRYPTION_FAILED")?,
            DecryptionOkay => writeln!(w, "DECRYPTION_OKAY")?,
            GoodMDC => writeln!(w, "GOODMDC")?,
            SessionKey {
                algo,
                sk,
            } => {
                writeln!(w, "SESSION_KEY {}:{}",
                         u8::from(*algo),
                         hex::encode(sk))?;
            },

            BeginEncryption {
                mdc_method,
                cipher,
            } => {
                writeln!(w, "BEGIN_ENCRYPTION {} {}",
                         mdc_method, u8::from(*cipher))?;
            },
            EndEncryption => writeln!(w, "END_ENCRYPTION")?,

            BeginSigning(hash) =>
                writeln!(w, "BEGIN_SIGNING H{}", u8::from(*hash))?,
            SigCreated {
                typ,
                pk_algo,
                hash_algo,
                class,
                timestamp,
                fingerprint,
            } => {
                // XXX: Curiously, GnuPG emits two hex digits for the
                // signature class, as documented in doc/DETAILS.  Not
                // sure why they went with hex here, and indeed GPGME
                // seems to mis-parse (e.g. 00 (== binary) which
                // strtol will interpret as octal).
                writeln!(w, "SIG_CREATED {} {} {} {:02X} {} {:X}",
                         typ,
                         u8::from(*pk_algo),
                         u8::from(*hash_algo),
                         u8::from(*class),
                         u32::from(*timestamp),
                         fingerprint)?;
            },

            NotationName {
                name,
            } => {
                writeln!(w, "NOTATION_NAME {}", name)?;
            },

            NotationFlags {
                critical,
                human_readable,
            } => {
                writeln!(w, "NOTATION_FLAGS {} {}",
                         if *critical { 1 } else { 0 },
                         if *human_readable { 1 } else { 0 },
                )?;
            },

            NotationData {
                data,
            } => {
                write!(w, "NOTATION_DATA ")?;
                e(w, data)?;
                writeln!(w)?;
            },

            Plaintext {
                format,
                timestamp,
                filename,
            } => {
                write!(w, "PLAINTEXT {:x} {}",
                       u8::from(*format),
                       timestamp.as_ref().and_then(|t| Timestamp::try_from(*t).ok())
                       .map(|t| u32::from(t)).unwrap_or(0))?;
                if let Some(filename) = filename {
                    write!(w, " ")?;
                    e(w, filename)?;
                }
                writeln!(w)?;
            },

            PlaintextLength(l) => writeln!(w, "PLAINTEXT_LENGTH {}", l)?,

            EncryptionComplianceMode(mode) => {
                if let Some(flag) = mode.to_flag() {
                    writeln!(w, "ENCRYPTION_COMPLIANCE_MODE {}", flag)?;
                }
            },

            DecryptionComplianceMode(mode) => {
                if let Some(flag) = mode.to_flag() {
                    writeln!(w, "DECRYPTION_COMPLIANCE_MODE {}", flag)?;
                }
            },

            InvalidRecipient {
                reason,
                query,
            } => writeln!(w, "INV_RECP {} {}", u8::from(*reason), query)?,

            InvalidSigner {
                reason,
                query,
            } => writeln!(w, "INV_SGNR {} {}", u8::from(*reason), query)?,

            KeyConsidered {
                fingerprint,
                not_selected,
                all_expired_or_revoked,
            } => {
                writeln!(w, "KEY_CONSIDERED {:X} {}",
                         fingerprint,
                         0
                         | if *not_selected { 1 } else { 0 }
                         | if *all_expired_or_revoked { 2 } else { 0 }
                )?;
            },

            KeyExpired {
                at,
            } => {
                let t = chrono::DateTime::<chrono::Utc>::from(*at);
                writeln!(w, "KEYEXPIRED {}", t.format("%s"))?;
            },

            NoPubkey {
                issuer,
            } => {
                writeln!(w, "NO_PUBKEY {:X}", issuer)?;
            },

            NoSeckey {
                issuer,
            } => {
                writeln!(w, "NO_SECKEY {:X}", issuer)?;
            },

            TrustUndefined => {
                writeln!(w, "TRUST_UNDEFINED")?;
            },
            TrustNever => {
                writeln!(w, "TRUST_NEVER")?;
            },
            TrustMarginal { model } => {
                writeln!(w, "TRUST_MARGINAL 0 {}", model)?;
            },
            TrustFully { model } => {
                writeln!(w, "TRUST_FULLY 0 {}", model)?;
            },
            TrustUltimate { model } => {
                writeln!(w, "TRUST_ULTIMATE 0 {}", model)?;
            },

            UserIdHint {
                keyid,
                userid,
            } => {
                writeln!(w, "USERID_HINT {:X} {}", keyid,
                         userid
                         .map(|u| String::from_utf8_lossy(u.value()).to_string())
                         .unwrap_or_else(|| "[?]".into()))?;
            },

            Imported {
                keyid,
                username,
            } => {
                writeln!(w, "IMPORTED {:X} {}", keyid, username)?;
            },

            ImportOk {
                flags,
                fingerprint,
            } => {
                write!(w, "IMPORT_OK {}", u8::from(*flags))?;
                if let Some(fp) = fingerprint {
                    write!(w, " {}", fp)?;
                }
                writeln!(w)?;
            },

            ImportProblem {
                reason,
                fingerprint,
            } => {
                write!(w, "IMPORT_PROBLEM {}", u8::from(*reason))?;
                if let Some(fp) = fingerprint {
                    write!(w, " {}", fp)?;
                }
                writeln!(w)?;
            },

            ImportRes(ImportResult {
                count,
                imported,
                unchanged,
                n_uids,
                n_subk,
                n_sigs,
                n_revoc,
                sec_read,
                sec_imported,
                sec_dups,
                skipped_new_keys,
                not_imported,
                skipped_v3_keys,
            }) => {
                writeln!(w, "IMPORT_RES {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
                         count,
                         0, // no_user_id
                         imported,
                         0, // always 0
                         unchanged,
                         n_uids,
                         n_subk,
                         n_sigs,
                         n_revoc,
                         sec_read,
                         sec_imported,
                         sec_dups,
                         skipped_new_keys,
                         not_imported,
                         skipped_v3_keys,
                )?;
            },

            Exported {
                fingerprint,
            } => {
                writeln!(w, "EXPORTED {:X}", fingerprint)?;
            },

            ExportRes(ExportResult {
                count,
                secret_count,
                exported,
            }) => {
                writeln!(w, "EXPORT_RES {} {} {}",
                         count,
                         secret_count,
                         exported,
                )?;
            },

            PinentryLaunched(i) => writeln!(w, "PINENTRY_LAUNCHED {}", i)?,

            NoData(reason) => {
                use NoDataReason::*;
                writeln!(w, "NODATA {}",
                         match reason {
                             NoArmoredData => 1,
                             ExpectedPacket => 2,
                             InvalidPacket => 3,
                             ExpectedSignature => 4,
                         })?;
            },

            Failure {
                location,
                error,
            } => {
                writeln!(w, "FAILURE {} {}", location, *error as isize)?;
            },
        }

        Ok(())
    }
}

/// Escapes the given byte sequence.
fn e<W: io::Write + ?Sized>(sink: &mut W, s: impl AsRef<[u8]>) -> Result<()> {
    let s = s.as_ref();

    for c in s {
        match c {
            b'%' => sink.write_all(b"%25")?,
            c if *c < 0x20 || *c == 127 =>
                write!(sink, "%{:02X}", *c)?,
            c => sink.write_all(&[*c])?,
        }
    }

    Ok(())
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum ErrSigStatus {
    UnsupportedAlgorithm,
    MissingKey,
    BadSignatureClass,
    UnexpectedRevocation,
    WeakHash,
    BadPublicKey,
    WrongKeyUsage,
}

impl fmt::Display for ErrSigStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ErrSigStatus::*;
        match self {
            UnsupportedAlgorithm => f.write_str("4"),
            WeakHash => f.write_str("5"),
            BadPublicKey => f.write_str("6"),
            MissingKey => f.write_str("9"),
            BadSignatureClass => f.write_str("32"),
            UnexpectedRevocation => f.write_str("52"),
            WrongKeyUsage => f.write_str("125"),
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct ImportResult {
    pub count: usize,
    pub imported: usize,
    pub unchanged: usize,
    pub n_uids: usize,
    pub n_subk: usize,
    pub n_sigs: usize,
    pub n_revoc: usize,
    pub sec_read: usize,
    pub sec_imported: usize,
    pub sec_dups: usize,
    pub skipped_new_keys: usize,
    pub not_imported: usize,
    pub skipped_v3_keys: usize,
}

impl ImportResult {
    pub fn changed_since(&self, base: ImportResult) -> ImportResult {
        ImportResult {
            count: self.count - base.count,
            imported: self.imported - base.imported,
            unchanged: self.unchanged - base.unchanged,
            n_uids: self.n_uids - base.n_uids,
            n_subk: self.n_subk - base.n_subk,
            n_sigs: self.n_sigs - base.n_sigs,
            n_revoc: self.n_revoc - base.n_revoc,
            sec_read: self.sec_read - base.sec_read,
            sec_imported: self.sec_imported - base.sec_imported,
            sec_dups: self.sec_dups - base.sec_dups,
            skipped_new_keys: self.skipped_new_keys - base.skipped_new_keys,
            not_imported: self.not_imported - base.not_imported,
            skipped_v3_keys: self.skipped_v3_keys - base.skipped_v3_keys,
        }
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct ImportOkFlags(u8);
pub const IMPORT_OK_NOT_CHANGED: ImportOkFlags = ImportOkFlags(0);
pub const IMPORT_OK_NEW_KEY: ImportOkFlags = ImportOkFlags(1);
pub const IMPORT_OK_NEW_UIDS: ImportOkFlags = ImportOkFlags(2);
pub const IMPORT_OK_NEW_SIGS: ImportOkFlags = ImportOkFlags(4);
pub const IMPORT_OK_NEW_SUBKEYS: ImportOkFlags = ImportOkFlags(8);
pub const IMPORT_OK_HAS_SECRET: ImportOkFlags = ImportOkFlags(16);

impl ImportOkFlags {
    pub fn set(&mut self, flag: ImportOkFlags) {
        self.0 |= flag.0;
    }

    pub fn is_set(&self, flag: ImportOkFlags) -> bool {
        self.0 & flag.0 > 0
    }
}

impl From<ImportOkFlags> for u8 {
    fn from(v: ImportOkFlags) -> u8 {
        v.0
    }
}

#[derive(Copy, Clone, Debug)]
pub enum ImportProblem {
    Unspecified,
    InvalidCert,
    IssuerCertMissing,
    CertChainTooLong,
    ErrorStoringCert,
}

impl From<ImportProblem> for u8 {
    fn from(v: ImportProblem) -> u8 {
        use ImportProblem::*;
        match v {
            Unspecified => 0,
            InvalidCert => 1,
            IssuerCertMissing => 2,
            CertChainTooLong => 3,
            ErrorStoringCert => 4,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct ExportResult {
    pub count: usize,
    pub secret_count: usize,
    pub exported: usize,
}

#[derive(Copy, Clone, Debug)]
pub enum SigType {
    Standard,
    Detached,
    Cleartext,
}

impl fmt::Display for SigType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SigType::*;
        match self {
            Detached => f.write_str("D"),
            Standard => f.write_str("S"),
            Cleartext => f.write_str("C"),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum MDCMethod {
    SEIPDv1,
}

impl fmt::Display for MDCMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MDCMethod::*;
        match self {
            SEIPDv1 => f.write_str("2"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum NoDataReason {
    NoArmoredData,
    ExpectedPacket,
    InvalidPacket,
    ExpectedSignature,
}

/// Reasons why a key is unsuitable.
///
/// Used in [`Status::InvalidRecipient`] and
/// [`Status::InvalidSigner`].
#[derive(Copy, Clone, Debug)]
pub enum InvalidKeyReason {
    /// No specific reason given.
    Unspecified,
    /// Not Found.
    NotFound,
    /// Ambigious specification.
    AmbigiousQuery,
    /// Wrong key usage.
    WrongKeyUseage,
    /// Key revoked.
    KeyRevoked,
    /// Key expired.
    KeyExpired,
    /// No CRL known.
    NoCRLKnown,
    /// CRL too old.
    CRLTooOld,
    /// Policy mismatch.
    PolicyMismatch,
    /// Not a secret key.
    NotASecretKey,
    /// Key not trusted.
    NotTrusted,
    /// Missing certificate.
    MissingCertificate,
    /// Missing issuer certificate.
    MissingIssuerCertificate,
    /// Key disabled.
    KeyDisabled,
    /// Syntax error in specification.
    SyntaxError,
}

impl From<InvalidKeyReason> for u8 {
    fn from(v: InvalidKeyReason) -> u8 {
        use InvalidKeyReason::*;
        match v {
            Unspecified => 0,
            NotFound => 1,
            AmbigiousQuery => 2,
            WrongKeyUseage => 3,
            KeyRevoked => 4,
            KeyExpired => 5,
            NoCRLKnown => 6,
            CRLTooOld => 7,
            PolicyMismatch => 8,
            NotASecretKey => 9,
            NotTrusted => 10,
            MissingCertificate => 11,
            MissingIssuerCertificate => 12,
            KeyDisabled => 13,
            SyntaxError => 14,
        }
    }
}
