//! Status-fd protocol and human-readable messaging.

use std::{
    cell::RefCell,
    convert::TryFrom,
    fmt::{self, Write},
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
    types::*,
};

use crate::{
    common::{TrustModel, OwnerTrust},
};

/// Match GnuPG's behavior more strictly.
///
/// Strictly match GnuPG's output even if the protocol allows other
/// output as well (e.g. GnuPG may only emit key ids whereas
/// doc/DETAILS says fingerprints are also allowed.
const STRICT_OUTPUT: bool = false;

pub struct Fd(Mutex<RefCell<Box<dyn io::Write + Send + Sync>>>);

impl<S: io::Write + Send + Sync + 'static> From<S> for Fd {
    fn from(s: S) -> Fd {
        Fd(Mutex::new(RefCell::new(Box::new(s))))
    }
}

impl Fd {
    #[allow(dead_code)]
    pub fn emit(&self, status: Status) -> Result<()> {
        status.emit(&mut *self.0.lock().expect("not poisoned").borrow_mut())
    }
}

#[allow(dead_code)]
pub enum Status {
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

    Plaintext {
        format: DataFormat,
        timestamp: Option<SystemTime>,
        filename: Option<Vec<u8>>,
    },

    PlaintextLength(u32),

    // Key related.

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

    PinentryLaunched(String),
}

impl Status {
    #[allow(dead_code)]
    fn emit(&self, w: &mut impl io::Write) -> Result<()> {
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
                write!(w, "EXPSIG {:X} ", issuer)?;
                e(w, primary_uid)?;
                writeln!(w)?;
            },

            ExpKeySig {
                issuer,
                primary_uid,
            } => {
                write!(w, "EXPKEYSIG {:X} ", issuer)?;
                e(w, primary_uid)?;
                writeln!(w)?;
            },

            RevKeySig {
                issuer,
                primary_uid,
            } => {
                write!(w, "REVKEYSIG {:X} ", issuer)?;
                e(w, primary_uid)?;
                writeln!(w)?;
            },

            BadSig {
                issuer,
                primary_uid,
            } => {
                write!(w, "BADSIG {:X} ", issuer)?;
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
                writeln!(w, "DECRYPTION_KEY {:X} {:X} {}",
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

            PinentryLaunched(i) => writeln!(w, "PINENTRY_LAUNCHED {}", i)?,
        }

        Ok(())
    }
}

/// Escapes the given string.
#[allow(dead_code)]
fn e_str(s: impl AsRef<str>) -> String {
    let s = s.as_ref();
    let mut o = String::with_capacity(s.len());

    for c in s.chars() {
        match c {
            '%' => o.push_str("%25"),
            c if c.is_ascii() && (c as u8) < 20 =>
                write!(o, "%{:02X}", c as u8)
                .expect("write to string is infallible"),
            c => o.push(c),
        }
    }

    o
}

/// Escapes the given byte sequence.
fn e(sink: &mut dyn io::Write, s: impl AsRef<[u8]>) -> Result<()> {
    let s = s.as_ref();

    for c in s {
        match c {
            b'%' => sink.write_all(b"%25")?,
            c if c.is_ascii() && *c < 20 =>
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
