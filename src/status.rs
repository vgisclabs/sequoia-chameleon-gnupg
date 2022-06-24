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
    BeginDecryption,
    EndDecryption,
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
                write!(w, "GOODSIG {:X} ", issuer)?;
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

            BeginDecryption => writeln!(w, "BEGIN_DECRYPTION")?,
            EndDecryption => writeln!(w, "END_DECRYPTION")?,
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
