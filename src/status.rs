//! Status-fd protocol and human-readable messaging.

use std::{
    cell::RefCell,
    fmt::Write,
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
    types::*,
};

pub struct Fd(Mutex<RefCell<Box<dyn io::Write + Send + Sync>>>);

impl<S: io::Write + Send + Sync + 'static> From<S> for Fd {
    fn from(s: S) -> Fd {
        Fd(Mutex::new(RefCell::new(Box::new(s))))
    }
}

impl Fd {
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

    // Key related.

    KeyConsidered {
        fingerprint: Fingerprint,
        not_selected: bool,
        all_expired_or_revoked: bool,
    },
}

impl Status {
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
                writeln!(w, "VALIDSIG {:X} {} {} {} {} {} {} {} {:02X} {:X}",
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
            _ => unimplemented!(),
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
pub enum ErrSigStatus {
    UnsupportedAlgorithm,
    MissingKey,
}