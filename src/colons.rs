//! Machine-readable --with-colons interface, and human-readable counterpart.
//!
//! This models information that GnuPG emits on commands supporting
//! --with-colons, but on top of that also handles human-readable
//! output from the same set of data.

use std::{
    cell::RefCell,
    fmt::{self, Write},
    io,
    sync::Mutex,
    time::SystemTime,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    KeyID,
    crypto::hash::Digest,
    packet::UserID,
    types::*,
};
use sequoia_ipc as ipc;
use ipc::Keygrip;

use crate::{
    babel,
    trust::*,
};

pub struct Fd(Mutex<RefCell<Box<dyn io::Write + Send + Sync>>>);

impl<S: io::Write + Send + Sync + 'static> From<S> for Fd {
    fn from(s: S) -> Fd {
        Fd(Mutex::new(RefCell::new(Box::new(s))))
    }
}

impl Fd {
    #[allow(dead_code)]
    pub fn emit(&self, record: Record, mr: bool) -> Result<()> {
        record.emit(&mut *self.0.lock().expect("not poisoned").borrow_mut(), mr)
    }
}

#[allow(dead_code)]
pub enum Record {
    PublicKey {
        validity: Validity,
        key_length: usize,
        pk_algo: PublicKeyAlgorithm,
        keyid: KeyID,
        creation_date: SystemTime,
        expiration_date: Option<SystemTime>,
        ownertrust: OwnerTrust,
        primary_key_flags: KeyFlags,
        sum_key_flags: KeyFlags,
        curve: Option<Curve>,
    },
    Subkey {
        validity: Validity,
        key_length: usize,
        pk_algo: PublicKeyAlgorithm,
        keyid: KeyID,
        creation_date: SystemTime,
        expiration_date: Option<SystemTime>,
        key_flags: KeyFlags,
        curve: Option<Curve>,
    },
    Fingerprint(Fingerprint),
    Keygrip(Keygrip),
    UserID {
        validity: Validity,
        creation_date: SystemTime,
        expiration_date: Option<SystemTime>,
        userid: UserID,
    },
}

impl Record {
    /// Emits the record to `w`, `mr` indicates whether it should be
    /// machine-readable.
    pub fn emit(&self, w: &mut impl io::Write, mr: bool) -> Result<()> {
        use Record::*;
        match self {
            PublicKey {
                validity,
                key_length,
                pk_algo,
                keyid,
                creation_date,
                expiration_date,
                ownertrust,
                primary_key_flags,
                sum_key_flags,
                curve,
            } => {
                let creation_date =
                    chrono::DateTime::<chrono::Utc>::from(*creation_date);

                let expiration_date = expiration_date.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                if mr {
                    writeln!(w,
                             "pub:{}:{}:{}:{:X}:{}:{}::{}:::{}{}:::::{}:::0:",
                             validity,
                             key_length,
                             u8::from(*pk_algo),
                             keyid,
                             creation_date.format("%s"),
                             expiration_date.map(|t| t.format("%s").to_string())
                             .unwrap_or_else(|| "".into()),
                             ownertrust,
                             babel::Fish(primary_key_flags),
                             babel::Fish(sum_key_flags).to_string().to_uppercase(),
                             curve.as_ref().map(|c| babel::Fish(c).to_string())
                             .unwrap_or_default(),
                    )?;
                } else {
                    writeln!(w,
                             "pub   {} {} [{}]{}",
                             babel::Fish((*pk_algo, *key_length, curve)),
                             creation_date.format("%Y-%m-%d"),
                             babel::Fish(primary_key_flags).to_string().to_uppercase(),
                             expiration_date.map(|t| format!(" expires: {}", // XXX: expired
                                                             t.format("%s")))
                             .unwrap_or_else(|| "".into())
                    )?;
                }
            },

            Subkey {
                validity,
                key_length,
                pk_algo,
                keyid,
                creation_date,
                expiration_date,
                key_flags,
                curve,
            } => {
                let creation_date =
                    chrono::DateTime::<chrono::Utc>::from(*creation_date);

                let expiration_date = expiration_date.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                if mr {
                    writeln!(w, "sub:{}:{}:{}:{:X}:{}:{}:::::{}:::::{}::",
                             validity,
                             key_length,
                             u8::from(*pk_algo),
                             keyid,
                             creation_date.format("%s"),
                             expiration_date.map(|t| t.format("%s").to_string())
                             .unwrap_or_else(|| "".into()),
                             babel::Fish(key_flags),
                             curve.as_ref().map(|c| babel::Fish(c).to_string())
                             .unwrap_or_default(),
                    )?;
                } else {
                    writeln!(w,
                             "sub   {} {} [{}]",
                             babel::Fish((*pk_algo, *key_length, curve)),
                             creation_date.format("%Y-%m-%d"),
                             babel::Fish(key_flags).to_string().to_uppercase(),
                    )?;
                }
            },

            Fingerprint(fp) => {
                if mr {
                    writeln!(w, "fpr:::::::::{:X}:", fp)?;
                } else {
                    writeln!(w, "      {:X}", fp)?;
                }
            },

            Keygrip(kg) => {
                if mr {
                    writeln!(w, "grp:::::::::{}:", kg)?;
                } else {
                    writeln!(w, "      Keygrip = {}", kg)?;
                }
            },

            UserID {
                validity,
                creation_date,
                expiration_date,
                userid,
            } => {
                let creation_date =
                    chrono::DateTime::<chrono::Utc>::from(*creation_date);

                let expiration_date = expiration_date.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                let mut uidhash = HashAlgorithm::RipeMD.context()?;
                uidhash.update(userid.value());
                let uidhash = uidhash.into_digest()?;

                if mr {
                    write!(w, "uid:{}::::{}:{}:{}::",
                           validity,
                           creation_date.format("%s"),
                           expiration_date.map(|t| t.format("%s").to_string())
                           .unwrap_or_else(|| "".into()),
                           openpgp::fmt::hex::encode(&uidhash),
                    )?;
                    e(w, userid.value())?;
                    writeln!(w, "::::::::::0:")?;
                } else {
                    writeln!(w, "uid           {} {}",
                             BoxedValidity(*validity),
                             String::from_utf8_lossy(userid.value()))?;
                }
            },
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
            b':' => sink.write_all(b"\\x3a")?,
            c if *c < 20 || ! c.is_ascii() =>
                write!(sink, "\\x{:02x}", *c)?,
            c => sink.write_all(&[*c])?,
        }
    }

    Ok(())
}

/// Boxes validity labels for the human-readable key list output.
struct BoxedValidity(Validity);

impl fmt::Display for BoxedValidity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Validity::*;
        match self.0 {
            Unknown =>  f.write_str("[ unknown]"),
            Ultimate => f.write_str("[ultimate]"),
        }
    }
}
