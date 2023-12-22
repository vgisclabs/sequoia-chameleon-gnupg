//! Machine-readable --with-colons interface, and human-readable counterpart.
//!
//! This models information that GnuPG emits on commands supporting
//! --with-colons, but on top of that also handles human-readable
//! output from the same set of data.

use std::{
    fmt::{self, Write},
    io,
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
    common::Compliance,
    trust::*,
};

#[allow(dead_code)]
pub enum Record {
    Key {
        have_secret: bool,
        validity: Validity,
        key_length: usize,
        pk_algo: PublicKeyAlgorithm,
        keyid: KeyID,
        creation_date: SystemTime,
        expiration_date: Option<SystemTime>,
        revocation_date: Option<SystemTime>,
        ownertrust: OwnerTrust,
        primary_key_flags: KeyFlags,
        sum_key_flags: KeyFlags,
        token_sn: Option<TokenSN>,
        curve: Option<Curve>,
        compliance: Vec<Compliance>,
    },
    Subkey {
        have_secret: bool,
        validity: Validity,
        key_length: usize,
        pk_algo: PublicKeyAlgorithm,
        keyid: KeyID,
        creation_date: SystemTime,
        expiration_date: Option<SystemTime>,
        revocation_date: Option<SystemTime>,
        key_flags: KeyFlags,
        token_sn: Option<TokenSN>,
        curve: Option<Curve>,
        compliance: Vec<Compliance>,
    },
    Fingerprint(Fingerprint),
    Keygrip(Keygrip),
    UserID {
        validity: Option<Validity>,
        creation_date: SystemTime,
        expiration_date: Option<SystemTime>,
        userid: UserID,
    },

    /// rvk: Revocation key
    RevocationKey {
        pk_algo: PublicKeyAlgorithm,
        revoker: Fingerprint,
        class: u8,
        sensitive: bool,
    },

    TrustDBInformation {
        old: bool,
        changed_model: bool,
        model: TrustModel,
        creation_time: SystemTime,
        expiration_time: Option<SystemTime>,
        marginals_needed: u8,
        completes_needed: u8,
        max_cert_depth: u8,
    },
}

impl Record {
    /// Emits the record to `w`, `mr` indicates whether it should be
    /// machine-readable.
    pub fn emit(&self, config: &crate::Config,
                w: &mut (impl io::Write + ?Sized))
                -> Result<()>
    {
        crate::with_invocation_log(
            |sink| self.do_emit(
                sink,
                config.with_colons,
                config.fingerprint > 0));
        self.do_emit(w,
                     config.with_colons,
                     config.fingerprint > 0)
    }

    fn do_emit(&self,
               w: &mut (impl io::Write + ?Sized),
               mr: bool,
               prettyprint: bool)
                -> Result<()>
    {
        use chrono::{DateTime, Utc};
        use Record::*;

        // Helper function to format expiration and revocation times
        // in human-readable key listings.
        fn bracket(revoked_at: Option<DateTime::<Utc>>,
                   expired_at: Option<DateTime::<Utc>>) -> String {
            revoked_at.map(|t| format!(
                " [revoked: {}]", t.format("%Y-%m-%d")))
                .or_else(|| expired_at.map(|t| format!(
                    " [{}: {}]",
                    if t > chrono::Utc::now() { "expires" } else { "expired" },
                    t.format("%Y-%m-%d"))))
                .unwrap_or_else(|| "".into())
        }

        match self {
            Key {
                have_secret,
                validity,
                key_length,
                pk_algo,
                keyid,
                creation_date,
                expiration_date,
                revocation_date,
                ownertrust,
                primary_key_flags,
                sum_key_flags,
                token_sn,
                curve,
                compliance,
            } => {
                let record_type = if *have_secret {
                    "sec"
                } else {
                    "pub"
                };

                let creation_date =
                    chrono::DateTime::<chrono::Utc>::from(*creation_date);

                let expiration_date = expiration_date.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                let revocation_date = revocation_date.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                if mr {
                    let compliance_flags = compliance.iter()
                        .filter_map(|c| c.to_flag())
                        .map(|flag| flag.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");

                    writeln!(w,
                             "{}:{}:{}:{}:{:X}:{}:{}::{:#}:::{}{}{}:::{}::{}:{}::0:",
                             record_type,
                             validity,
                             key_length,
                             u8::from(*pk_algo),
                             keyid,
                             creation_date.format("%s"),
                             expiration_date.map(|t| t.format("%s").to_string())
                             .unwrap_or_else(|| "".into()),
                             ownertrust,
                             format!("{:#}", babel::Fish(primary_key_flags)),
                             format!("{:#}", babel::Fish(sum_key_flags)).to_uppercase(),
                             if ownertrust.disabled() { "D" } else { "" },
                             token_sn.as_ref().map(ToString::to_string)
                             .unwrap_or_default(),
                             curve.as_ref().map(|c| babel::Fish(c).to_string())
                             .unwrap_or_default(),
                             compliance_flags,
                    )?;
                } else {
                    writeln!(w,
                             "{}   {} {} [{}]{}",
                             record_type,
                             babel::Fish((*pk_algo, *key_length, curve)),
                             creation_date.format("%Y-%m-%d"),
                             babel::Fish(primary_key_flags).to_string().to_uppercase(),
                             bracket(revocation_date, expiration_date),
                    )?;
                }
            },

            Subkey {
                have_secret,
                validity,
                key_length,
                pk_algo,
                keyid,
                creation_date,
                expiration_date,
                revocation_date,
                key_flags,
                token_sn,
                curve,
                compliance,
            } => {
                let record_type = if *have_secret {
                    "ssb"
                } else {
                    "sub"
                };

                let creation_date =
                    chrono::DateTime::<chrono::Utc>::from(*creation_date);

                let expiration_date = expiration_date.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                let revocation_date = revocation_date.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                if mr {
                    let compliance_flags = compliance.iter()
                        .filter_map(|c| c.to_flag())
                        .map(|flag| flag.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");

                    writeln!(w, "{}:{}:{}:{}:{:X}:{}:{}:::::{}:::{}::{}:{}:",
                             record_type,
                             validity,
                             key_length,
                             u8::from(*pk_algo),
                             keyid,
                             creation_date.format("%s"),
                             expiration_date.map(|t| t.format("%s").to_string())
                             .unwrap_or_else(|| "".into()),
                             format!("{:#}", babel::Fish(key_flags)),
                             token_sn.as_ref().map(ToString::to_string)
                             .unwrap_or_default(),
                             curve.as_ref().map(|c| babel::Fish(c).to_string())
                             .unwrap_or_default(),
                             compliance_flags,
                    )?;
                } else {
                    writeln!(w,
                             "{}   {} {} [{}]{}",
                             record_type,
                             babel::Fish((*pk_algo, *key_length, curve)),
                             creation_date.format("%Y-%m-%d"),
                             babel::Fish(key_flags).to_string().to_uppercase(),
                             bracket(revocation_date, expiration_date),
                    )?;
                }
            },

            Fingerprint(fp) => {
                if mr {
                    writeln!(w, "fpr:::::::::{:X}:", fp)?;
                } else {
                    if prettyprint {
                        writeln!(w, "      {}", fp.to_spaced_hex())?;
                    } else {
                        writeln!(w, "      {:X}", fp)?;
                    }
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
                           validity.unwrap_or(Validity::Unknown),
                           creation_date.format("%s"),
                           expiration_date.map(|t| t.format("%s").to_string())
                           .unwrap_or_else(|| "".into()),
                           openpgp::fmt::hex::encode(&uidhash),
                    )?;
                    e(w, userid.value())?;
                    writeln!(w, "::::::::::0:")?;
                } else {
                    if let Some(validity) = validity {
                        writeln!(w, "uid           {} {}",
                                 BoxedValidity(*validity),
                                 String::from_utf8_lossy(userid.value()))?;
                    } else {
                        writeln!(w, "uid                      {}",
                                 String::from_utf8_lossy(userid.value()))?;
                    }
                }
            },

            RevocationKey {
                pk_algo,
                revoker,
                class,
                sensitive,
            } => {
                if mr {
                    writeln!(w, "rvk:::{}::::::{:X}:{:02x}{}:",
                             u8::from(*pk_algo),
                             revoker,
                             class,
                             if *sensitive { "s" } else { "" })?;
                }
            },

            TrustDBInformation {
                old,
                changed_model,
                model,
                creation_time,
                expiration_time,
                marginals_needed,
                completes_needed,
                max_cert_depth,
            } => {
                let creation_time =
                    chrono::DateTime::<chrono::Utc>::from(*creation_time);

                let expiration_time = expiration_time.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                if mr {
                    writeln!(w, "tru:{}{}:{}:{}:{}:{}:{}:{}",
                             if *old { "o" } else { "" },
                             if *changed_model { "o" } else { "" },
                             if let TrustModel::Classic = model { "0" } else { "1" },
                             creation_time.format("%s"),
                             expiration_time.map(|t| t.format("%s").to_string())
                             .unwrap_or_else(|| "0".into()),
                             marginals_needed,
                             completes_needed,
                             max_cert_depth,
                    )?;
                }
            },
        }

        Ok(())
    }
}

/// Represents the value of field 15, "S/N of a token".
pub enum TokenSN {
    SerialNumber(String),
    SimpleStub,
    SecretAvaliable,
}

impl fmt::Display for TokenSN {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TokenSN::*;
        match self {
            SerialNumber(s) => f.write_str(s),
            SimpleStub =>      f.write_str("#"),
            SecretAvaliable => f.write_str("+"),
        }
    }
}

/// Escapes the given string.
pub fn escape(s: impl AsRef<str>) -> String {
    e_str(s.as_ref())
}
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
pub fn escape_bytes(sink: &mut dyn io::Write, s: impl AsRef<[u8]>) -> Result<()>
{
    e(sink, s.as_ref())
}
fn e<W: io::Write + ?Sized>(sink: &mut W, s: impl AsRef<[u8]>) -> Result<()> {
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
            Unknown =>   f.write_str("[ unknown]"),
            Revoked =>   f.write_str("[ revoked]"),
            Expired =>   f.write_str("[ expired]"),
            Undefined => f.write_str("[  undef ]"),
            Never =>     f.write_str("[  never ]"),
            Marginal =>  f.write_str("[marginal]"),
            Fully =>     f.write_str("[  full  ]"),
            Ultimate =>  f.write_str("[ultimate]"),
        }
    }
}
