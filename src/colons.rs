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
    cert::prelude::*,
    crypto::hash::Digest,
    crypto::mpi::PublicKey,
    packet::{UserID, Key, key::{PublicParts, PrimaryRole, SubordinateRole}},
    types::*,
};
use sequoia_ipc as ipc;
use ipc::Keygrip;

use crate::{
    KeyIDFormat,
    babel,
    common::{Common, Compliance},
    trust::*,
};

#[allow(dead_code)]
pub enum Record<'k> {
    Key {
        key: &'k Key<PublicParts, PrimaryRole>,
        have_secret: bool,
        validity: Validity,
        expiration_date: Option<SystemTime>,
        revocation_date: Option<SystemTime>,
        ownertrust: OwnerTrust,
        primary_key_flags: KeyFlags,
        sum_key_flags: KeyFlags,
        token_sn: Option<TokenSN>,
        compliance: Vec<Compliance>,
    },
    Subkey {
        key: &'k Key<PublicParts, SubordinateRole>,
        have_secret: bool,
        validity: Validity,
        expiration_date: Option<SystemTime>,
        revocation_date: Option<SystemTime>,
        key_flags: KeyFlags,
        token_sn: Option<TokenSN>,
        compliance: Vec<Compliance>,
    },
    Fingerprint(Fingerprint),
    Keygrip(Keygrip),
    UserID {
        amalgamation: UserIDAmalgamation<'k>,
        validity: Option<Validity>,
    },

    Signature {
        issuer: Option<KeyID>,
        issuer_fp: Option<Fingerprint>,
        issuer_uid: Option<UserID>,
        validity: Option<SignatureValidity>,
        pk_algo: PublicKeyAlgorithm,
        hash_algo: HashAlgorithm,
        creation_time: SystemTime,
        typ: SignatureType,
        exportable: bool,
        trust: Option<(u8, u8)>,
        has_notations: bool,
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

impl Record<'_> {
    /// Emits the record to `w`, `mr` indicates whether it should be
    /// machine-readable.
    pub fn emit(&self, config: &crate::Config,
                w: &mut (impl io::Write + ?Sized))
                -> Result<()>
    {
        crate::with_invocation_log(
            |sink| self.do_emit(
                sink,
                config,
                config.with_colons,
                config.fingerprint > 0));
        self.do_emit(w,
                     config,
                     config.with_colons,
                     config.fingerprint > 0)
    }

    fn do_emit(&self,
               w: &mut (impl io::Write + ?Sized),
               config: &crate::Config,
               mr: bool,
               prettyprint: bool)
                -> Result<()>
    {
        use chrono::{DateTime, Utc};
        use Record::*;

        // Helper function to format expiration and revocation times
        // in human-readable key listings.
        fn bracket(config: &crate::Config,
                   revoked_at: Option<DateTime::<Utc>>,
                   expired_at: Option<DateTime::<Utc>>) -> String {
            revoked_at.map(|t| format!(
                " [revoked: {}]", t.format("%Y-%m-%d")))
                .or_else(|| expired_at.map(|t| format!(
                    " [{}: {}]",
                    if t > chrono::DateTime::<chrono::Utc>::from(config.now()) {
                        "expires"
                    } else {
                        "expired"
                    },
                    t.format("%Y-%m-%d"))))
                .unwrap_or_else(|| "".into())
        }

        match self {
            Key {
                key,
                have_secret,
                validity,
                expiration_date,
                revocation_date,
                ownertrust,
                primary_key_flags,
                sum_key_flags,
                token_sn,
                compliance,
                ..
            } => {
                let record_type = if *have_secret {
                    "sec"
                } else {
                    "pub"
                };

                let creation_date =
                    chrono::DateTime::<chrono::Utc>::from(key.creation_time());

                let expiration_date = expiration_date.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                let revocation_date = revocation_date.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                let curve = get_curve(key.mpis());
                let key_length = get_bits(key.mpis());

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
                             u8::from(key.pk_algo()),
                             key.keyid(),
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
                             "{}   {}{} {} [{}]{}",
                             record_type,
                             babel::Fish((key.pk_algo(), key_length, &curve)),
                             match config.keyid_format {
                                 KeyIDFormat::None => format!(""),
                                 KeyIDFormat::Long => format!("/{}", key.keyid()),
                                 KeyIDFormat::HexLong => format!("/0x{}", key.keyid()),
                             },
                             creation_date.format("%Y-%m-%d"),
                             babel::Fish(primary_key_flags).to_string().to_uppercase(),
                             bracket(config, revocation_date, expiration_date),
                    )?;
                }
            },

            Subkey {
                key,
                have_secret,
                validity,
                expiration_date,
                revocation_date,
                key_flags,
                token_sn,
                compliance,
            } => {
                let record_type = if *have_secret {
                    "ssb"
                } else {
                    "sub"
                };

                let creation_date =
                    chrono::DateTime::<chrono::Utc>::from(key.creation_time());

                let expiration_date = expiration_date.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                let revocation_date = revocation_date.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                let curve = get_curve(key.mpis());
                let key_length = get_bits(key.mpis());

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
                             u8::from(key.pk_algo()),
                             key.keyid(),
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
                             "{}   {}{} {} [{}]{}",
                             record_type,
                             babel::Fish((key.pk_algo(), key_length, &curve)),
                             match config.keyid_format {
                                 KeyIDFormat::None => format!(""),
                                 KeyIDFormat::Long => format!("/{}", key.keyid()),
                                 KeyIDFormat::HexLong => format!("/0x{}", key.keyid()),
                             },
                             creation_date.format("%Y-%m-%d"),
                             babel::Fish(key_flags).to_string().to_uppercase(),
                             bracket(config, revocation_date, expiration_date),
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
                amalgamation,
                validity,
            } => {
                let userid = amalgamation.userid();
                let binding = amalgamation
                    .binding_signature(config.policy(), config.now()).ok()
                    .or_else(|| amalgamation.self_signatures().next());

                let creation_date = binding.as_ref()
                    .and_then(|b| b.signature_creation_time())
                    .unwrap_or(std::time::UNIX_EPOCH);

                let expiration_date = binding.as_ref()
                    .and_then(|b| b.signature_expiration_time());

                // GnuPG doesn't emit the creation date if the user ID
                // binding signature is expired or revoked.
                let creation_date =
                    (
                        matches!(
                            amalgamation.revocation_status(
                                config.policy(), config.now()),
                            RevocationStatus::NotAsFarAsWeKnow)
                        && expiration_date.is_none()
                    ).then_some(
                        chrono::DateTime::<chrono::Utc>::from(creation_date)
                    );

                let expiration_date = expiration_date.map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                });

                let mut uidhash = HashAlgorithm::RipeMD.context()?;
                uidhash.update(userid.value());
                let uidhash = uidhash.into_digest()?;

                if mr {
                    write!(w, "uid:{}::::{}:{}:{}::",
                           validity.unwrap_or(ValidityLevel::Unknown.into()),
                           creation_date.map(|t| t.format("%s").to_string())
                           .unwrap_or_default(),
                           expiration_date.map(|t| t.format("%s").to_string())
                           .unwrap_or_else(|| "".into()),
                           openpgp::fmt::hex::encode(&uidhash),
                    )?;
                    e(w, userid.value())?;
                    writeln!(w, "::::::::::0:")?;
                } else {
                    if let Some(validity) = validity {
                        writeln!(w, "{:width$}{} {}",
                                 "uid",
                                 BoxedValidity(*validity),
                                 String::from_utf8_lossy(userid.value()),
                                 width = match config.keyid_format {
                                     KeyIDFormat::None => 14,
                                     KeyIDFormat::Long => 20,
                                     KeyIDFormat::HexLong => 22,
                                 },
                        )?;
                    } else {
                        writeln!(w, "uid                      {}",
                                 String::from_utf8_lossy(userid.value()))?;
                    }
                }
            },

            Signature {
                issuer,
                issuer_fp,
                issuer_uid,
                validity,
                pk_algo,
                hash_algo,
                creation_time,
                typ,
                exportable,
                trust,
                has_notations,
            } => {
                use SignatureType::*;
                let class = match typ {
                    CertificationRevocation
                        | KeyRevocation
                        | SubkeyRevocation => "rev",
                    _ => "sig",
                };

                let creation_time =
                    chrono::DateTime::<chrono::Utc>::from(*creation_time);

                if mr {
                    writeln!(w, "{}:{}::{}:{}:{}::{}::{}:{:02x}{}::{}:::{}:",
                             class,
                             validity.as_ref().map(|i| i.to_string())
                             .unwrap_or_default(),
                             u8::from(*pk_algo),
                             issuer.as_ref().map(|i| i.to_string())
                             .unwrap_or_default(),
                             creation_time.format("%s"),
                             trust.map(|(depth, amount)|
                                       format!("{} {}", depth, amount))
                             .unwrap_or_else(|| "".into()),
                             issuer_uid.as_ref()
                             .map(|u| String::from_utf8_lossy(u.value()).to_string())
                             .unwrap_or_else(|| "[User ID not found]".to_string()),
                             u8::from(*typ),
                             if *exportable { 'x' } else { 'l' },
                             issuer_fp.as_ref().map(|i| i.to_string())
                             .unwrap_or_default(),
                             u8::from(*hash_algo))?;
                } else {
                    use SignatureType::*;
                    writeln!(w, "{} {}    {} {} {} {}  {}",
                             class,
                             match typ {
                                 PersonaCertification => '1',
                                 CasualCertification => '2',
                                 PositiveCertification => '3',
                                 _ => ' ',
                             },
                             has_notations.then_some('N').unwrap_or(' '),
                             trust.map(|(depth, _amount)| depth.to_string())
                             .unwrap_or_else(|| " ".into()),
                             issuer.as_ref().map(|i| i.to_string())
                             .unwrap_or_default(),
                             creation_time.format("%Y-%m-%d"),
                             issuer_uid.as_ref()
                             .map(|u|
                                  String::from_utf8_lossy(u.value()).to_string())
                             .unwrap_or_else(
                                 || "[User ID not found]".to_string()))?;
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

pub enum SignatureValidity {
    Good,
    Bad,
    MissingKey,
    OtherError,
}

impl fmt::Display for SignatureValidity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SignatureValidity::*;
        match self {
            Good => f.write_str("!"),
            Bad => f.write_str("-"),
            MissingKey => f.write_str("?"),
            OtherError => f.write_str("%"),
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
        if self.0.revoked {
            f.write_str("[ revoked]")
        } else if self.0.expired {
            f.write_str("[ expired]")
        } else {
            use ValidityLevel::*;
            match self.0.level {
                Unknown =>   f.write_str("[ unknown]"),
                Undefined => f.write_str("[  undef ]"),
                Never =>     f.write_str("[  never ]"),
                Marginal =>  f.write_str("[marginal]"),
                Fully =>     f.write_str("[  full  ]"),
                Ultimate =>  f.write_str("[ultimate]"),
            }
        }
    }
}

/// Returns the elliptic curve of the given key, if any.
pub fn get_curve(mpis: &PublicKey) -> Option<Curve> {
    match mpis {
        PublicKey::EdDSA { curve, .. }
        | PublicKey::ECDSA { curve, .. }
        | PublicKey::ECDH { curve, .. } => Some(curve.clone()),
        _ => None,
    }
}

/// Returns the size of the key that we should report.
pub fn get_bits(mpis: &PublicKey) -> usize {
    match mpis {
        // GnuPG knows better than the rest of the world.
        PublicKey::EdDSA { curve, .. } if *curve == Curve::Ed25519 => 255,
        // GnuPG knows better than the rest of the world.
        PublicKey::ECDH { curve, .. } if *curve == Curve::Cv25519 => 255,
        _ => mpis.bits().unwrap_or(0),
    }
}
