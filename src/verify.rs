use std::{
    io,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    crypto::hash::Digest,
    packet::Signature,
    packet::signature::subpacket::*,
    types::*,
    serialize::Marshal,
};
use openpgp::cert::prelude::*;
use openpgp::parse::{
    Parse,
};
use openpgp::parse::stream::*;

use crate::{
    control,
    status::Status,
    utils,
};

/// Dispatches the --verify command.
///
/// Assume that the input is a signature and verify it without
/// generating any output.  With no arguments, the signature packet is
/// read from stdin (it may be a detached signature when not used in
/// batch mode). If only a sigfile is given, it may be a complete
/// signature or a detached signature in which case the signed stuff
/// is expected from stdin. With more than 1 argument, the first
/// should be a detached signature and the remaining files are the
/// signed stuff.
pub fn cmd_verify(control: &dyn control::Common, args: &[String])
                  -> Result<()>
{
    // Decide whether we should handle a detached or a normal signature,
    // which is needed so that the code later can hash the correct data and
    // not have a normal signature act as detached signature and ignoring the
    // intended signed material from the 2nd file or stdin.
    // 1. gpg <file        - normal
    // 2. gpg file         - normal (or detached)
    // 3. gpg file <file2  - detached
    // 4. gpg file file2   - detached
    // The question is how decide between case 2 and 3?  The only way
    // we can do it is by reading one byte from stdin and then unget
    // it; the problem here is that we may be reading from the
    // terminal (which could be detected using isatty() but won't work
    // when under control of a pty using program (e.g. expect)) and
    // might get us in trouble when stdin is used for another purpose
    // (--passphrase-fd 0).  So we have to break with the behaviour
    // prior to gpg 1.0.4 by assuming that case 3 is a normal
    // signature (where file2 is ignored and require for a detached
    // signature to indicate signed material comes from stdin by using
    // case 4 with a file2 of "-".

    let sigfile = args.get(0).cloned().unwrap_or_else(|| "-".into());
    let sig = utils::open(control, &sigfile)?;

    let policy = control.policy();

    // Long story short: If we have at least two files, it is a
    // detached signature.
    let _helper = if args.len() > 1 {
        let data = utils::open_multiple(control, &args[1..]);
        let helper = VHelper::new(control, 1);
        let mut v = DetachedVerifierBuilder::from_reader(sig)?
            .with_policy(policy, None, helper)?;
        v.verify_reader(data)?;
        v.into_helper()
    } else {
        let mut sink = if let Some(name) = control.outfile() {
            utils::create(control, name)?
        } else {
            Box::new(io::sink())
        };
        let helper = VHelper::new(control, 1);
        let mut v = VerifierBuilder::from_reader(sig)?
            .with_policy(policy, None, helper)?;
        io::copy(&mut v, &mut sink)?;
        v.into_helper()
    };

    Ok(())
}

struct VHelper<'a> {
    #[allow(dead_code)]
    control: &'a dyn control::Common,
    signatures: usize,
    good_signatures: usize,
    good_checksums: usize,
    unknown_checksums: usize,
    bad_signatures: usize,
    bad_checksums: usize,
    broken_signatures: usize,
}

impl<'a> VHelper<'a> {
    fn new(control: &'a dyn control::Common, signatures: usize)
           -> Self {
        VHelper {
            control,
            signatures,
            good_signatures: 0,
            good_checksums: 0,
            unknown_checksums: 0,
            bad_signatures: 0,
            bad_checksums: 0,
            broken_signatures: 0,
        }
    }

    fn print_status(&self) {
        fn p(dirty: &mut bool, what: &str, quantity: usize) {
            if quantity > 0 {
                eprint!("{}{} {}{}",
                        if *dirty { ", " } else { "" },
                        quantity, what,
                        if quantity == 1 { "" } else { "s" });
                *dirty = true;
            }
        }

        let mut dirty = false;
        p(&mut dirty, "good signature", self.good_signatures);
        p(&mut dirty, "good checksum", self.good_checksums);
        p(&mut dirty, "unknown checksum", self.unknown_checksums);
        p(&mut dirty, "bad signature", self.bad_signatures);
        p(&mut dirty, "bad checksum", self.bad_checksums);
        p(&mut dirty, "broken signatures", self.broken_signatures);
        if dirty {
            eprintln!(".");
        }
    }

    /// Computes the signature id, a hash over the signature.
    fn compute_signature_id(&self, sig: &Signature) -> Result<String> {
        let mut h = HashAlgorithm::SHA1.context()?;

        // Algorithms.
        h.write_all(&[
            sig.pk_algo().into(),
            sig.hash_algo().into(),
        ])?;

        // Creation time.
        if let SubpacketValue::SignatureCreationTime(t) =
            sig.subpacket(SubpacketTag::SignatureCreationTime)
            .expect("every valid sig has one")
            .value()
        {
            h.write_all(&u32::from(*t).to_be_bytes())?;
        } else {
            unreachable!()
        };

        // MPIs.
        sig.mpis().serialize(&mut h)?;

        // Now base64-encode to form the Signature ID.
        Ok(base64::encode_config(h.into_digest()?, base64::STANDARD_NO_PAD))
    }

    fn emit_sig_header(&self, sig: &Signature) -> Result<()> {
        self.control.status().emit(Status::NewSig {
            signers_uid: sig.signers_user_id().map(Into::into),
        })?;
        eprintln!("{}: Signature made {}",
                  "gpgv",
                  sig.signature_creation_time()
                  .map(|t| {
                      use chrono::*;
                      DateTime::<Utc>::from(t).with_timezone(&Local)
                          .format("%c %Z").to_string()
                  })
                  .unwrap_or_else(|| "without creation time".into()));
        eprintln!("{}:                using {:?} key {}",
                  "gpgv",
                  sig.pk_algo(),
                  sig.get_issuers().get(0)
                  .map(ToString::to_string)
                  .unwrap_or_else(|| "without issuer information".into()));

        Ok(())
    }

    fn emit_key_considered(&self, cert: &Cert, not_selected: bool)
                           -> Result<()> {
        self.control.status().emit(Status::KeyConsidered {
            fingerprint: cert.fingerprint(),
            not_selected,
            all_expired_or_revoked:
            cert.with_policy(self.control.policy(), None)
                .map(|vcert| vcert.keys().revoked(false)
                     .all(|ka| ka.alive().is_err()))
                .unwrap_or(true),
        })
    }

    fn print_sigs(&mut self, results: &[VerificationResult]) -> Result<()> {
        use crate::print_error_chain;
        use self::VerificationError::*;
        for result in results {
            match result {
                Ok(GoodChecksum { sig, ka, .. }) => {
                    self.emit_sig_header(sig)?;
                    self.emit_key_considered(ka.cert(), false)?;

                    if sig.typ() == SignatureType::Binary
                        || sig.typ() == SignatureType::Text
                    {
                        self.control.status().emit(Status::SigId {
                            id: self.compute_signature_id(sig)?,
                            creation_time: sig.signature_creation_time()
                                .expect("every valid sig has one"),
                        })?;
                    }

                    self.control.status().emit(Status::GoodSig {
                        issuer: ka.fingerprint().into(),
                        primary_uid:
                        ka.cert().primary_userid().map(|u| u.value().into())
                            .unwrap_or_else(|_| b"unknown"[..].into()),
                    })?;

                    let primary_uid =
                        ka.cert().primary_userid().map(|u| {
                            String::from_utf8_lossy(u.value()).to_string()
                        })
                        .unwrap_or_else(|_| ka.fingerprint().to_string());
                    eprintln!("{}: Good signature from {:?}",
                              "gpgv", primary_uid);
                    for uid in ka.cert().userids() {
                        let uid = String::from_utf8_lossy(uid.value());
                        if uid != primary_uid {
                            eprintln!("{}:                     {:?}",
                                      "gpgv", uid);
                        }
                    }

                    // Dump notations.
                    for notation in sig.notation_data() {
                        self.control.status().emit(Status::NotationName {
                            name: notation.name().into(),
                        })?;
                        if notation.flags().human_readable() {
                            self.control.status().emit(Status::NotationFlags {
                                // If it were critical, the sig would
                                // not have checked out
                                critical: false,
                                human_readable: true,
                            })?;
                        }
                        self.control.status().emit(Status::NotationData {
                            data: notation.value().into(),
                        })?;
                    }

                    // Cryptographically valid.
                    self.control.status().emit(Status::ValidSig {
                        issuer: ka.fingerprint(),
                        creation_time: sig.signature_creation_time()
                            .expect("every well-formed signature has one"),
                        expire_time: sig.signature_expiration_time(),
                        version: sig.version(),
                        pk_algo: sig.pk_algo(),
                        hash_algo: sig.hash_algo(),
                        sig_class: sig.typ(),
                        primary: ka.cert().fingerprint(),
                    })?;

                    self.good_signatures += 1;
                },
                Err(MalformedSignature { sig, error, .. }) => {
                    self.emit_sig_header(sig)?;
                    eprintln!("Malformed signature:");
                    print_error_chain(error);
                    self.broken_signatures += 1;
                    continue;
                },
                Err(MissingKey { sig, .. }) => {
                    self.emit_sig_header(sig)?;
                    let issuer = sig.get_issuers().get(0)
                        .expect("missing key checksum has an issuer")
                        .to_string();
                    let what = match sig.level() {
                        0 => "checksum".into(),
                        n => format!("level {} notarizing checksum", n),
                    };
                    eprintln!("No key to check {} from {}", what, issuer);
                    self.unknown_checksums += 1;
                    continue;
                },
                Err(UnboundKey { sig, cert, error, .. }) => {
                    self.emit_sig_header(sig)?;
                    // XXX does this case map to KEY_CONSIDERED not_selected?
                    self.emit_key_considered(cert, true)?;
                    eprintln!("Signing key on {} is not bound:",
                              cert.fingerprint());
                    print_error_chain(error);
                    self.bad_checksums += 1;
                    continue;
                },
                Err(BadKey { sig, ka, error, .. }) => {
                    self.emit_sig_header(sig)?;
                    self.emit_key_considered(ka.cert(), false)?;
                    // xxx: check sig.verify(ka.key()) && policy(sig) first

                    // ExpKeySig, RevKeySig
                    eprintln!("Signing key on {} is bad:",
                              ka.cert().fingerprint());
                    print_error_chain(error);
                    self.bad_checksums += 1;
                    continue;
                },
                Err(BadSignature { sig, ka, error }) => {
                    self.emit_sig_header(sig)?;
                    self.emit_key_considered(ka.cert(), false)?;

                    self.control.status().emit(Status::BadSig {
                        issuer: ka.fingerprint().into(),
                        primary_uid:
                        ka.cert().primary_userid().map(|u| u.value().into())
                            .unwrap_or_else(|_| b"unknown"[..].into()),
                    })?;

                    eprintln!("{}: BAD signature from {:?}",
                              "gpgv",
                              ka.cert().primary_userid().map(|u| {
                                  String::from_utf8_lossy(u.value()).to_string()
                              })
                              .unwrap_or_else(|_|
                                              ka.fingerprint().to_string()));

                    if self.control.verbose() > 0 {
                        print_error_chain(error);
                    }

                    self.bad_checksums += 1;
                    continue;
                }
            };
        }

        Ok(())
    }
}

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        Ok(ids.iter().map(|id| self.control.keydb().get(id).cloned())
           .filter_map(|v| v).collect())
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for layer in structure {
            match layer {
                MessageLayer::Compression { algo } =>
                    eprintln!("Compressed using {}", algo),
                MessageLayer::Encryption { sym_algo, aead_algo } =>
                    if let Some(aead_algo) = aead_algo {
                        eprintln!("Encrypted and protected using {}/{}",
                                  sym_algo, aead_algo);
                    } else {
                        eprintln!("Encrypted using {}", sym_algo);
                    },
                MessageLayer::SignatureGroup { ref results } =>
                    self.print_sigs(results)?,
            }
        }

        if self.good_signatures >= self.signatures
            && self.bad_signatures + self.bad_checksums == 0
        {
            Ok(())
        } else {
            if self.control.verbose() > 0 {
                self.print_status();
            }
            Err(anyhow::anyhow!("Verification failed"))
        }
    }
}
