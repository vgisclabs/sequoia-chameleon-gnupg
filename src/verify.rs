use std::{
    collections::HashSet,
    io,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    KeyID,
    crypto::hash::Digest,
    packet::{
        Packet,
        Signature,
        header::BodyLength,
    },
    packet::signature::subpacket::*,
    packet::key,
    types::*,
    policy::HashAlgoSecurity,
    serialize::Marshal,
};
use openpgp::cert::prelude::*;
use openpgp::parse::{
    Parse,
};
use openpgp::parse::stream::*;

use sequoia_cert_store as cert_store;
use cert_store::Store;

use crate::{
    argparse,
    argparse::options::Opt,
    babel,
    common::{Common, Query, ValidityLevel},
    status::{Status, ErrSigStatus, NoDataReason},
    utils,
};

/// Controls verification operations.
pub struct VerifyOptions {
    /// Display photo IDs during signature verification.
    pub photos: bool,

    /// Show policy URLs during signature listings.
    pub policy_urls: bool,

    /// Show IETF standard notations during signature listings.
    pub ietf_notations: bool,

    /// Show user standard notations during signature listings.
    pub user_notations: bool,

    /// Show preferred keyserver URLs during signature listings.
    pub preferred_keyserver: bool,

    /// Show user ID validity during signature verification.
    pub uid_validity: bool,

    /// Show revoked and expired user IDs in signature verification.
    pub unusable_uids: bool,

    /// Show only the primary user ID in signature verification.
    pub primary_uid_only: bool,

    /// Validate signatures with PKA data.
    pub pka_lookups: bool,

    /// Elevate the trust of signatures with valid PKA data.
    pub pka_trust_increase: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            photos: false,
            policy_urls: true,
            ietf_notations: true,
            user_notations: false,
            preferred_keyserver: true,
            uid_validity: true,
            unusable_uids: false,
            primary_uid_only: false,
            pka_lookups: false,
            pka_trust_increase: false,
        }
    }
}

impl VerifyOptions {
    const OPTS: [Opt<VerifyOptions>; 12] = [
        opt_todo! {
            "show-photos",
            |o, s, _| Ok({ o.photos = s; }),
            "display photo IDs during signature verification",
        },

        opt_todo! {
            "show-policy-urls",
            |o, s, _| Ok({ o.policy_urls = s; }),
            "show policy URLs during signature listings",
        },

        opt_todo! {
            "show-notations",
            |o, s, _| Ok({ o.ietf_notations = s; o.user_notations = s; }),
            "show all notations during signature listings",
        },

        opt_todo! {
            "show-std-notations",
            |o, s, _| Ok({ o.ietf_notations = s; }),
            "show IETF standard notations during signature listings",
        },

        opt_todo! {
            "show-standard-notations",
            |o, s, _| Ok({ o.ietf_notations = s; }),
            "",
        },

        opt_todo! {
            "show-user-notations",
            |o, s, _| Ok({ o.user_notations = s; }),
            "show user-supplied notations during signature listings",
        },

        opt_todo! {
            "show-keyserver-urls",
            |o, s, _| Ok({ o.preferred_keyserver = s; }),
            "show preferred keyserver URLs during signature listings",
        },

        opt! {
            "show-uid-validity",
            |o, s, _| Ok({ o.uid_validity = s; }),
            "show user ID validity during signature verification",
        },

        opt_todo! {
            "show-unusable-uids",
            |o, s, _| Ok({ o.unusable_uids = s; }),
            "show revoked and expired user IDs in signature verification",
        },

	opt_todo! {
            "show-primary-uid-only",
            |o, s, _| Ok({ o.primary_uid_only = s; }),
	    "show only the primary user ID in signature verification",
        },

	opt_todo! {
            "pka-lookups",
            |o, s, _| Ok({ o.pka_lookups = s; }),
	    "validate signatures with PKA data",
        },

	opt_todo! {
            "pka-trust-increase",
            |o, s, _| Ok({ o.pka_trust_increase = s; }),
	    "elevate the trust of signatures with valid PKA data",
        },
    ];

    /// Prints the list of verify options if requested.
    ///
    /// If `s == "help"`, prints all supported options and returns
    /// `true`.  The caller should then exit the process gracefully.
    pub fn maybe_print_help(s: &str) -> Result<bool> {
        argparse::options::maybe_print_help(&Self::OPTS, s)
    }

    /// Parses the verify options.
    pub fn parse(&mut self, s: &str) -> Result<()> {
        argparse::options::parse(&Self::OPTS, s, self)
    }
}

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
pub fn cmd_verify(control: &crate::Config, args: &[String])
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
    let do_it = || -> Result<()> {
        if args.len() > 1 {
            let data = utils::open_multiple(control, &args[1..]);
            let helper = VHelper::new(control, 1);
            let mut v = DetachedVerifierBuilder::from_reader(sig)?
                .with_policy(policy, control.now(), helper)?;
            v.verify_reader(data)?;
            Ok(())
        } else {
            let mut sink = if let Some(name) = control.outfile() {
                utils::create(control, name)?
            } else {
                Box::new(io::sink())
            };
            let helper = VHelper::new(control, 1);
            let mut v = VerifierBuilder::from_reader(sig)?
                .with_policy(policy, control.now(), helper)?;
            io::copy(&mut v, &mut sink)?;
            Ok(())
        }
    };

    map_verificaton_error(control, do_it())
}

/// Dispatches the --verify-files command.
pub fn cmd_verify_files(control: &crate::Config, args: &[String])
                        -> Result<()>
{
    let inputs_store;
    let inputs = if args.is_empty() {
        // Read files from stdin, one each line.
        use io::BufRead;
        inputs_store = io::BufReader::new(io::stdin()).lines()
            .collect::<io::Result<Vec<String>>>()?;
        &inputs_store[..]
    } else {
        args
    };

    let policy = control.policy();
    for sigfile in inputs {
        let sig = utils::open(control, &sigfile)?;

        control.status().emit(Status::FileStart {
            what: crate::status::FileStartOperation::Verify,
            name: &sigfile,
        })?;

        let do_it = || -> Result<()> {
            // Curiously, GnuPG supports --output with --multifile
            // --verify, but it will override the file with each
            // verification.
            let mut sink = if let Some(name) = control.outfile() {
                utils::create(control, name)?
            } else {
                Box::new(io::sink())
            };
            let helper = VHelper::new(control, 1);
            let mut v = VerifierBuilder::from_reader(sig)?
                .with_policy(policy, control.now(), helper)?;
            io::copy(&mut v, &mut sink)?;

            Ok(())
        };

        let _ = map_verificaton_error(control, do_it());
        control.status().emit(Status::FileDone)?;
    }

    Ok(())
}

fn map_verificaton_error(control: &crate::Config, r: Result<()>)
                         -> Result<()> {
    match r {
        Ok(()) => Ok(()),
        Err(e) => {
            control.override_status_code(1);
            match e.downcast::<openpgp::Error>() {
                Ok(oe) => {
                    // Map our errors to the way GnuPG reports errors.
                    match oe {
                        openpgp::Error::MalformedPacket(_) =>
                        {
                            control.status().emit(Status::NoData(
                                NoDataReason::ExpectedPacket))?;
                            control.status().emit(Status::NoData(
                                NoDataReason::ExpectedSignature))?;
                        },
                        openpgp::Error::MalformedMessage(_) => {
                            control.status().emit(Status::NoData(
                                NoDataReason::InvalidPacket))?;
                            control.status().emit(Status::NoData(
                                NoDataReason::ExpectedSignature))?;
                        },
                        _ => (),
                    }
                    Err(oe.into())
                },
                Err(e) => Err(e),
            }
        },
    }
}

pub struct VHelper<'a, 'store> {
    control: &'a crate::Config<'store>,
    #[allow(dead_code)]
    signatures: usize,
    good_signatures: usize,
    good_checksums: usize,
    unknown_checksums: usize,
    bad_signatures: usize,
    bad_checksums: usize,
    broken_signatures: usize,

    /// Weak hash algorithm warnings.
    ///
    /// The value indicates whether a warning has been printed for
    /// this algorithm.
    weak_digest_warning_printed: HashSet<HashAlgorithm>,
}

impl<'a, 'store> VHelper<'a, 'store> {
    pub fn new(control: &'a crate::Config<'store>, signatures: usize)
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
            weak_digest_warning_printed: Default::default(),
        }
    }

    fn print_status(&self) {
        fn p(dirty: &mut bool, what: &str, quantity: usize) {
            if quantity > 0 {
                safe_eprint!("{}{} {}{}",
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
            safe_eprintln!(".");
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
        use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine};
        Ok(BASE64_STANDARD_NO_PAD.encode(h.into_digest()?))
    }

    fn emit_signature<'c, C, K, E>(&mut self, sig: &Signature,
                                   ka: K,
                                   err_sig_status: E,
                                   cert: C, not_selected: bool)
                                   -> Result<bool>
    where
        K: Into<Option<&'c ValidErasedKeyAmalgamation<'c, key::PublicParts>>>,
        E: Into<Option<ErrSigStatus>>,
        C: Into<Option<&'c Cert>>,
    {
        let ka = ka.into();
        let err_sig_status = err_sig_status.into();

        let good_signature_type = sig.typ() == SignatureType::Binary ||
            sig.typ() == SignatureType::Text;

        let weak_hash =
            if let Err(e) = self.control.policy().signature(
                sig, HashAlgoSecurity::CollisionResistance)
        {
            // Yuck.  Get the hash algo back from the error.
            if let Some(openpgp::Error::PolicyViolation(m, _)) =
                e.downcast_ref()
            {
                m.parse::<HashAlgorithm>().ok()
            } else {
                None
            }
        } else {
            None
        };

        self.control.status().emit(Status::NewSig {
            signers_uid: sig.signers_user_id().map(Into::into),
        })?;

        if ! good_signature_type {
            self.control.error(
                format_args!("standalone signature of class 0x{:02x}",
                             u8::from(sig.typ())));
        }
        self.control.warn(format_args!(
            "Signature made {}",
            sig.signature_creation_time()
                .map(|t| babel::Fish(t).to_string())
                .unwrap_or_else(|| "without creation time".into())));
        self.control.warn(format_args!(
            "               using {} key {}",
            babel::Fish(sig.pk_algo()),
            sig.get_issuers().get(0)
                .map(ToString::to_string)
                .unwrap_or_else(|| "without issuer information".into())));
        if let Some(issuer) = sig.signers_user_id() {
            self.control.warn(format_args!(
                "               issuer {:?}",
                String::from_utf8_lossy(issuer)));
        }

        if let Some(cert) = cert.into() {
            if good_signature_type {
                self.emit_key_considered(cert, not_selected)?;
            }
        }

        if good_signature_type && weak_hash.is_none()
            && err_sig_status.is_none()
        {
            Ok(false)
        } else {
            use SignatureType::*;

            if let Some(algo) = weak_hash.as_ref().cloned() {
                if ! self.weak_digest_warning_printed.contains(&algo)
                    && ! self.control.quiet()
                    && err_sig_status != Some(ErrSigStatus::MissingKey)
                {
                    self.control.warn(format_args!(
                        "Note: signatures using the {} \
                         algorithm are rejected",
                        babel::Fish(algo)));
                    self.weak_digest_warning_printed.insert(algo);
                }
            }

            self.control.status().emit(Status::ErrSig {
                issuer: sig.issuers().cloned().next()
                    .unwrap_or(KeyID::wildcard()),
                creation_time: sig.signature_creation_time()
                    .expect("every well-formed signature has one"),
                pk_algo: sig.pk_algo(),
                hash_algo: sig.hash_algo(),
                sig_class: sig.typ(),
                rc: if let Some(s) = err_sig_status {
                    s
                } else if weak_hash.is_some() {
                    ErrSigStatus::WeakHash
                } else if sig.typ() == KeyRevocation {
                    ErrSigStatus::UnexpectedRevocation
                } else {
                    ErrSigStatus::BadSignatureClass
                },
                issuer_fingerprint: sig.issuer_fingerprints().cloned().next(),
            })?;

            match sig.typ() {
                GenericCertification
                    | PersonaCertification
                    | CasualCertification
                    | PositiveCertification
                    | SubkeyBinding
                    | DirectKey
                    | SubkeyRevocation
                    | CertificationRevocation =>
                {
                    self.control.error(
                        format_args!("invalid root packet for sigclass {:02x}",
                                     u8::from(sig.typ())));
                },
                KeyRevocation =>
                {
                    self.control.error(
                        format_args!("standalone revocation - \
                                      use \"gpg --import\" to apply"));
                },
                _ => (),
            }

            if let Some(s) = err_sig_status {
                match s {
                    ErrSigStatus::BadPublicKey =>
                        self.control.error(
                            format_args!("Can't check signature: \
                                          Bad public key")),
                    ErrSigStatus::WrongKeyUsage => {
                        self.control.error(
                            format_args!("bad data signature from key {:X}: \
                                          Wrong key usage (0x{:02x}, 0x{:x})",
                                         ka.map(|ka| ka.keyid())
                                         .unwrap_or_else(|| KeyID::wildcard()),
                                         u8::from(sig.typ()),
                                         ka.and_then(|ka| ka.key_flags())
                                         .map(key_flags_to_usage)
                                         .unwrap_or(0)));
                        self.control.error(
                            format_args!("Can't check signature: \
                                          Wrong key usage"));
                    },
                    ErrSigStatus::MissingKey => {
                        self.control.status().emit(Status::NoPubkey {
                            issuer: sig.get_issuers().get(0).map(Into::into)
                                .unwrap_or_else(KeyID::wildcard),
                        })?;
                        self.control.error(
                            format_args!("Can't check signature: \
                                          No public key"));
                    },
                    _ => unreachable!(),
                }
            } else if weak_hash.is_some() {
                self.control.error(
                    format_args!("Can't check signature: \
                                  Invalid digest algorithm"));
            } else if sig.typ() != KeyRevocation {
                self.control.error(
                    format_args!("Can't check signature: \
                                  Invalid signature class"));
            }

            Ok(true)
        }
    }

    fn emit_key_considered(&self, cert: &Cert, not_selected: bool)
                           -> Result<()> {
        self.control.status().emit(Status::KeyConsidered {
            fingerprint: cert.fingerprint(),
            not_selected,
            all_expired_or_revoked:
            false && // XXX: I haven't seen GnuPG set that.
            cert.with_policy(self.control.policy(), self.control.now())
                .map(|vcert| vcert.keys().subkeys().revoked(false)
                     .all(|ka| ka.alive().is_err()))
                .unwrap_or(true),
        })
    }

    fn emit_good_signature(&self,
                           sig: &Signature,
                           ka: &ValidErasedKeyAmalgamation<key::PublicParts>,
                           error: Option<&openpgp::Error>)
                           -> Result<()> {
        if sig.typ() == SignatureType::Binary
            || sig.typ() == SignatureType::Text
        {
            self.control.status().emit(Status::SigId {
                id: self.compute_signature_id(sig)?,
                creation_time: sig.signature_creation_time()
                    .expect("every valid sig has one"),
            })?;
        }

        // First, GnuPG emits a key considered status as a side-effect
        // of evaluating the trust information.  Emulate that.
        self.control.status().emit(Status::KeyConsidered {
            fingerprint: ka.cert().fingerprint(),
            not_selected: false,
            all_expired_or_revoked: false // XXX: I haven't seen GnuPG set that.
        })?;

        let primary_uid = crate::utils::best_effort_primary_uid(
            self.control.policy(), ka.cert());
        match error {
            None => {
                self.control.status().emit(Status::GoodSig {
                    issuer: ka.fingerprint().into(),
                    primary_uid: primary_uid.as_bytes().to_vec().into(),
                })?;
            },
            Some(openpgp::Error::Expired(at)) => {
                self.control.status().emit(Status::KeyExpired {
                    at: *at,
                })?;

                self.control.status().emit(Status::ExpKeySig {
                    issuer: ka.fingerprint().into(),
                    primary_uid: primary_uid.as_bytes().to_vec().into(),
                })?;
            },
            Some(openpgp::Error::InvalidKey(_)) => {
                self.control.status().emit(Status::RevKeySig {
                    issuer: ka.fingerprint().into(),
                    primary_uid: primary_uid.as_bytes().to_vec().into(),
                })?;
            },
            e => unimplemented!("{:?}", e),
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

        // Check that the issuing key matches the policy (for
        // --assert-pubkey-algo).
        self.control.pubkey_algo_policy.check(self.control, ka.key())?;

        let validity =
            self.control.lookup_certs(
                &Query::ExactKey(ka.cert().key_handle()))?
            .get(0)
            .map(|(validity, _cert)| *validity);

        if let Some(v) = validity.as_ref()
            .filter(|_| self.control.verify_options.uid_validity)
        {
            self.control.warn(format_args!(
                "Good signature from {:?} [{}]", primary_uid, babel::Fish(*v)));
        } else {
            self.control.warn(format_args!(
                "Good signature from {:?}", primary_uid));
        }
        for uid in ka.cert().userids() {
            let uid = String::from_utf8_lossy(uid.value());
            if uid != primary_uid {
                self.control.warn(format_args!(
                    "                    {:?}", uid));
            }
        }

        let print_fingerprint = if validity.map(|v| v.revoked).unwrap_or(false) {
            // XXX
            false
        } else if validity.map(|v| v.expired).unwrap_or(false) {
            self.control.info(format_args!(
                "Note: This key has expired!"));
            true
        } else {
          use ValidityLevel::*;
          match validity.map(|v| v.level) {
            Some(Unknown) | Some(Undefined) => {
                self.control.info(format_args!(
                    "WARNING: This key is not certified with \
                     a trusted signature!"));
                self.control.info(
                    format_args!("         There is no indication that the \
                                  signature belongs to the owner."));
                true
            },

            Some(Never) => {
                self.control.info(format_args!(
                    "WARNING: We do NOT trust this key!"));
                self.control.info(format_args!(
                    "         The signature is probably a FORGERY."));
                // XXX: rc = gpg_error (GPG_ERR_BAD_SIGNATURE);
                false
            },

            Some(Marginal) => {
                self.control.info(format_args!(
                    "WARNING: This key is not certified with \
                     sufficiently trusted signatures!"));
                self.control.info(format_args!(
                    "         It is not certain that the \
                     signature belongs to the owner."));
                true
            },

            Some(Fully) | Some(Ultimate) => {
                false
            },

            None => false, // For gpgv.
          }
        };

        if print_fingerprint || self.control.with_fingerprint() {
            let fp = ka.fingerprint();
            let cert_fp = ka.cert().fingerprint();
            let primary = fp == cert_fp;

            self.control.log(format_args!(
                "Primary key fingerprint: {}", cert_fp.to_spaced_hex()));
            if ! primary {
                self.control.log(format_args!(
                    "     Subkey fingerprint: {}", fp.to_spaced_hex()));
            }
        }

        // Compute validity information.

        // If we are gpg, we want to emit the validity of the cert.
        // To that end, get a view on the trust model at the signature
        // creation time.
        if let Ok(vtm) = self.control.trust_model_impl().with_policy(
            self.control,
            sig.signature_creation_time())
        {
            let acert = crate::common::cert::AuthenticatedCert::new(vtm.as_ref(), ka.cert())?;
            use crate::common::ValidityLevel::*;
            match acert.cert_validity().level {
                Unknown | Undefined =>
                    self.control.status().emit(Status::TrustUndefined {
                        model: Some(vtm.kind()),
                    })?,
                Never =>
                    self.control.status().emit(Status::TrustNever {
                        model: Some(vtm.kind()),
                    })?,
                Marginal =>
                    self.control.status().emit(Status::TrustMarginal {
                        model: vtm.kind(),
                    })?,
                Fully =>
                    self.control.status().emit(Status::TrustFully {
                        model: vtm.kind(),
                    })?,
                Ultimate =>
                    self.control.status().emit(Status::TrustUltimate {
                        model: vtm.kind(),
                    })?,
            }
        }

        Ok(())
    }

    fn emit_bad_signature(&mut self,
                          ka: &ValidErasedKeyAmalgamation<key::PublicParts>,
                          error: Option<&openpgp::Error>)
                          -> Result<()> {
        let validity =
            self.control.lookup_certs(
                &Query::ExactKey(ka.cert().key_handle()))?
            .get(0)
            .map(|(validity, _cert)| *validity);

        match error {
            Some(openpgp::Error::Expired(at)) => {
                self.control.status().emit(Status::KeyExpired {
                    at: *at,
                })?;
            },
            _ => (),
        }

        let primary_uid = crate::utils::best_effort_primary_uid(
            self.control.policy(), ka.cert());
        self.control.status().emit(Status::BadSig {
            issuer: ka.fingerprint().into(),
            primary_uid: primary_uid.as_bytes().to_vec().into(),
        })?;

        if let Some(v) = &validity {
            self.control.warn(format_args!(
                "BAD signature from {:?} [{}]", primary_uid, babel::Fish(*v)));
        } else {
            self.control.warn(format_args!(
                "BAD signature from {:?}", primary_uid));
        }

        self.bad_checksums += 1;
        Ok(())
    }

    fn print_sigs(&mut self, results: &[VerificationResult]) -> Result<()> {
        use crate::print_error_chain;
        use self::VerificationError::*;
        for result in results {
            match result {
                Ok(GoodChecksum { sig, ka, .. }) => {
                    if self.emit_signature(sig, ka, None, ka.cert().cert(),
                                           false)?
                    {
                        continue;
                    }
                    self.emit_good_signature(sig, ka, None)?;

                    self.good_signatures += 1;
                },
                Err(MalformedSignature { sig, error, .. }) => {
                    if self.emit_signature(sig, None, None, None, false)?
                    {
                        continue;
                    }
                    if self.control.verbose() > 0 {
                        safe_eprintln!("Malformed signature:");
                        print_error_chain(error);
                    }
                    self.broken_signatures += 1;
                    continue;
                },
                Err(MissingKey { sig, .. }) => {
                    if self.emit_signature(sig, None, ErrSigStatus::MissingKey,
                                           None, false)?
                    {
                        if self.control.verbose() > 0 {
                            let issuer = sig.get_issuers().get(0)
                                .expect("missing key checksum has an issuer")
                                .to_string();
                            safe_eprintln!("No key to check signature from {}",
                                      issuer);
                        }
                        self.unknown_checksums += 1;
                        continue;
                    }
                    unreachable!("emit_signature with error short-circuits")
                },
                Err(UnboundKey { sig, cert, error, .. }) => {
                    // XXX does this case map to KEY_CONSIDERED not_selected?
                    // XXX apparently not...
                    if self.emit_signature(
                        sig, None, ErrSigStatus::BadPublicKey, *cert,
                        false)?
                    {
                        if self.control.verbose() > 0 {
                            safe_eprintln!("Signing key on {} is not bound:",
                                      cert.fingerprint());
                            print_error_chain(error);
                        }
                        continue;
                    }
                    unreachable!("emit_signature with error short-circuits")
                },
                Err(BadKey { sig, ka, error, .. }) => {
                    let e =
                        if ! ka.binding_signature().key_flags()
                        .map(|f| f.for_signing()).unwrap_or(false)
                    {
                        Some(ErrSigStatus::WrongKeyUsage)
                    } else {
                        None
                    };

                    if self.emit_signature(sig, ka, e, ka.cert().cert(), false)?
                    {
                        continue;
                    }

                    let mut sig = (*sig).clone();
                    let openpgp_error = error.downcast_ref::<openpgp::Error>();
                    if sig.verify(ka.key()).is_ok()
                        && self.control.policy().signature(
                            &sig, HashAlgoSecurity::CollisionResistance).is_ok()
                    {
                        self.emit_good_signature(&sig, ka, openpgp_error)?;
                    } else {
                        self.emit_bad_signature(ka, openpgp_error)?;
                    }
                    // ExpKeySig, RevKeySig

                    if self.control.verbose() > 0 {
                        safe_eprintln!("Signing key on {} is bad:",
                                  ka.cert().fingerprint());
                        print_error_chain(error);
                    }

                    continue;
                },
                Err(BadSignature { sig, ka, error }) => {
                    if self.emit_signature(sig, ka, None, ka.cert().cert(),
                                           false)?
                    {
                        continue;
                    }
                    let openpgp_error = error.downcast_ref::<openpgp::Error>();
                    self.emit_bad_signature(ka, openpgp_error)?;

                    if self.control.verbose() > 0 {
                        print_error_chain(error);
                    }

                    continue;
                }
            };
        }

        Ok(())
    }
}

impl<'a, 'store> VerificationHelper for VHelper<'a, 'store> {
    fn inspect(&mut self, pp: &openpgp::parse::PacketParser) -> Result<()> {
        match &pp.packet {
            Packet::Literal(p) if ! self.control.list_only => {
                self.control.status().emit(
                    Status::Plaintext {
                        format: p.format(),
                        timestamp: p.date(),
                        filename: p.filename().map(|n| n.to_vec()),
                    })?;

                if let BodyLength::Full(l) = pp.header().length() {
                    // Subtract the Literal Data packet's header
                    // fields from the packet length.
                    let body_len = *l - (
                        1
                            + (1 + p.filename().map(|f| f.len() as u32)
                               .unwrap_or(0))
                            + 4);
                    self.control.status().emit(
                        Status::PlaintextLength(body_len))?;
                }
            },
            _ => (),
        }

        Ok(())
    }

    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        Ok(ids.iter().filter_map(|id| self.control.keydb().lookup_by_cert_or_subkey(id).ok())
           .flatten()
           .filter_map(|cert| cert.to_cert().ok().cloned())
           .collect())
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for layer in structure {
            match layer {
                MessageLayer::Compression { .. } => (),
                MessageLayer::Encryption { .. } => (),
                MessageLayer::SignatureGroup { ref results } =>
                    self.print_sigs(results)?,
            }
        }

        if self.bad_signatures + self.bad_checksums == 0
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

const GCRY_PK_USAGE_SIGN: u8 = 1;   // Good for signatures.
const GCRY_PK_USAGE_ENCR: u8 = 2;   // Good for encryption.
const GCRY_PK_USAGE_CERT: u8 = 4;   // Good to certify other keys.
const GCRY_PK_USAGE_AUTH: u8 = 8;   // Good for authentication.
const GCRY_PK_USAGE_UNKN: u8 = 128; // Unknown usage flag.

/// Converts KeyFlags to a gcrypt-style key usage octet.
fn key_flags_to_usage(f: KeyFlags) -> u8 {
    0
    | if f.for_signing()              { GCRY_PK_USAGE_SIGN } else { 0 }
    | if f.for_transport_encryption() { GCRY_PK_USAGE_ENCR } else { 0 }
    | if f.for_storage_encryption()   { GCRY_PK_USAGE_ENCR } else { 0 }
    | if f.for_certification()        { GCRY_PK_USAGE_CERT } else { 0 }
    | if f.for_authentication()       { GCRY_PK_USAGE_AUTH } else { 0 }
    | if ! f
        .clear_signing()
        .clear_transport_encryption()
        .clear_storage_encryption()
        .clear_certification()
        .clear_authentication()
        .clear_group_key()
        .clear_split_key()
        .is_empty()                   { GCRY_PK_USAGE_UNKN } else { 0 }
}
