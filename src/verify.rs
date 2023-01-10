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
    packet::Signature,
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

use crate::{
    babel,
    common::Common,
    status::{Status, ErrSigStatus, NoDataReason},
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

    if let Err(e) = do_it() {
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
    } else {
        Ok(())
    }
}

pub struct VHelper<'a> {
    control: &'a crate::Config,
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

impl<'a> VHelper<'a> {
    pub fn new(control: &'a crate::Config, signatures: usize)
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

        match error {
            None => {
                self.control.status().emit(Status::GoodSig {
                    issuer: ka.fingerprint().into(),
                    primary_uid:
                    ka.cert().primary_userid().map(|u| u.value().into())
                        .unwrap_or_else(|_| b"unknown"[..].into()),
                })?;
            },
            Some(openpgp::Error::Expired(at)) => {
                self.control.status().emit(Status::KeyExpired {
                    at: *at,
                })?;

                self.control.status().emit(Status::ExpKeySig {
                    issuer: ka.fingerprint().into(),
                    primary_uid:
                    ka.cert().primary_userid().map(|u| u.value().into())
                        .unwrap_or_else(|_| b"unknown"[..].into()),
                })?;
            },
            Some(openpgp::Error::InvalidKey(_)) => {
                self.control.status().emit(Status::RevKeySig {
                    issuer: ka.fingerprint().into(),
                    primary_uid:
                    ka.cert().primary_userid().map(|u| u.value().into())
                        .unwrap_or_else(|_| b"unknown"[..].into()),
                })?;
            },
            e => unimplemented!("{:?}", e),
        }

        let primary_uid =
            ka.cert().primary_userid().map(|u| {
                String::from_utf8_lossy(u.value()).to_string()
            })
            .unwrap_or_else(|_| ka.fingerprint().to_string());
        self.control.warn(format_args!(
            "Good signature from {:?}", primary_uid));
        for uid in ka.cert().userids() {
            let uid = String::from_utf8_lossy(uid.value());
            if uid != primary_uid {
                self.control.warn(format_args!(
                    "                    {:?}", uid));
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

        // Compute validity information.

        // First, GnuPG emits a key considered status as a side-effect
        // of evaluating the trust information.  Emulate that.
        self.control.status().emit(Status::KeyConsidered {
            fingerprint: ka.cert().fingerprint(),
            not_selected: false,
            all_expired_or_revoked: false // XXX: I haven't seen GnuPG set that.
        })?;

        // If we are gpg, we want to emit the validity of the cert.
        // To that end, get a view on the trust model at the signature
        // creation time.
        if let Ok(vtm) = self.control.trust_model_impl().with_policy(
            self.control,
            sig.signature_creation_time())
        {
            let acert = crate::common::cert::AuthenticatedCert::new(vtm.as_ref(), ka.cert())?;
            use crate::common::Validity::*;
            match acert.cert_validity() {
                Revoked | Expired => (),
                Unknown | Undefined =>
                    self.control.status().emit(Status::TrustUndefined)?,
                Never =>
                    self.control.status().emit(Status::TrustNever)?,
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
        match error {
            Some(openpgp::Error::Expired(at)) => {
                self.control.status().emit(Status::KeyExpired {
                    at: *at,
                })?;
            },
            _ => (),
        }

        self.control.status().emit(Status::BadSig {
            issuer: ka.fingerprint().into(),
            primary_uid:
            ka.cert().primary_userid().map(|u| u.value().into())
                .unwrap_or_else(|_| b"unknown"[..].into()),
        })?;

        self.control.warn(format_args!(
            "BAD signature from {:?}",
            ka.cert().primary_userid().map(|u| {
                String::from_utf8_lossy(u.value()).to_string()
            })
                .unwrap_or_else(|_|
                                ka.fingerprint().to_string())));

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
                        eprintln!("Malformed signature:");
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
                            eprintln!("No key to check signature from {}",
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
                            eprintln!("Signing key on {} is not bound:",
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
                        eprintln!("Signing key on {} is bad:",
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

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        Ok(ids.iter().map(|id| self.control.keydb().get(id).cloned())
           .filter_map(|v| v).collect())
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
