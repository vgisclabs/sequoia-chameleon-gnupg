use std::{
    io,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::{ValidCert, Preferences},
    crypto::{Password, S2K, SessionKey},
    KeyID,
    packet::{
        key,
        Key,
        skesk::SKESK4,
    },
    parse::Parse,
    policy::Policy,
    serialize::{Serialize, stream::*},
    types::*,
};

use crate::{
    babel,
    common::{
        Common,
        PublicKeyAlgorithmAndSize,
        Query,
        TrustModel,
        Validity,
        ValidityLevel,
    },
    compliance::Compliance,
    status::{self, Status, InvalidKeyReason},
    utils,
};

/// Dispatches the --encrypt command.
///
/// Creates encrypted messages, optionally signing the plaintext
/// first.
pub fn cmd_encrypt(config: &crate::Config, args: &[String],
                   symmetric: bool, sign: bool)
                   -> Result<()>
{
    if let Err(e) = do_encrypt(config, args,
                               config.outfile(),
                               symmetric, sign)
    {
        config.error(format_args!(
            "{}: encryption failed: {}",
            args.get(0).map(String::as_str).unwrap_or("-"),
            e));
    }
    Ok(())
}

/// Dispatches the --encrypt-files command.
pub fn cmd_encrypt_files(config: &crate::Config, args: &[String])
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

    for plaintext in inputs {
        config.status().emit(Status::FileStart {
            what: crate::status::FileStartOperation::Encrypt,
            name: &plaintext,
        })?;

        if let Err(e) = do_encrypt(config, &[plaintext.into()],
                                   Some(&format!("{}.gpg", plaintext)),
                                   false, false)
        {
            config.error(format_args!(
                "{}: encryption failed: {}",
                args.get(0).map(String::as_str).unwrap_or("-"),
                e));
        }

        config.status().emit(Status::FileDone)?;
    }

    Ok(())
}

fn do_encrypt(config: &crate::Config, args: &[String],
              outfile: Option<&String>,
              symmetric: bool, sign: bool)
              -> Result<()>
{
    let rt = tokio::runtime::Runtime::new()?;

    let policy = config.policy();
    let filenames =
        if args.is_empty() { vec!["-".into()] } else { args.to_vec() };
    let mut de_vs_compliant = true;

    if filenames.len() != 1 {
        return Err(anyhow::anyhow!("Only a single file name is allowed"));
    }

    // First, get the recipients.
    let mut keys: Vec<Key<_, _>> = vec![];
    let mut cipher_preferences: Vec<_> = [
        SymmetricAlgorithm::AES256,
        SymmetricAlgorithm::AES192,
        SymmetricAlgorithm::AES128,
        SymmetricAlgorithm::Camellia256,
        SymmetricAlgorithm::Camellia192,
        SymmetricAlgorithm::Camellia128,
        SymmetricAlgorithm::Blowfish,
        SymmetricAlgorithm::Twofish,
        SymmetricAlgorithm::CAST5,
        SymmetricAlgorithm::IDEA,
        SymmetricAlgorithm::TripleDES,
    ].iter().copied().filter(|a| a.is_supported()).collect();
    let mut digest_preferences: Vec<_> = [
        HashAlgorithm::SHA512,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA224,
    ].iter().copied().filter(|a| a.is_supported()).collect();

    for recipient in &config.remote_user {
        // XXX: honor constraints
        let query: crate::trust::Query = recipient.name.parse()?;

        // XXX: One remote user may expand to multiple recipients.  In
        // the case of groups, this is a feature.  In the case of
        // trust models, it depends.  For example, with
        // --always-trust, expanding to multiple recipients is a
        // problem.  We should be more diligent here.
        let mut found_one = false;
        let mut invalid_key_reason = InvalidKeyReason::Unspecified;

        // Get the candidates, and sort by descending validity.
        let mut candidates = if recipient.from_file {
            use std::sync::Arc;
            vec![(ValidityLevel::Fully.into(),
                  Arc::new(openpgp::Cert::from_file(&recipient.name)?.into()))]
        } else {
            config.lookup_certs(&query)?
        };
        candidates.sort_by(|a, b| a.0.cmp(&b.0).reverse());

        for (validity, cert) in candidates {
            let vcert = cert.with_policy(policy, config.now())
                .context(format!("Key {:X} is not valid", cert.key_handle()))?;

            let mut found_one_subkey = false;
            let mut key_query = vcert.keys();

            // If we have an exact key query ("<FP>!"), use exactly
            // that key.
            if let crate::Query::ExactKey(h) = &query {
                key_query = key_query.key_handle(h.clone());
            } else {
                key_query = key_query
                    .for_storage_encryption()
                    .for_transport_encryption();
            }

            // XXX: Figure out how exactly GnuPG behaves with bang
            // expressions, e.g. can we then use keys that are not
            // alive? Revoked? What if the algorithm is not supported?

            for key in key_query.alive().revoked(false).supported() {
                if ! do_we_trust(config, &query, &vcert, key.key(), validity)? {
                    invalid_key_reason = InvalidKeyReason::NotTrusted;
                    continue;
                }

                keys.push(key.key().clone());
                found_one_subkey = true;
                de_vs_compliant &= config.de_vs_producer.key(&key).is_ok();
            }

            // Bit of a hack here: if this query is not going thru the
            // trust model, suppress the KEY_CONSIDERED line.  This
            // isn't quite the right place to do that, but let's roll
            // with it for now.
            if ! query.by_key_handle() {
                // GnuPG always reports the cert fingerprint even if a
                // subkey has been given as recipient.
                config.status().emit(
                    Status::KeyConsidered {
                        fingerprint: cert.fingerprint(),
                        not_selected:
                        if let InvalidKeyReason::NotTrusted = invalid_key_reason {
                            // If the key is not trusted, GnuPG doesn't
                            // set the flags.
                            false
                        } else {
                            ! found_one_subkey
                        },
                        all_expired_or_revoked:
                        if let InvalidKeyReason::NotTrusted = invalid_key_reason {
                            // If the key is not trusted, GnuPG doesn't
                            // set the flags.
                            false
                        } else {
                            ! found_one_subkey // XXX: not quite
                        },
                    })?;
            }

            found_one |= found_one_subkey;
            if found_one {
                // If the recipients has preferences, compute the
                // intersection with our list.
                if let Some(p) = vcert.preferred_hash_algorithms() {
                    digest_preferences.retain(|a| p.contains(a));
                }
                if let Some(p) = vcert.preferred_symmetric_algorithms() {
                    cipher_preferences.retain(|a| p.contains(a));
                }

                break;
            }
        }

        if ! found_one {
            config.status().emit(
                Status::InvalidRecipient {
                    reason: invalid_key_reason,
                    query: &query,
                })?;

            let error = crate::error_codes::Error::GPG_ERR_UNUSABLE_PUBKEY;
            if let InvalidKeyReason::Unspecified = invalid_key_reason {
                config.warn(format_args!("{}: skipped: {}", query, error));
            }
            config.status().emit(
                Status::Failure {
                    location: "encrypt",
                    error,
                })?;
            return Err(error)?;
        }
    }

    let recipients: Vec<Recipient>
        = keys.iter().rev().map(Recipient::from).collect();

    let mut sink = if let Some(name) = outfile {
        utils::create(config, name)?
    } else {
        Box::new(io::stdout())
    };

    // Note: we use crypto::Signers backed by the gpg-agent.
    // Currently, it is not safe to use these from async contexts,
    // because they evaluate futures using a runtime, which may not be
    // nested.  Therefore, the following code may not be run in an
    // async context.
    let mut message = Message::new(&mut sink);
    if config.armor {
        message = Armorer::new(message).build()?;
    }

    // If we want to encrypt with a password, we need to do that now.
    // The reason is that we want to produce the SKESK ourselves so
    // that we can cache the password in the agent.  To that end, fix
    // cipher and session key here.

    let cipher = if let Some(def_cipher) = config.def_cipher {
        // This overrides the recipients preferences, but we may warn
        // about that, unless we deem ourselves an expert.
        if ! config.expert && ! cipher_preferences.contains(&def_cipher) {
            config.warn(format_args!(
                "WARNING: forcing symmetric cipher {} ({}) \
                 violates recipient preferences",
                babel::Fish(def_cipher), u8::from(def_cipher)));
        }

        def_cipher
    } else {
        // Select best cipher from the recipient's preferences.
        cipher_preferences.get(0).cloned().unwrap_or_default()
    };

    let sk = SessionKey::new(cipher.key_size()?);
    de_vs_compliant &=
        config.de_vs_producer.symmetric_algorithm(cipher).is_ok();

    // Now do our trick, maybe.
    if symmetric {
        let s2k = S2K::default();
        let cacheid = crate::gpg_agent::cacheid_of(&s2k);

        let p = rt.block_on(ask_password(config, cacheid))?;
        // XXX: We emit the SKESK first.  Naive consumers may
        // therefore ask for a password even if they could use a PKESK
        // to decrypt the message.  If that turns out to be the case,
        // we could produce and emit the PKESKs before this
        // conditional.
        let skesk = SKESK4::with_password(cipher, cipher, s2k, &sk, &p)?;
        openpgp::Packet::from(skesk).serialize(&mut message)?;

        // Symmetric and asymmetric encryption voids compliance.
        de_vs_compliant &= recipients.is_empty();
    }

    let encryptor = Encryptor2::with_session_key(message, cipher, sk)?
        .add_recipients(recipients);

    let mut message = encryptor.build()?;

    if let Some(algo) = config.compress_algo
        .filter(|&a| a != CompressionAlgorithm::Uncompressed)
    {
        message = Compressor::new(message).algo(algo).build()?;
    }

    if sign {
        // First, get the signers.
        let (mut signers, signers_desc) =
            rt.block_on(crate::sign::get_signers(config))?;

        let timestamp = config.now().try_into()?;
        let hash_algo = config.def_digest.unwrap_or_default();
        let mut signer =
            Signer::new(message, signers.pop().expect("at least one"))
            .creation_time(timestamp)
            .hash_algo(hash_algo)?;
        for additional_signer in signers {
            signer = signer.add_signer(additional_signer);
        }

        message = signer.build()?;
        config.status().emit(Status::BeginSigning(hash_algo))?;

        let class = SignatureType::Binary;
        for (pk_algo, fingerprint) in signers_desc {
            config.status().emit(
                Status::SigCreated {
                    typ: status::SigType::Standard,
                    pk_algo,
                    hash_algo,
                    class,
                    timestamp,
                    fingerprint,
                })?;
        }
    }

    if true { // XXX wrapping
        message = LiteralWriter::new(message).build()?;
    }

    if de_vs_compliant
        && crate::gnupg_interface::EMIT_ENCRYPTION_COMPLIANCE
    {
        config.status().emit(
            Status::EncryptionComplianceMode(Compliance::DeVs))?;
    }
    config.status().emit(Status::BeginEncryption {
        mdc_method: status::MDCMethod::SEIPDv1,
        cipher,
    })?;

    std::io::copy(&mut utils::open(config, &filenames[0])?, &mut message)?;
    message.finalize()?;

    config.status().emit(Status::EndEncryption)?;

    Ok(())
}

async fn ask_password(config: &crate::Config<'_>, cacheid: Option<String>)
                      -> Result<Password> {
    use sequoia_gpg_agent::PinentryMode;
    let mut agent = config.connect_agent().await?;

    if matches!(config.pinentry_mode, PinentryMode::Loopback)
        && config.static_passphrase.borrow().is_none()
    {
        // GnuPG emits this twice, for good measure.  The second time
        // we emit it from Config::get_passphrase.
        config.status().emit(Status::InquireMaxLen(100))?;
    }

    Ok(config.get_passphrase(
        &mut agent,
        &cacheid, &None, None, None, false, 0, false, false,
        |p| {
            let info = String::from_utf8_lossy(&p);
            config.status().emit(
                Status::PinentryLaunched(info.into()))?;
            Ok(())
        },
    ).await?)
}

fn do_we_trust(config: &crate::Config,
               query: &Query,
               cert: &ValidCert,
               key: &Key<key::PublicParts, key::UnspecifiedRole>,
               validity: Validity)
               -> Result<bool>
{
    use ValidityLevel::*;
    let ok = match validity.level {
        _ if config.trust_model == Some(TrustModel::Always) => {
            if config.verbose > 0 {
                config.info(format_args!(
                    "No trust check due to '--trust-model always' option"));
            }
            true
        },

        _ if validity.revoked || validity.expired => {
            config.info(format_args!(
                "{}: There is no assurance this key belongs to the named user",
                key.keyid()));
            false
        },

        Marginal => {
            config.info(format_args!(
                "{}: There is limited assurance this key belongs \
                 to the named user",
                key.keyid()));
            true
        },

        Fully => {
            if config.verbose > 0 {
                config.info(format_args!(
                    "This key probably belongs to the named user"));
            }
            true
        },

        Ultimate => {
            if config.verbose > 0 {
                config.info(format_args!("This key belongs to us"));
            }
            true
        },

        Never => {
            config.info(format_args!(
                "{}: This key is bad!  It has been marked as untrusted!",
                key.keyid()));
            false
        },

        Unknown | Undefined => {
            config.info(format_args!(
                "{}: There is no assurance this key belongs to the named user",
                key.keyid()));
            false
        },
    };

    if ! ok && ! config.batch {
        let fp = key.fingerprint();
        let cert_fp = cert.fingerprint();
        let primary = fp == cert_fp;

        safe_eprintln!();
        safe_eprintln!("{}  {}/{} {} {}",
                  if primary { "pub" } else { "sub" },
                  babel::Fish(PublicKeyAlgorithmAndSize::from(key)),
                  KeyID::from(&fp),
                  {
                      let creation_date =
                          chrono::DateTime::<chrono::Utc>::from(
                              key.creation_time());
                      creation_date.format("%Y-%m-%d")
                  },
                  query.best_effort_uid(config.policy(), cert));

        safe_eprintln!(" Primary key fingerprint: {}", cert_fp.to_spaced_hex());
        if ! primary {
            safe_eprintln!("      Subkey fingerprint: {}", fp.to_spaced_hex());
        }
        safe_eprintln!();

        if validity.level == ValidityLevel::Never {
            safe_eprintln!(
                "This key is bad!  It has been marked as untrusted!  If you\n\
                 *really* know what you are doing, you may answer the next\n\
                 question with yes.");
        } else {
            safe_eprintln!(
                "It is NOT certain that the key belongs to the person named\n\
                 in the user ID.  If you *really* know what you are doing,\n\
                 you may answer the next question with yes.");
        }
        safe_eprintln!();

        config.status().emit(
            Status::UserIdHint {
                keyid: key.keyid(),
                userid: cert.primary_userid().ok().map(|u| u.userid()),
            })?;

        if config.prompt_yN(
            "untrusted_key.override".into(),
            format_args!("Use this key anyway?"))?
        {
            return Ok(true);
        }
    }

    Ok(ok)
}
