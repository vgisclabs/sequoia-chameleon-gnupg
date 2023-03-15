use std::{
    io,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::ValidCert,
    crypto::{Password, S2K, SessionKey},
    KeyID,
    packet::{
        key,
        Key,
        skesk::SKESK4,
    },
    policy::Policy,
    serialize::{Serialize, stream::*},
    types::SignatureType,
};
use sequoia_ipc as ipc;

use crate::{
    babel,
    common::{Common, Query, TrustModel, Validity},
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
    if let Err(e) = do_encrypt(config, args, symmetric, sign) {
        config.error(format_args!(
            "{}: encryption failed: {}",
            args.get(0).map(String::as_str).unwrap_or("-"),
            e));
    }
    Ok(())
}

fn do_encrypt(config: &crate::Config, args: &[String],
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
    for recipient in &config.remote_user {
        // XXX: honor constraints
        let query = crate::trust::Query::from(recipient.name.as_str());

        // XXX: One remote user may expand to multiple recipients.  In
        // the case of groups, this is a feature.  In the case of
        // trust models, it depends.  For example, with
        // --always-trust, expanding to multiple recipients is a
        // problem.  We should be more diligent here.
        let mut found_one = false;
        let mut invalid_key_reason = InvalidKeyReason::Unspecified;

        // Get the candidates, and sort by descending validity.
        let mut candidates = config.lookup_certs(&query)?;
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
                        found_one_subkey
                    },
                    all_expired_or_revoked:
                    if let InvalidKeyReason::NotTrusted = invalid_key_reason {
                        // If the key is not trusted, GnuPG doesn't
                        // set the flags.
                        false
                    } else {
                        found_one_subkey // XXX: not quite
                    },
                })?;

            found_one |= found_one_subkey;
            if found_one {
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
        = keys.iter().map(Recipient::from).collect();

    let mut sink = if let Some(name) = config.outfile() {
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
    let cipher = config.def_cipher;
    let sk = SessionKey::new(cipher.key_size()?);
    de_vs_compliant &=
        config.de_vs_producer.symmetric_algorithm(cipher).is_ok();

    // Now do our trick, maybe.
    if symmetric {
        let s2k = S2K::default();
        let cacheid = crate::agent::cacheid_of(&s2k);

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

    let encryptor = Encryptor::with_session_key(message, cipher, sk)?
        .add_recipients(recipients);

    let mut message = encryptor.build()?;

    if let Some(algo) = config.compress_algo {
        message = Compressor::new(message).algo(algo).build()?;
    }

    if sign {
        // First, get the signers.
        let (mut signers, signers_desc) =
            rt.block_on(crate::sign::get_signers(config))?;

        let timestamp = openpgp::types::Timestamp::now();
        let hash_algo = config.def_digest;
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
    let mut agent = config.connect_agent().await?;
    Ok(crate::agent::get_passphrase(
        &mut agent,
        &cacheid, &None, None, None, false, 0, false,
        |_agent, response| if let ipc::assuan::Response::Inquire {
            keyword, parameters } = response
        {
            match keyword.as_str() {
                "PINENTRY_LAUNCHED" => {
                    let p = parameters.unwrap_or_default();
                    let info = String::from_utf8_lossy(&p);
                    let _ = config.status().emit(
                        Status::PinentryLaunched(info.into()));
                    None
                },
                _ => None,
            }
        } else {
            None
        }
    ).await?)
}

fn do_we_trust(config: &crate::Config,
               query: &Query,
               cert: &ValidCert,
               key: &Key<key::PublicParts, key::UnspecifiedRole>,
               validity: Validity)
               -> Result<bool>
{
    let ok = match validity {
        _ if config.trust_model == Some(TrustModel::Always) => {
            if config.verbose > 0 {
                config.info(format_args!(
                    "No trust check due to '--trust-model always' option"));
            }
            true
        },

        Validity::Marginal => {
            config.info(format_args!(
                "{}: There is limited assurance this key belongs \
                 to the named user",
                key.keyid()));
            true
        },

        Validity::Fully => {
            if config.verbose > 0 {
                config.info(format_args!(
                    "This key probably belongs to the named user"));
            }
            true
        },

        Validity::Ultimate => {
            if config.verbose > 0 {
                config.info(format_args!("This key belongs to us"));
            }
            true
        },

        Validity::Never => {
            config.info(format_args!(
                "{}: This key is bad!  It has been marked as untrusted!",
                key.keyid()));
            false
        },

        Validity::Unknown | Validity::Undefined
        // XXX these are flags in GnuPG
            | Validity::Revoked | Validity::Expired =>
        {
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

        eprintln!();
        eprintln!("{}  {}/{} {} {}",
                  if primary { "pub" } else { "sub" },
                  babel::Fish((key.pk_algo(),
                               key.mpis().bits().unwrap_or_default(),
                               &crate::list_keys::get_curve(key.mpis()))),
                  KeyID::from(&fp),
                  {
                      let creation_date =
                          chrono::DateTime::<chrono::Utc>::from(
                              key.creation_time());
                      creation_date.format("%Y-%m-%d")
                  },
                  utils::best_effort_uid_for_query(config.policy(), cert, query));

        eprintln!(" Primary key fingerprint: {}", cert_fp.to_spaced_hex());
        if ! primary {
            eprintln!("      Subkey fingerprint: {}", fp.to_spaced_hex());
        }
        eprintln!();

        if validity == Validity::Never {
            eprintln!(
                "This key is bad!  It has been marked as untrusted!  If you\n\
                 *really* know what you are doing, you may answer the next\n\
                 question with yes.");
        } else {
            eprintln!(
                "It is NOT certain that the key belongs to the person named\n\
                 in the user ID.  If you *really* know what you are doing,\n\
                 you may answer the next question with yes.");
        }
        eprintln!();

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
