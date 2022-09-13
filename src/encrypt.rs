use std::{
    io,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    serialize::stream::*,
    types::SignatureType,
};

use crate::{
    common::Common,
    status::{self, Status},
    utils,
};

/// Dispatches the --encrypt command.
///
/// Creates encrypted messages, optionally signing the plaintext
/// first.
pub fn cmd_encrypt(config: &crate::Config, args: &[String],
                   sign: bool)
                   -> Result<()>
{
    let policy = config.policy();
    let filenames =
        if args.is_empty() { vec!["-".into()] } else { args.to_vec() };

    if filenames.len() != 1 {
        return Err(anyhow::anyhow!("Only a single file name is allowed"));
    }

    // First, get the recipients.
    let mut recipients: Vec<Recipient> = vec![];
    for recipient in &config.remote_user {
        // XXX: honor constraints
        let query = crate::trust::Query::from(recipient.name.as_str());

        // XXX: One remote user may expand to multiple recipients.  In
        // the case of groups, this is a feature.  In the case of
        // trust models, it depends.  For example, with
        // --always-trust, expanding to multiple recipients is a
        // problem.  We should be more diligent here.
        let mut found_one = false;
        for cert in config.lookup_certs(&query)? {
            // GnuPG always reports the cert fingerprint even if a
            // subkey has been given as recipient.
            config.status().emit(
                Status::KeyConsidered {
                    fingerprint: cert.fingerprint(),
                    not_selected: false,
                    all_expired_or_revoked: false,
                })?;

            let vcert = cert.with_policy(policy, None)
                .context(format!("Key {:X} is not valid", cert.key_handle()))?;

            let mut found_one_subkey = false;
            let mut key_query = vcert.keys();

            // If we have an exact key query ("<FP>!"), use exactly
            // that key.
            if let crate::Query::ExactKey(h) = &query {
                key_query = key_query.key_handle(h.clone());
            } else {
                key_query = key_query
                    .for_transport_encryption()
                    .for_transport_encryption();
            }

            // XXX: Figure out how exactly GnuPG behaves with bang
            // expressions, e.g. can we then use keys that are not
            // alive? Revoked? What if the algorithm is not supported?

            for key in key_query.alive().revoked(false).supported() {
                recipients.push(key.key().into());
                found_one_subkey = true;
            }

            if ! found_one_subkey {
                return Err(anyhow::anyhow!(
                    "Key {:X} is not encrypting-capable", cert.key_handle()))?;
            }

            found_one = true;
        }

        if ! found_one {
            return Err(anyhow::anyhow!(
                "No encrypting-capable key found for {}", query))?;
        }
    }

    let mut sink = if let Some(name) = config.outfile() {
        utils::create(config, name)?
    } else {
        Box::new(io::stdout())
    };

    let mut message = Message::new(&mut sink);
    if config.armor {
        message = Armorer::new(message).build()?;
    }

    let cipher = config.def_cipher;
    let encryptor = Encryptor::for_recipients(message, recipients)
        .symmetric_algo(cipher);
    // XXX symmetric
    let mut message = encryptor.build()?;

    if let Some(algo) = config.compress_algo {
        message = Compressor::new(message).algo(algo).build()?;
    }

    if sign {
        // First, get the signers.
        let (mut signers, signers_desc) = crate::sign::get_signers(config)?;

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

    config.status().emit(Status::BeginEncryption {
        mdc_method: status::MDCMethod::SEIPDv1,
        cipher,
    })?;

    std::io::copy(&mut utils::open(config, &filenames[0])?, &mut message)?;
    message.finalize()?;

    config.status().emit(Status::EndEncryption)?;

    Ok(())
}
