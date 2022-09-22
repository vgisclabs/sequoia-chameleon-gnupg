use std::{
    io,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    crypto::{S2K, SessionKey},
    packet::skesk::SKESK4,
    policy::Policy,
    serialize::{Serialize, stream::*},
    types::SignatureType,
};
use sequoia_ipc as ipc;

use crate::{
    common::Common,
    compliance::Compliance,
    status::{self, Status},
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
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(real_cmd_encrypt(config, args, symmetric, sign))
}

async fn real_cmd_encrypt(config: &crate::Config, args: &[String],
                          symmetric: bool, sign: bool)
                          -> Result<()>
{
    let policy = config.policy();
    let filenames =
        if args.is_empty() { vec!["-".into()] } else { args.to_vec() };
    let mut de_vs_compliant = true;

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
                    .for_transport_encryption()
                    .for_transport_encryption();
            }

            // XXX: Figure out how exactly GnuPG behaves with bang
            // expressions, e.g. can we then use keys that are not
            // alive? Revoked? What if the algorithm is not supported?

            for key in key_query.alive().revoked(false).supported() {
                recipients.push(key.key().into());
                found_one_subkey = true;
                de_vs_compliant &= config.de_vs_producer.key(&key).is_ok();
            }

            if ! found_one_subkey {
                return Err(anyhow::anyhow!(
                    "Key {:X} is not encryption-capable", cert.key_handle()))?;
            }

            found_one = true;
        }

        if ! found_one {
            return Err(anyhow::anyhow!(
                "No encryption-capable key found for {}", query))?;
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
        let mut agent = config.connect_agent().await?;
        let p =
            crate::agent::get_passphrase(
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
            ).await?;

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
