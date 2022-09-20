use std::{
    io,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Fingerprint,
    KeyHandle,
    crypto::{
        self,
        Decryptor as _,
        SessionKey,
    },
    fmt::hex,
    packet::prelude::*,
    packet::header::BodyLength,
    types::*,
    packet::key::*,
    parse::{
        Parse,
        stream::*,
    },
};
use sequoia_ipc as ipc;
use ipc::gnupg::{
    KeyPair,
};
use crate::{
    babel,
    common::Common,
    status::Status,
    utils,
    verify::*,
};

/// Dispatches the --decrypt command.
///
/// Assume that the input is an encrypted message and decrypt (and if
/// signed, verify the signature on) it.  This command differs from
/// the default operation, as it never writes to the filename which is
/// included in the file and it rejects files which don't begin with
/// an encrypted message.
pub fn cmd_decrypt(config: &crate::Config, args: &[String])
                  -> Result<()>
{

    let filename = args.get(0).cloned().unwrap_or_else(|| "-".into());
    let message = utils::open(config, &filename)?;

    let policy = config.policy();

    // XXX: Currently, there is no nice way to disable armoring when
    // using the streaming decryptor.

    let mut sink = if let Some(name) = config.outfile() {
        utils::create(config, name)?
    } else {
        Box::new(io::stdout())
    };

    let transaction = || -> Result<()> {
        let helper = DHelper::new(config, VHelper::new(config, 1));
        let message = DecryptorBuilder::from_reader(message)?;
        let mut d = match message.with_policy(policy, config.now(), helper) {
            Ok(d) => d,
            Err(e) => if config.list_only {
                return Ok(());
            } else {
                return Err(e);
            },
        };

        if ! config.list_only {
            io::copy(&mut d, &mut sink)?;
        }
        let helper = d.into_helper();

        if ! config.list_only {
            helper.config.status().emit(Status::DecryptionOkay)?;
            // For compatibility reasons we issue GOODMDC also for AEAD messages.
            helper.config.status().emit(Status::GoodMDC)?;
        }

        Ok(())
    };

    let r = transaction();
    config.status().emit(Status::EndDecryption)?;
    r?;

    Ok(())
}

struct DHelper<'a> {
    config: &'a crate::Config,
    vhelper: VHelper<'a>,
    used_mdc: bool,
}

impl<'a> DHelper<'a> {
    fn new(config: &'a crate::Config, vhelper: VHelper<'a>)
           -> Self {
        DHelper {
            config,
            vhelper,
            used_mdc: false,
        }
    }

    fn decryption_successful(&self, algo: SymmetricAlgorithm, sk: SessionKey)
                             -> Result<()>
    {
        self.config.status().emit(Status::BeginDecryption)?;

        if ! self.config.list_only {
            self.config.status().emit(
                Status::DecryptionInfo {
                    use_mdc: self.used_mdc,
                    sym_algo: algo,
                    aead_algo: None, // XXX
                })?;
        }

        if self.config.show_session_key {
            self.config.warn(format_args!(
                "session key: '{}:{}'",
                u8::from(algo), hex::encode(&sk)));
            self.config.status().emit(
                Status::SessionKey {
                    algo,
                    sk,
                })?;
        }

        Ok(())
    }

    /// Tries to decrypt the given PKESK packet with `keypair` and try
    /// to decrypt the packet parser using `decrypt`.
    async fn try_decrypt<D>(&self,
                            agent: &mut sequoia_ipc::gnupg::Agent,
                            cert: &Cert,
                            pkesk: &PKESK,
                            sym_algo: Option<SymmetricAlgorithm>,
                            keypair: KeyPair,
                            decrypt: &mut D)
                            -> Result<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        let kek = agent.decrypt(&keypair, pkesk.esk()).await
            .map_err(|e| {
                // XXX: All errors here likely indicate that the key
                // is not available.  But, there could be other
                // failure modes.
                let _ = self.config.status().emit(
                    Status::NoSeckey {
                        issuer: keypair.public().keyid(),
                    });
                e
            })?;

        // XXX: This is a bit rough.  We get the raw plaintext from
        // Agent::decrypt, but there is no nice API to decrypt a PKESK
        // with that.  What we can do, is use a shim that implements
        // the low-level crypto::Decryptor and merely returns the
        // plaintext that we already have.

        struct KEK(KeyPair, Option<SessionKey>);
        impl crypto::Decryptor for KEK {
            fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
                self.0.public()
            }
            fn decrypt(&mut self,
                       _ciphertext: &crypto::mpi::Ciphertext,
                       _plaintext_len: Option<usize>)
                       -> Result<SessionKey> {
                Ok(self.1.take().expect("KEK::decrypted called twice"))
            }
        }

        // Decrypt the PKESK with our shim.
        let mut decryptor = KEK(keypair, Some(kek));
        match pkesk.decrypt(&mut decryptor, sym_algo)
            .and_then(|(algo, sk)| {
                if decrypt(algo, &sk) { Some((algo, sk)) } else { None }
            })
        {
            Some((algo, sk)) => {
                if ! self.config.list_only {
                    self.config.status().emit(
                        Status::DecryptionKey {
                            fp: decryptor.0.public().fingerprint(),
                            cert_fp: cert.fingerprint(),
                            owner_trust: self.config.trustdb
                                .get_ownertrust(&cert.fingerprint())
                                .unwrap_or(OwnerTrustLevel::Undefined.into()),
                        })?;
                }

                self.decryption_successful(algo, sk)?;
                Ok(Some(cert.fingerprint()))
            },
            None => Ok(None),
        }
    }

    async fn async_decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                              sym_algo: Option<SymmetricAlgorithm>,
                              mut decrypt: D)
                              -> Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        // Before doing anything else, try if we were given a session
        // key.
        if let Some(sk) = &self.config.override_session_key {
            if decrypt(sk.cipher(), sk.key()) {
                self.decryption_successful(sk.cipher(), sk.key().clone())?;
                return Ok(None);
            }
            // XXX: Does GnuPG keep trying if this fails?
        }

        let ctx = self.config.ipc()?;
        let mut agent = self.config.connect_agent().await?;

        let emit_no_seckey = |keyid: &openpgp::KeyID| -> Result<()> {
            self.config.status().emit(
                Status::NoSeckey {
                    issuer: keyid.clone(),
                })?;
                Ok(())
        };


        // First, try public key encryption.
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            if keyid.is_wildcard() {
                continue; // XXX
            }

            let handle = KeyHandle::from(keyid);
            if let Some(cert) = self.config.keydb().get(&handle) {
                let key = cert.keys().key_handle(handle.clone())
                    .next().expect("the indices to be consistent");
                let creation_time =
                    chrono::DateTime::<chrono::Utc>::from(key.creation_time());

                self.config.warn(format_args!(
                    "encrypted with {}-bit {} key, ID {}, created {}\n      {:?}",
                    key.mpis().bits().unwrap_or(0),
                    babel::Fish(pkesk.pk_algo()),
                    pkesk.recipient(),
                    creation_time.format("%Y-%m-%d"),
                    utils::best_effort_primary_uid(self.config.policy(), &cert)));
            } else {
                self.config.warn(format_args!(
                    "encrypted with {} key, ID {}",
                    babel::Fish(pkesk.pk_algo()), pkesk.recipient()));
            }

            self.config.status().emit(
                Status::EncTo {
                    keyid: keyid.clone(),
                    pk_algo: Some(pkesk.pk_algo()),
                    pk_len: None,
                })?;

            // See if we have the recipient cert.
            let cert = match self.config.keydb().by_subkey(&handle) {
                Some(c) => c,
                None => {
                    emit_no_seckey(keyid)?;
                    continue;
                },
            };
            let vcert = match cert.with_policy(self.config.policy(),
                                               self.config.now()) {
                Ok(c) => c,
                Err(_) => {
                    emit_no_seckey(keyid)?;
                    continue;
                },
            };

            self.config.status().emit(
                Status::KeyConsidered {
                    fingerprint: cert.fingerprint(),
                    not_selected: false,
                    all_expired_or_revoked: false,
                })?;

            // Get the subkey.
            let key = match vcert.keys().key_handle(handle)
                .for_transport_encryption()
                .for_storage_encryption()
                .next()
            {
                Some(k) => k,
                None => {
                    // Key was not encryption-capable.
                    emit_no_seckey(keyid)?;
                    continue;
                },
            };

            // And just try to decrypt it using the agent.
            let keypair = KeyPair::new(&ctx, &key)?
                .with_cert(&vcert);
            if let Ok(fp) = self.try_decrypt(
                &mut agent, &cert, pkesk, sym_algo, keypair, &mut decrypt)
                .await
            {
                // Success!
                return Ok(fp);
            }
        }

        // Then, try password-based encryption.
        if skesks.is_empty() {
            self.config.status().emit(Status::BeginDecryption)?;
            return Err(anyhow::anyhow!("decryption failed: No secret key"));
        }

        let cacheid = crate::agent::cacheid_over_all(skesks);

        let mut error: Option<String> = None;
        loop {
            let p =
                crate::agent::get_passphrase(
                    &mut agent,
                    &cacheid, &error, None, None, false, 0, false,
                    |_agent, response| if let ipc::assuan::Response::Inquire {
                        keyword, parameters } = response
                    {
                        match keyword.as_str() {
                            "PINENTRY_LAUNCHED" => {
                                let p = parameters.unwrap_or_default();
                                let info = String::from_utf8_lossy(&p);
                                let _ = self.config.status().emit(
                                    Status::PinentryLaunched(info.into()));
                                None
                            },
                            "PASSPHRASE" =>
                                self.config.static_passprase.take()
                                .map(|encrypted| encrypted.map(
                                    |decrypted| decrypted.clone())),
                            _ => None,
                        }
                    } else {
                        None
                    }
                ).await?;

            for skesk in skesks {
                if let Some((algo, sk)) = skesk.decrypt(&p).ok()
                    .and_then(|(algo, sk)| { if decrypt(algo, &sk) {
                        Some((algo, sk))
                    } else {
                        None
                    }})
                {
                    self.decryption_successful(algo, sk)?;
                    return Ok(None);
                }
            }

            // Error message to display next time.
            error = Some("Decryption failed".to_string());
            if let Some(cacheid) = &cacheid {
                // Make gpg-agent forget the bad passphrase.
                crate::agent::forget_passphrase(
                    &mut agent,
                    &cacheid,
                    |info| {
                        let info = String::from_utf8_lossy(&info);
                        let _ = self.config.status().emit(
                            Status::PinentryLaunched(info.into()));
                    },).await?;
            }
        }
    }
}

impl<'a> DecryptionHelper for DHelper<'a> {
    fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                  sym_algo: Option<SymmetricAlgorithm>,
                  decrypt: D) -> Result<Option<openpgp::Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        let rt = tokio::runtime::Runtime::new()?;
        let r =
            rt.block_on(self.async_decrypt(pkesks, skesks, sym_algo, decrypt));

        if r.is_err() && ! self.config.list_only {
            self.config.status().emit(Status::DecryptionFailed)?;
        }

        r
    }
}

impl<'a> VerificationHelper for DHelper<'a> {
    fn inspect(&mut self, pp: &openpgp::parse::PacketParser) -> Result<()> {
        match &pp.packet {
            Packet::SEIP(p) => self.used_mdc = p.version() == 1,
            Packet::Literal(p) if ! self.config.list_only => {
                self.config.status().emit(
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
                    self.config.status().emit(
                        Status::PlaintextLength(body_len))?;
                }
            },
            _ => (),
        }
        self.vhelper.inspect(pp)
    }

    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        self.vhelper.get_certs(ids)
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        self.vhelper.check(structure)
    }
}
