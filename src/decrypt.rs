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
    policy::Policy,
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

use sequoia_cert_store as cert_store;
use cert_store::Store;

use crate::{
    babel,
    common::Common,
    compliance::Compliance,
    status::Status,
    trust::OwnerTrustLevel,
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

    // Note: we use crypto::Decryptors backed by the gpg-agent.
    // Currently, it is not safe to use these from async contexts,
    // because they evaluate futures using a runtime, which may not be
    // nested.  Therefore, the following code may not be run in an
    // async context.
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

/// Dispatches the --decrypt-files command.
pub fn cmd_decrypt_files(config: &crate::Config, args: &[String])
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

    let policy = config.policy();
    for ciphertext in inputs {
        config.status().emit(Status::FileStart {
            what: crate::status::FileStartOperation::Encrypt,
            name: &ciphertext,
        })?;

        // Note: we use crypto::Decryptors backed by the gpg-agent.
        // Currently, it is not safe to use these from async contexts,
        // because they evaluate futures using a runtime, which may not be
        // nested.  Therefore, the following code may not be run in an
        // async context.
        let transaction = || -> Result<()> {
            let message = utils::open(config, &ciphertext)?;
            let mut sink = utils::create(
                config, &utils::make_outfile_name(ciphertext)?)?;

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

        if let Err(e) = transaction() {
            config.error(format_args!("{}", e));
        }
        config.status().emit(Status::EndDecryption)?;
        config.status().emit(Status::FileDone)?;
    }

    Ok(())
}

pub struct DHelper<'a, 'store> {
    config: &'a crate::Config<'store>,
    vhelper: VHelper<'a, 'store>,
    used_mdc: bool,
    filename: String,

    // We compute compliance with compliance::DeVSProducer.
    de_vs_compliant: bool,
}

impl<'a, 'store> DHelper<'a, 'store> {
    pub fn new(config: &'a crate::Config<'store>, vhelper: VHelper<'a, 'store>)
               -> Self {
        DHelper {
            config,
            vhelper,
            used_mdc: false,
            filename: Default::default(),
            de_vs_compliant: true,
        }
    }

    /// Indicates that the encryption container uses MDC.
    pub fn uses_mdc(&mut self) {
        self.used_mdc = true;
    }

    fn decryption_successful(&self, algo: SymmetricAlgorithm, sk: SessionKey)
                             -> Result<()>
    {
        if self.config.verbose > 0 && ! self.config.list_only {
            self.config.warn(format_args!("{} encrypted data",
                                          babel::Fish(algo)));
            self.config.warn(format_args!("original file name='{}'",
                                          self.filename));
        }

        self.config.status().emit(Status::BeginDecryption)?;

        if ! self.config.list_only {
            if self.de_vs_compliant
                && self.config.de_vs_producer.symmetric_algorithm(algo).is_ok()
                && crate::gnupg_interface::EMIT_DECRYPTION_COMPLIANCE
            {
                self.config.status().emit(
                    Status::DecryptionComplianceMode(Compliance::DeVs))?;
            }

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
        // We provide all the information upfront before we try any
        // decryption.
        for skesk in skesks {
            let (cipher, aead) = match skesk {
                SKESK::V4(s) => (s.symmetric_algo(), None),
                SKESK::V5(s) => (s.symmetric_algo(), Some(s.aead_algo())),
                _ => continue,
            };
            if ! self.config.quiet {
                self.config.info(format_args!(
                    "{}.{} encrypted session key",
                    babel::Fish(cipher),
                    aead.map(|a| babel::Fish(a).to_string())
                        .unwrap_or_else(|| "CFB".into()),
                ));
            }
        }

        if ! skesks.is_empty() {
            if ! self.config.quiet {
                self.config.info(format_args!(
                    "encrypted with {} passphrase{}",
                    skesks.len(),
                    if skesks.len() != 1 { "s" } else { "" },
                ));
            }
        }

        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            let handle = KeyHandle::from(keyid);
            if ! self.config.quiet && self.config.verbose > 0 {
                self.config.warn(format_args!(
                    "public key is {}", handle));
            }

            if let Some(cert) = self.config.keydb().lookup_by_key(&handle).ok()
                .and_then(|certs: Vec<_>| certs.into_iter().next())
                .and_then(|cert| cert.as_cert().ok())
            {
                if ! self.config.quiet && self.config.verbose > 0 {
                    self.config.warn(format_args!(
                        "using subkey {} instead of primary key {}", handle,
                        cert.keyid()));
                }

                let key = cert.keys().key_handle(handle.clone())
                    .next().expect("the indices to be consistent");
                let creation_time =
                    chrono::DateTime::<chrono::Utc>::from(key.creation_time());

                if ! self.config.quiet {
                    self.config.warn(format_args!(
                        "encrypted with {}-bit {} key, ID {}, created {}\n      {:?}",
                        key.mpis().bits().unwrap_or(0),
                        babel::Fish(pkesk.pk_algo()),
                        pkesk.recipient(),
                        creation_time.format("%Y-%m-%d"),
                        utils::best_effort_primary_uid(self.config.policy(), &cert)));
                }
            } else {
                if ! self.config.quiet {
                    self.config.warn(format_args!(
                        "encrypted with {} key, ID {}",
                        babel::Fish(pkesk.pk_algo()), pkesk.recipient()));
                }
            }

            self.config.status().emit(
                Status::EncTo {
                    keyid: keyid.clone(),
                    pk_algo: Some(pkesk.pk_algo()),
                    // According to doc/DETAILS, GnuPG always
                    // reports the length as 0.
                    pk_len: None,
                })?;
        }

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
        let mut success = None;
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            if keyid.is_wildcard() {
                continue; // XXX
            }
            let handle = KeyHandle::from(keyid);

            // See if we have the recipient cert.
            let cert = match self.config.keydb().lookup_by_key(&handle).ok()
                .and_then(|c| c.into_iter().next())
                .and_then(|c| c.as_cert().ok())
            {
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
            if let Ok(maybe_fp) = self.try_decrypt(
                &mut agent, &cert, pkesk, sym_algo, keypair, &mut decrypt)
                .await
            {
                // Success!
                success = Some(maybe_fp);
                break;
            }
        }

        if let Some(maybe_fp) = success {
            return Ok(maybe_fp);
        }

        // Then, try password-based encryption.
        if skesks.is_empty() {
            self.config.status().emit(Status::BeginDecryption)?;
            return Err(anyhow::anyhow!("decryption failed: No secret key"));
        }

        let cacheid = crate::agent::cacheid_over_all(skesks);

        let mut error: Option<String> = None;
        loop {
            // There is a bit of an impedance mismatch because we're
            // trying to be nicer to the user.  GnuPG loops over the
            // SKESKs and asks for a passphrase each time.  We ask
            // once and try it with all SKESKS.  Hence, we emit all
            // the NEED_PASSPHRASE_SYM lines beforehand.
            for skesk in skesks {
                let (cipher, s2k) = match skesk {
                    SKESK::V4(s) => (s.symmetric_algo(), s.s2k().clone()),
                    SKESK::V5(s) => (s.symmetric_algo(), s.s2k().clone()),
                    _ => continue,
                };
                if ! self.config.list_only {
                    self.config.status().emit(Status::NeedPassphraseSym {
                        cipher,
                        s2k,
                    })?;
                }
            }

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
                                self.config.static_passphrase.take()
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

impl<'a, 'store> DecryptionHelper for DHelper<'a, 'store> {
    fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                  sym_algo: Option<SymmetricAlgorithm>,
                  decrypt: D) -> Result<Option<openpgp::Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        // Compute decryption compliance with DeVS.
        self.de_vs_compliant &=
            self.config.override_session_key.is_none() // Voids compliance.
            && (pkesks.is_empty() || skesks.is_empty()) // Both => void.
            && pkesks.iter().all(|pkesk| { // Check all recipients.
                let certs = if let Ok(certs) = self.config.keydb()
                    .lookup_by_key(&pkesk.recipient().into())
                {
                    certs
                } else {
                    return false;
                };

                for cert in certs.into_iter().filter_map(|cert| cert.as_cert().ok()) {
                    if let Some(key) = cert.keys()
                        .with_policy(&self.config.de_vs_producer, None)
                        .key_handle(pkesk.recipient()).next()
                    {
                        if self.config.de_vs_producer.key(&key).is_ok() {
                            return true;
                        }
                    }
                }
                false
            });

        let rt = tokio::runtime::Runtime::new()?;
        let r =
            rt.block_on(self.async_decrypt(pkesks, skesks, sym_algo, decrypt));

        if r.is_err() && ! self.config.list_only {
            self.config.status().emit(Status::DecryptionFailed)?;
        }

        r
    }
}

impl<'a, 'store> VerificationHelper for DHelper<'a, 'store> {
    fn inspect(&mut self, pp: &openpgp::parse::PacketParser) -> Result<()> {
        match &pp.packet {
            Packet::SEIP(p) => self.used_mdc = p.version() == 1,
            Packet::Literal(p) if ! self.config.list_only => {
                self.filename = String::from_utf8_lossy(
                    p.filename().unwrap_or_default()).into();
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
