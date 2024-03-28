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

use sequoia_gpg_agent as gpg_agent;
use gpg_agent::{
    KeyPair,
};

use sequoia_cert_store as cert_store;
use cert_store::Store;

use crate::{
    gpg_agent::PinentryMode,
    babel,
    common::Common,
    compliance::Compliance,
    error_codes,
    status::{
        NoDataReason,
        Status,
        UnexpectedReason,
    },
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

    match transaction() {
        Ok(()) => config.status().emit(Status::EndDecryption)?,
        Err(e) => {
            match e.downcast_ref::<openpgp::Error>() {
                Some(openpgp::Error::MalformedMessage(m)) => {
                    if m.ends_with("not expected") {
                        // Wrong data encountered.
                        config.status().emit(
                            Status::Unexpected(UnexpectedReason::Unspecified))?;
                        config.status().emit(
                            Status::Failure {
                                location: "decrypt",
                                error: error_codes::Error::GPG_ERR_UNEXPECTED,
                            })?;
                        config.error(format_args!(
                            "decrypt_message failed: Unexpected error"));
                    } else {
                        // No data encountered.
                        config.status().emit(
                            Status::NoData(NoDataReason::ExpectedPacket))?;
                        config.status().emit(
                            Status::Failure {
                                location: "decrypt",
                                error: error_codes::Error::GPG_ERR_MINUS_ONE,
                            })?;
                        config.error(format_args!(
                            "decrypt_message failed: Unknown system error"));
                    }

                    // Don't emit Status::EndDecryption.
                    return Err(e);
                },
                _ => (),
            }
            config.status().emit(Status::EndDecryption)?;
            return Err(e);
        },
    }

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
            de_vs_compliant: false,
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
                            cert: &Cert,
                            pkesk: &PKESK,
                            sym_algo: Option<SymmetricAlgorithm>,
                            mut keypair: KeyPair,
                            decrypt: &mut D)
                            -> Result<(Option<Fingerprint>,
                                       SymmetricAlgorithm,
                                       SessionKey)>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        let kek = keypair.decrypt(pkesk.esk(),
                                  sym_algo.and_then(|a| a.key_size().ok()))?;

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
                Ok((Some(cert.fingerprint()), algo, sk))
            },
            None => Err(anyhow::anyhow!("decryption failed")),
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

        let mut agent = self.config.connect_agent().await?;
        let secret_keys = agent.list_keys().await.unwrap_or_default();

        // First, try public key encryption.
        let mut success = None;
        let mut pkesks_results: Vec<(&PKESK, Option<error_codes::Error>)> =
            pkesks.into_iter().map(|p| (p, None)).collect();
        for (pkesk, error) in pkesks_results.iter_mut() {
            let keyid = pkesk.recipient();
            let handle = KeyHandle::from(keyid);
            if ! self.config.quiet && self.config.verbose > 0 {
                self.config.warn(format_args!(
                    "public key is {}", handle));
            }

            self.config.status().emit(
                Status::EncTo {
                    keyid: pkesk.recipient().clone(),
                    pk_algo: Some(pkesk.pk_algo()),
                    // According to doc/DETAILS, GnuPG always
                    // reports the length as 0.
                    pk_len: None,
                })?;

            if success.is_some() {
                continue;
            }

            // Before doing anything else, try if we were given a session
            // key.
            if let Some(sk) = &self.config.override_session_key {
                if decrypt(sk.cipher(), sk.key()) {
                    success = Some((None, sk.cipher(), sk.key().clone()));
                    continue;
                }
            }

            let keyid = pkesk.recipient();
            if keyid.is_wildcard() {
                continue; // XXX
            }
            let handle = KeyHandle::from(keyid);

            // See if we have the recipient cert.  We *don't* emit the
            // KeyConsidered here, we only do it if we really have a
            // secret.
            let cert = match self.config.keydb().lookup_by_cert_or_subkey(&handle).ok()
                .and_then(|c| c.into_iter().next())
                .and_then(|c| c.to_cert().ok().cloned())
            {
                Some(c) => c,
                None => {
                    *error = Some(error_codes::Error::GPG_ERR_NO_SECKEY);
                    continue;
                },
            };
            let vcert = match cert.with_policy(self.config.policy(),
                                               self.config.now()) {
                Ok(c) => c,
                Err(_) => {
                    *error = Some(error_codes::Error::GPG_ERR_NO_SECKEY);
                    continue;
                },
            };

            // Get the subkey.
            let key = match vcert.keys().key_handle(handle)
                .for_transport_encryption()
                .for_storage_encryption()
                .next()
            {
                Some(k) => k,
                None => {
                    // Key was not encryption-capable.
                    *error = Some(error_codes::Error::GPG_ERR_NO_SECKEY);
                    continue;
                },
            };

            if secret_keys.lookup_by_key(key.key()).is_none() {
                *error = Some(error_codes::Error::GPG_ERR_NO_SECKEY);
                continue;
            }

            if self.config.list_only {
                continue;
            }

            // GnuPG emits this line twice in `get_session_key`.
            // First to get the secret key using `get_seckey`, then
            // once more in `get_it`.
            for _ in 0..2 {
                self.config.status().emit(
                    Status::KeyConsidered {
                        fingerprint: cert.fingerprint(),
                        not_selected: false,
                        all_expired_or_revoked: false,
                    })?;
            }

            // And just try to decrypt it using the agent.
            let mut pair = agent.keypair(&key)?
                .with_cert(&vcert);

            // See if we have a static password to loop back to the
            // agent.
            if let (crate::gpg_agent::PinentryMode::Loopback, Some(p)) =
                (&self.config.pinentry_mode,
                 self.config.static_passphrase.borrow().as_ref())
            {
                pair = pair.with_password(p.clone());
            }

            if let Ok(r) = self.try_decrypt(
                &cert, pkesk, sym_algo, pair, &mut decrypt).await
            {
                // Success!
                success = Some(r);
                continue;
            } else {
                // XXX: map and handle other errors.
                *error = Some(error_codes::Error::GPG_ERR_NO_SECKEY);
            }
        }

        // Emit the PKESK infos.  GnuPG construct a linked list, hence
        // we reverse the order.  First, print all those keys we tried
        // but failed to decrypt the message with.
        for (p, err) in pkesks_results.iter().rev()
            .filter(|(_p, r)| r.is_some())
        {
            self.emit_pkesk_info(p, err)?;
        }

        // Then print the keys that we didn't try or successfully used.
        for (p, err) in pkesks_results.iter().rev()
            .filter(|(_p, r)| r.is_none())
        {
            self.emit_pkesk_info(p, err)?;
        }

        // Compute decryption compliance with DeVS.
        self.de_vs_compliant =
            success.is_some() // PK decryption successful.
            && self.config.override_session_key.is_none() // Voids compliance.
            && crate::compliance::CRYPTO_LIBRARY_IS_DE_VS
            && (pkesks.is_empty() || skesks.is_empty()) // Both => void.
            && {
                let mut compliant = true;

                // XXX: check all skesk ciphers.

                // Check all recipients.
                for pkesk in pkesks {
                    let certs = if let Ok(certs) = self.config
                        .lookup_by_cert_or_subkey(&pkesk.recipient().into())
                    {
                        certs
                    } else {
                        compliant = false;
                        continue;
                    };

                    for cert in certs.into_iter()
                        .filter_map(|cert| cert.to_cert().ok().cloned())
                    {
                        if let Some(key) = cert.keys()
                            .with_policy(&self.config.de_vs_producer, None)
                            .key_handle(pkesk.recipient()).next()
                        {
                            compliant = compliant &&
                                self.config.de_vs_producer.key(&key).is_ok();
                        }
                    }
                }

                compliant
            };

        if let Some((maybe_fp, algo, sk)) = success {
            self.decryption_successful(algo, sk)?;
            return Ok(maybe_fp);
        }

        if self.config.list_only {
            // If we --list-only, we'll never invoke
            // decryption_successful, so print the status message
            // here.
            self.config.status().emit(Status::BeginDecryption)?;
            // And short-circuit so that we don't ask for passwords.
            return Ok(None);
        }

        // See if we were given a session key.  We do that here again
        // in case there were no PKESK packets.
        if let Some(sk) = &self.config.override_session_key {
            if decrypt(sk.cipher(), sk.key()) {
                self.decryption_successful(sk.cipher(), sk.key().clone())?;
                return Ok(None);
            }
        }

        // Then, try password-based encryption.
        if skesks.is_empty() {
            self.config.status().emit(Status::BeginDecryption)?;
            return Err(anyhow::anyhow!("decryption failed: No secret key"));
        }

        let cacheid = crate::gpg_agent::cacheid_over_all(skesks);

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

            if matches!(self.config.pinentry_mode, PinentryMode::Loopback)
                && self.config.static_passphrase.borrow().is_none()
            {
                // GnuPG emits this twice, for good measure.  The second time
                // we emit it from Config::get_passphrase.
                self.config.status().emit(Status::InquireMaxLen(100))?;
            }

            let p =
                self.config.get_passphrase(
                    &mut agent,
                    &cacheid, &error, None, None, false, 0, false, false,
                    |p| {
                        let info = String::from_utf8_lossy(&p);
                        self.config.status().emit(
                            Status::PinentryLaunched(info.into()))?;
                        Ok(())
                    },
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
                agent.forget_passphrase(
                    &cacheid,
                    |info| {
                        let info = String::from_utf8_lossy(&info);
                        let _ = self.config.status().emit(
                            Status::PinentryLaunched(info.into()));
                    },).await?;
            }

            // If we use loopback pinentry, we supplied the one
            // passphrase that we had and it failed to decrypt the
            // message.  Bail instead of spinning forever.
            if let PinentryMode::Loopback = self.config.pinentry_mode {
                return Err(anyhow::anyhow!("decryption failed: No secret key"));
            }
        }
    }

    /// Emits the KEY_CONSIDERED lines and human-readable information
    /// about the recipients.
    fn emit_pkesk_info(&self, pkesk: &PKESK, err: &Option<error_codes::Error>)
                       -> Result<()>
    {
        let keyid = pkesk.recipient();
        let handle = KeyHandle::from(keyid);

        if ! self.config.quiet {
            if let Some(cert) = self.config.lookup_by_cert_or_subkey(&handle).ok()
                .and_then(|certs: Vec<_>| certs.into_iter().next())
                .and_then(|cert| cert.to_cert().ok().cloned())
            {
                if self.config.verbose > 0 {
                    self.config.warn(format_args!(
                        "using subkey {} instead of primary key {}", handle,
                        cert.keyid()));
                }

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
        }

        if let Some(error_codes::Error::GPG_ERR_NO_SECKEY) = err {
            self.config.status().emit(
                Status::NoSeckey {
                    issuer: keyid.clone(),
                })?;
        }

        Ok(())
    }
}

impl<'a, 'store> DecryptionHelper for DHelper<'a, 'store> {
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
