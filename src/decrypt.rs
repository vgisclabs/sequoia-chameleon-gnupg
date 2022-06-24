use std::{
    io,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Fingerprint,
    crypto::{
        self,
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
    control::Common,
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

    let transaction = || -> Result<DHelper> {
        let helper = DHelper::new(config, VHelper::new(config, 1));
        let mut d = DecryptorBuilder::from_reader(message)?
            .with_policy(policy, None, helper)?;
        io::copy(&mut d, &mut sink)?;
        let helper = d.into_helper();

        helper.config.status().emit(Status::DecryptionOkay)?;
        // For compatibility reasons we issue GOODMDC also for AEAD messages.
        helper.config.status().emit(Status::GoodMDC)?;

        Ok(helper)
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

    fn emit_session_key(&self, algo: SymmetricAlgorithm, sk: SessionKey)
                        -> Result<()>
    {
        self.config.status().emit(
            Status::DecryptionInfo {
                use_mdc: self.used_mdc,
                sym_algo: algo,
                aead_algo: None, // XXX
            })?;

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
        //let keyid = keypair.public().fingerprint().into();
        let kek = agent.decrypt(&keypair, pkesk.esk()).await?;

        // XXX: This is a bit rough.  We get the raw plaintext from
        // Agent::decrypt, but there is no nice API to encrypt a PKESK
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
                self.emit_session_key(algo, sk)?;
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
        use openpgp::crypto::S2K;
        let ctx = self.config.ipc()?;
        let mut agent = self.config.connect_agent().await?;

        // First, try public key encryption.
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            if keyid.is_wildcard() {
                continue; // XXX
            }

            // See if we have the recipient cert.
            let keyid: openpgp::KeyHandle = keyid.into();
            let cert = match self.config.keydb().by_subkey(&keyid) {
                Some(c) => c,
                None => continue,
            };
            let vcert = match cert.with_policy(self.config.policy(), None) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Get the subkey.
            let key = match vcert.keys().key_handle(keyid)
                .for_transport_encryption()
                .for_storage_encryption()
                .next()
            {
                Some(k) => k,
                None => continue, // Key was not encryption-capable.
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
            return Err(anyhow::anyhow!("decryption failed: No secret key"));
        }

        // GnuPG asks for each SKESK separately, and uses the first
        // eight bytes of salt from the S2K.  We ask for one password
        // and try it with every SKESK.  We xor the first eight bytes
        // of salt from every S2K, matching GnuPG's result in the
        // common case of having just one SKESK.
        let mut cacheid = [0; 8];
        for skesk in skesks {
            let s2k = match skesk {
                SKESK::V4(skesk) => skesk.s2k(),
                SKESK::V5(skesk) => skesk.s2k(),
                _ => continue,
            };
            #[allow(deprecated)]
            let salt = match s2k {
                S2K::Iterated { salt, .. } => &salt[..8],
                S2K::Salted { salt, .. } => &salt[..8],
                _ => continue,
            };
            cacheid.iter_mut().zip(salt.iter()).for_each(|(p, s)| *p ^= *s);
        }
        let cacheid = format!("S{}", hex::encode(&cacheid));

        let mut error: Option<String> = None;
        loop {
            let p =
                crate::agent::get_passphrase(
                    &mut agent,
                    &cacheid, error, None, None, false, 0, false,
                    |info| {
                        let info = String::from_utf8_lossy(&info);
                        let _ = self.config.status().emit(
                            Status::PinentryLaunched(info.into()));
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
                    self.emit_session_key(algo, sk)?;
                    return Ok(None);
                }
            }

            // Error message to display next time.
            error = Some("Decryption failed".to_string());
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

impl<'a> DecryptionHelper for DHelper<'a> {
    fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                  sym_algo: Option<SymmetricAlgorithm>,
                  decrypt: D) -> Result<Option<openpgp::Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        self.config.status().emit(Status::BeginDecryption)?;

        let rt = tokio::runtime::Runtime::new()?;
        let r =
            rt.block_on(self.async_decrypt(pkesks, skesks, sym_algo, decrypt));

        if r.is_err() {
            self.config.status().emit(Status::DecryptionFailed)?;
        }

        r
    }
}

impl<'a> VerificationHelper for DHelper<'a> {
    fn inspect(&mut self, pp: &openpgp::parse::PacketParser) -> Result<()> {
        match &pp.packet {
            Packet::SEIP(p) => self.used_mdc = p.version() == 1,
            Packet::Literal(p) => {
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
