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
        Password,
        SessionKey,
    },
    fmt::hex,
    packet::prelude::*,
    packet::header::BodyLength,
    types::*,
    parse::{
        Parse,
        stream::*,
    },
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
    let helper = DHelper::new(config, VHelper::new(config, 1));
    let mut d = DecryptorBuilder::from_reader(message)?
        .with_policy(policy, None, helper)?;
    io::copy(&mut d, &mut sink)?;
    let helper = d.into_helper();

    helper.config.status().emit(Status::DecryptionOkay)?;
    // For compatibility reasons we issue GOODMDC also for AEAD messages.
    helper.config.status().emit(Status::GoodMDC)?;
    helper.config.status().emit(Status::EndDecryption)?;


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
    fn try_decrypt<D>(&self, pkesk: &PKESK,
                      sym_algo: Option<SymmetricAlgorithm>,
                      mut keypair: Box<dyn crypto::Decryptor>,
                      decrypt: &mut D)
                      -> Result<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        //let keyid = keypair.public().fingerprint().into();
        match pkesk.decrypt(&mut *keypair, sym_algo)
            .and_then(|(algo, sk)| {
                if decrypt(algo, &sk) { Some((algo, sk)) } else { None }
            })
        {
            Some((algo, sk)) => {
                self.emit_session_key(algo, sk)?;
                unimplemented!()
            },
            None => Ok(None),
        }
    }
}

impl<'a> DecryptionHelper for DHelper<'a> {
    fn decrypt<D>(&mut self, _: &[PKESK], skesks: &[SKESK],
                  _sym_algo: Option<SymmetricAlgorithm>,
                  mut decrypt: D) -> Result<Option<openpgp::Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        self.config.status().emit(Status::BeginDecryption)?;

        let password = Password::from("streng geheim");
        for skesk in skesks {
            if let Some((algo, sk)) = skesk.decrypt(&password).ok()
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

        Ok(None)
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
