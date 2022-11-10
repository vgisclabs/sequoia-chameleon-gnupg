//! Miscellaneous commands.

use std::{
    io::{self, Read},
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::{
        CertParser,
        CertRevocationBuilder,
    },
    policy::NullPolicy,
    types::*,
    Packet,
    parse::{
        Parse,
        PacketParser,
        PacketParserResult,
        stream::*,
    },
    serialize::{
        Serialize,
        stream::{Message, Armorer},
    },
};

use crate::{
    babel,
    colons,
    common::Common,
    status::{Status, NoDataReason},
    utils,
};

/// Dispatches the implicit command.
pub fn cmd_implicit(config: &crate::Config, args: &[String])
                    -> Result<()>
{
    config.warn(format_args!("WARNING: no command supplied.  \
                              Trying to guess what you mean ..."));

    #[derive(Debug)]
    enum Action {
        ListKeys,
        Decrypt,
        DetachVerify,
        InlineVerify,
    }

    if args.len() > 1 {
        return Err(anyhow::anyhow!("Expected only one argument, got more"));
    }

    let filename = args.get(0).cloned().unwrap_or_else(|| "-".into());
    let mut input = utils::open(config, &filename)?;

    // Peek at the data to decide what to do.
    const PEEK: usize = 4096;
    let mut buf = Vec::with_capacity(PEEK);
    input.by_ref().take(PEEK.try_into().unwrap()).read_to_end(&mut buf)?;

    let mut action = None;
    {
        let mut ppr = match
            PacketParser::from_reader(io::Cursor::new(&buf[..])) {
                Ok(ppr) => ppr,
                Err(e) => {
                    config.status().emit(Status::NoData(
                        NoDataReason::ExpectedPacket))?;
                    config.status().emit(Status::NoData(
                        NoDataReason::InvalidPacket))?;
                    return Err(e);
                },
            };

        while let PacketParserResult::Some(pp) = ppr {
            match pp.packet {
                Packet::PublicKey(_) | Packet::SecretKey(_) => {
                    action = Some(Action::ListKeys);
                    break;
                },
                Packet::OnePassSig(_) => {
                    action = Some(Action::InlineVerify);
                    break;
                },
                Packet::Signature(_) => {
                    action = Some(Action::DetachVerify);
                    break;
                },
                Packet::PKESK(_) | Packet::SKESK(_) => {
                    action = Some(Action::Decrypt);
                    break;
                },
                _ => (),
            }
            let (_packet, ppr_) = pp.next()?;
            ppr = ppr_;
        }
    }

    // We took up to PEEK bytes from input, now we need to put it
    // back.
    let input: Box<dyn io::Read + Send + Sync> = if buf.len() < PEEK {
        // input is exhausted, we don't need to worry about that.
        Box::new(io::Cursor::new(buf))
    } else {
        // Prepend buf to input.
        Box::new(io::Cursor::new(buf).chain(input))
    };

    use Action::*;
    match action {
        None =>
            Err(anyhow::anyhow!("I don't know what to do with this data")),
        Some(ListKeys) => {
            let certs =
                CertParser::from_reader(input)?.collect::<Result<Vec<_>>>()?;
            crate::list_keys::list_keys(
                config, certs.iter(), vec![], false, false, io::stdout())
        },
        Some(InlineVerify) => {
            let mut sink = if let Some(name) = config.outfile() {
                utils::create(config, name)?
            } else {
                Box::new(io::sink())
            };
            let helper = crate::verify::VHelper::new(config, 1);
            let mut v = VerifierBuilder::from_reader(input)?
                .with_policy(config.policy(), config.now(), helper)?;
            io::copy(&mut v, &mut sink)?;
            Ok(())
        },
        a => Err(anyhow::anyhow!("Implicit action on {:?} not implemented", a)),
    }
}

/// Dispatches the --list-config command.
pub fn cmd_list_config(config: &crate::Config, args: &[String])
                       -> Result<()>
{
    if args.len() > 1 {
        return Err(anyhow::anyhow!("Expected only one argument, got more"));
    }

    if ! config.with_colons {
        // A nop for humans.
        return Ok(());
    }

    // XXX: items are space-delimited
    let (all, items) = args.get(0).map(|a| {
        (false, a.split(' ').collect::<Vec<_>>())
    }).unwrap_or_else(|| (true, vec![]));

    if all || items.iter().any(|i| *i == "group") {
        for (name, values) in config.groups.iter() {
            let values =
                values.iter().map(|h| h.to_string()).collect::<Vec<_>>();
            println!("cfg:group:{}:{}",
                     colons::escape(name),
                     values.join(";"));
        }
    }

    if all || items.iter().any(|i| *i == "version") {
        println!("cfg:version:{}", crate::gnupg_interface::VERSION);
    }

    if all || items.iter().any(|i| *i == "pubkey") {
        print!("cfg:pubkey:");
        for (i, a) in (0..0xff).into_iter()
            .filter(|a| *a != 2 && *a != 3) // Skip single-use RSA
            .map(PublicKeyAlgorithm::from)
            .filter(|a| a.is_supported()).enumerate()
        {
            if i > 0 {
                print!(";");
            }
            print!("{}", u8::from(a));
        }
        println!();
    }

    if all || items.iter().any(|i| *i == "pubkeyname") {
        print!("cfg:pubkeyname:");
        for (i, a) in (0..0xff).into_iter()
            .filter(|a| *a != 2 && *a != 3) // Skip single-use RSA
            .map(PublicKeyAlgorithm::from)
            .filter(|a| a.is_supported()).enumerate()
        {
            if i > 0 {
                print!(";");
            }
            print!("{}", babel::Fish(a));
        }
        println!();
    }

    if all || items.iter().any(|i| *i == "cipher") {
        print!("cfg:cipher:");
        for (i, a) in (0..0xff).into_iter()
            .map(SymmetricAlgorithm::from)
            .filter(|a| a.is_supported()).enumerate()
        {
            if i > 0 {
                print!(";");
            }
            print!("{}", u8::from(a));
        }
        println!();
    }

    if all || items.iter().any(|i| *i == "ciphername") {
        print!("cfg:ciphername:");
        for (i, a) in (0..0xff).into_iter()
            .map(SymmetricAlgorithm::from)
            .filter(|a| a.is_supported()).enumerate()
        {
            if i > 0 {
                print!(";");
            }
            print!("{}", babel::Fish(a));
        }
        println!();
    }

    if all || items.iter().any(|i| *i == "digest" || *i == "hash") {
        print!("cfg:digest:");
        for (i, a) in (0..0xff).into_iter()
            .map(HashAlgorithm::from)
            .filter(|a| *a != HashAlgorithm::MD5)
            .filter(|a| a.is_supported()).enumerate()
        {
            if i > 0 {
                print!(";");
            }
            print!("{}", u8::from(a));
        }
        println!();
    }

    if all || items.iter().any(|i| *i == "digestname" || *i == "hashname") {
        print!("cfg:digestname:");
        for (i, a) in (0..0xff).into_iter()
            .map(HashAlgorithm::from)
            .filter(|a| *a != HashAlgorithm::MD5)
            .filter(|a| a.is_supported()).enumerate()
        {
            if i > 0 {
                print!(";");
            }
            print!("{}", babel::Fish(a));
        }
        println!();
    }

    if all || items.iter().any(|i| *i == "compress") {
        print!("cfg:compress:");
        for (i, a) in (0..0xff).into_iter()
            .map(CompressionAlgorithm::from)
            .filter(|a| a.is_supported()).enumerate()
        {
            if i > 0 {
                print!(";");
            }
            print!("{}", u8::from(a));
        }
        println!();
    }

    if all || items.iter().any(|i| *i == "compressname") {
        print!("cfg:compressname:");
        for (i, a) in (0..0xff).into_iter()
            .map(CompressionAlgorithm::from)
            .filter(|a| a.is_supported()).enumerate()
        {
            if i > 0 {
                print!(";");
            }
            print!("{}", babel::Fish(a));
        }
        println!();
    }

    if all || items.iter().any(|i| *i == "curve") {
        print!("cfg:curve:");
        use Curve::*;
        for (i, cv) in [
            NistP256,
            NistP384,
            NistP521,
            BrainpoolP256,
            BrainpoolP512,
            Ed25519,
            Cv25519,
        ].iter().filter(|a| a.is_supported()).enumerate()
        {
            if i > 0 {
                print!(";");
            }
            print!("{}", babel::Fish(cv));
        }
        println!();
    }

    // XXX: curveoid

    Ok(())
}

/// Dispatches the --generate-revocation command.
pub fn cmd_generate_revocation(config: &crate::Config, args: &[String])
                               -> Result<()>
{
    use crate::trust::{Query, model::{self, Model}};

    if args.len() > 1 {
        return Err(anyhow::anyhow!("Expected only one argument, got more"));
    }

    let q = Query::from(args[0].as_str());
    let always = model::Always::default();
    let vtm = always.with_policy(config, Some(config.now()))?;
    let certs = config.lookup_certs_with(vtm.as_ref(), &q, true)?;

    if certs.is_empty() {
        return Err(anyhow::anyhow!("secret key \"{}\" not found", q));
    }

    // XXX: Maybe filter out the certs here instead of after the
    // check.

    if certs.len() > 1 {
        return Err(anyhow::anyhow!("query \"{}\" matched multiple keys", q));
    }
    let cert = certs[0];
    let primary = cert.primary_key().key();

    // Get the primary signer.  To that end, we need a valid cert
    // first to make password prompts more helpful for the user.
    let null_policy = NullPolicy::new();
    let vcert = cert.with_policy(config.policy(), config.now())
        .or_else(|_| cert.with_policy(
            config.policy(), cert.primary_key().creation_time()))
        .or_else(|_| cert.with_policy(
            &null_policy, cert.primary_key().creation_time()))
        .context(format!("Key {:X} is not valid", cert.fingerprint()))?;
    // XXX: Would be nice to make this infallible, but
    // ipc::gnupg::KeyPair::with_cert takes a ValidCert, and there is
    // no Cert equivalent.

    let rt = tokio::runtime::Runtime::new()?;
    let mut primary_signer =
        rt.block_on(config.get_signer(&vcert, primary.into()))?;

    let creation_time =
        chrono::DateTime::<chrono::Utc>::from(primary.creation_time());

    if ! config.prompt_yN(format_args!(
        "
sec  {}/{} {} {}

Create a revocation certificate for this key?",
        babel::Fish((primary.pk_algo(), primary.mpis().bits().unwrap_or(0),
                     &crate::list_keys::get_curve(primary.mpis()))),
        primary.keyid(),
        creation_time.format("%Y-%m-%d"),
        utils::best_effort_primary_uid(config.policy(), &cert),
    ))? {
        return Ok(());
    }

    'start_over: loop {
        let reason = loop {
            match config.prompt(format_args!(
                "Please select the reason for the revocation:
  0 = No reason specified
  1 = Key has been compromised
  2 = Key is superseded
  3 = Key is no longer used
  Q = Cancel
(Probably you want to select 1 here)
Your decision?"))?.to_lowercase().as_str()
            {
                "0" => break ReasonForRevocation::Unspecified,
                "1" => break ReasonForRevocation::KeyCompromised,
                "2" => break ReasonForRevocation::KeySuperseded,
                "3" => break ReasonForRevocation::KeyRetired,
                "q" => return Ok(()),
                _ => {
                    eprintln!("Invalid selection.");
                },
            }
        };

        eprintln!("Enter an optional description; end it with an empty line:");
        let mut description = vec![];
        loop {
            let line = config.prompt(format_args!(">"))?;
            if line.is_empty() {
                break;
            } else {
                description.push(line);
            }
        }
        let description = description.join("\n");

        // Summarize, and check again.
        eprintln!("Reason for revocation: {}", babel::Fish(reason));
        if description.is_empty() {
            eprintln!("(No description given)");
        } else {
            eprintln!("{}", description);
        }
        if ! config.prompt_yN(format_args!("Is this okay?"))? {
            continue 'start_over;
        }

        let sig = CertRevocationBuilder::new()
            .set_reason_for_revocation(reason, description.as_bytes())?
            .build(&mut primary_signer, &cert, None)?;

        let sink = if let Some(name) = config.outfile() {
            utils::create(config, name)?
        } else {
            Box::new(io::stdout())
        };

        let mut message = Message::new(sink);

        if config.armor {
            message = Armorer::new(message)
                .kind(openpgp::armor::Kind::PublicKey)
                .add_header("Comment", "This is a revocation certificate")
                .build()?;
        }
        openpgp::Packet::from(sig).serialize(&mut message)?;
        message.finalize()?;

        eprintln!("Revocation certificate created.

Please move it to a medium which you can hide away; if Mallory gets
access to this certificate he can use it to make your key unusable.
It is smart to print this certificate and store it away, just in case
your media become unreadable.  But have some caution:  The print system of
your machine might store the data and make it available to others!");

        return Ok(());
    }
}
