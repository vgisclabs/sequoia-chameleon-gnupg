//! Miscellaneous commands.

use std::{
    io::{self, Read},
    sync::Arc,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::{
        CertRevocationBuilder,
        raw::RawCertParser,
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

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;

use crate::{
    babel,
    colons,
    common::{
        BRAINPOOL_P384_OID,
        Common,
    },
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
                RawCertParser::from_reader(input)?
                    .map(|r| r.map(|c| Arc::new(LazyCert::from(c))))
                    .collect::<Result<Vec<_>>>()?;
            crate::list_keys::list_keys(
                config, certs.into_iter(), false, false, io::stdout())
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
        for (name, values) in config.groups.iter().rev() {
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
            .filter(|a| *a != 20) // Skip dual-use ElGamal
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
            .filter(|a| *a != 20) // Skip dual-use ElGamal
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
            Cv25519,
            Ed25519,
            NistP256,
            NistP384,
            NistP521,
            BrainpoolP256,
            Unknown(BRAINPOOL_P384_OID.into()),
            BrainpoolP512,
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
    use crate::trust::{self, Model};

    if args.len() > 1 {
        return Err(anyhow::anyhow!("Expected only one argument, got more"));
    }

    let q = args[0].parse()?;
    let always = trust::Always::default();
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
    let cert = certs[0].1.to_cert()?;
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

    if ! config.prompt_yN("gen_revoke.okay",
                          format_args!(
        "
sec  {}/{} {} {}

Create a revocation certificate for this key?",
        babel::Fish((primary.pk_algo(), primary.mpis().bits().unwrap_or(0),
                     &crate::colons::get_curve(primary.mpis()))),
        primary.keyid(),
        creation_time.format("%Y-%m-%d"),
        utils::best_effort_primary_uid(config.policy(), &cert),
    ))? {
        return Ok(());
    }

    'start_over: loop {
        let reason = loop {
            match config.prompt(
                "ask_revocation_reason.code",
                format_args!("\
Please select the reason for the revocation:
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
            let line = config.prompt(
                "ask_revocation_reason.text", format_args!(">"))?;
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
        if ! config.prompt_yN(
            "ask_revocation_reason.okay",
            format_args!("Is this okay?"))?
        {
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

/// Dispatches the --enarmor command.
pub fn cmd_enarmor(config: &crate::Config, args: &[String])
                   -> Result<()>
{
    use openpgp::armor::{Writer, Kind};

    let filename = args.get(0).cloned().unwrap_or_else(|| "-".into());
    let mut source = utils::open(config, &filename)?;
    let sink = if let Some(name) = config.outfile() {
        utils::create(config, name)?
    } else {
        Box::new(io::stdout())
    };

    let mut sink = Writer::with_headers(
        sink, Kind::File,
        vec![("Comment", "Use \"gpg --dearmor\" for unpacking")])?;
    std::io::copy(&mut source, &mut sink)?;
    sink.finalize()?;
    Ok(())
}

/// Dispatches the --dearmor command.
pub fn cmd_dearmor(config: &crate::Config, args: &[String])
                   -> Result<()>
{
    use openpgp::armor::{Reader, ReaderMode};

    let filename = args.get(0).cloned().unwrap_or_else(|| "-".into());
    let source = utils::open(config, &filename)?;
    let mut sink = if let Some(name) = config.outfile() {
        utils::create(config, name)?
    } else {
        Box::new(io::stdout())
    };

    let mut source = Reader::from_reader(source, ReaderMode::Tolerant(None));
    std::io::copy(&mut source, &mut sink)?;
    Ok(())
}

/// Dispatches the --import-ownertrust command.
pub fn cmd_import_ownertrust(config: &mut crate::Config, args: &[String])
                             -> Result<()>
{
    if args.len() > 1 {
        return Err(anyhow::anyhow!("Expected only one argument, got more"));
    }

    let filename = args.get(0).cloned().unwrap_or_else(|| "-".into());
    let mut source = crate::utils::open(config, &filename)?;
    config.trustdb.import_ownertrust(config, &mut source)?;
    config.trustdb.commit_overlay(config.keydb())?;
    Ok(())
}

/// Dispatches the --export-ownertrust command.
pub fn cmd_export_ownertrust(config: &crate::Config, args: &[String])
                             -> Result<()>
{
    if args.len() > 0 {
        return Err(anyhow::anyhow!("Expected no arguments, got some"));
    }

    config.trustdb.export_ownertrust(&mut std::io::stdout())?;
    Ok(())
}

/// Dispatches the --print-md command.
pub fn print_md(config: &crate::Config, args: &[String]) -> Result<()>
{
    let (args, algo) = if args.is_empty() {
        (args, None)
    } else if &args[0] == "*" {
        (&args[1..], None)
    } else {
        (&args[1..], Some(args[0].parse::<babel::Fish<_>>()?.0))
    };
    _print_mds(config, algo, args)
}

/// Dispatches the --print-mds command.
pub fn print_mds(config: &crate::Config, args: &[String]) -> Result<()>
{
    _print_mds(config, None, args)
}

pub fn _print_mds(config: &crate::Config, algo: Option<HashAlgorithm>,
                  args: &[String]) -> Result<()>
{
    // Break on long file names.
    const INDENT_LIMIT: usize = 40;
    const INDENT: &'static str =
        "                                        ";
    assert_eq!(INDENT.len(), INDENT_LIMIT);

    let filename = args.get(0).cloned().unwrap_or_else(|| "-".into());
    for f in std::iter::once(&filename).chain(args.iter().skip(1)) {
        let mut source = utils::open(config, &f)?;

        if let Some(algo) = algo {
            let mut hash = algo.context()?;
            std::io::copy(&mut source, &mut hash)?;
            let mut digest = vec![0; hash.digest_size()];
            hash.digest(&mut digest)?;

            let mut offset = 0;
            if f != "-" {
                print!("{}:", f);
                offset += f.chars().count() + 1;
            } else {
                if config.with_colons {
                    print!(":");
                }
            }

            if config.with_colons {
                println!("{}:{}:", u8::from(algo),
                         openpgp::fmt::hex::encode(digest));
            } else {
                if offset > INDENT_LIMIT {
                    println!();
                    offset = 0;
                }

                let indent = offset;

                let (chunk_len, center_space) = match digest.len() {
                    16 => (1, Some(8)),
                    20 => (2, Some(5)),
                    _ => (4, None),
                };
                for (i, chunk) in digest.chunks(chunk_len).enumerate() {
                    if offset + chunk_len * 2 > 79 {
                        print!("\n{}", &INDENT[..indent]);
                        offset = indent;
                    }

                    if center_space.map(|at| i == at).unwrap_or(false) {
                        print!(" ");
                        offset += 1;
                    }

                    print!(" {}", openpgp::fmt::hex::encode(chunk));
                    offset += 1 + chunk_len * 2;
                }
                println!();
            }
        } else {
            // Sort the hash algorithms in a particular way.
            use HashAlgorithm::{SHA224, SHA256};
            let mut hashes = (0..SHA256.into()).into_iter()
                .chain(std::iter::once(SHA224.into()))
                .chain((SHA256.into()..SHA224.into()).into_iter())
                .chain((u8::from(SHA224) + 1..0xFF).into_iter())
                .map(HashAlgorithm::from)
                .filter(|a| a.is_supported())
                .map(|h| h.context())
                .collect::<Result<Vec<_>>>()?;

            let mut buf = vec![0; 4096];
            loop {
                let l = source.read(&mut buf)?;
                if l == 0 {
                    break;
                }
                hashes.iter_mut().for_each(|h| h.update(&buf[..l]));
            }

            for mut hash in hashes {
                let algo = hash.algo();
                let mut digest = vec![0; hash.digest_size()];
                hash.digest(&mut digest)?;

                let mut offset = 0;
                if f != "-" {
                    print!("{}:", f);
                    offset += f.chars().count() + 1;
                } else {
                    if config.with_colons {
                        print!(":");
                    }
                }

                if offset > INDENT_LIMIT {
                    println!();
                    offset = 0;
                }

                if config.with_colons {
                    println!("{}:{}:", u8::from(algo),
                             openpgp::fmt::hex::encode(digest));
                } else {
                    print!("{:>6} =", babel::Fish(algo).to_string()
                           .replace("RIPEMD160", "RMD160"));
                    offset += 8;
                    let indent = offset;

                    let (chunk_len, center_space) = match digest.len() {
                        16 => (1, Some(8)),
                        20 => (2, Some(5)),
                        _ => (4, None),
                    };
                    for (i, chunk) in digest.chunks(chunk_len).enumerate() {
                        if offset + chunk_len * 2 > 79 {
                            print!("\n{}", &INDENT[..indent]);
                            offset = indent;
                        }

                        if center_space.map(|at| i == at).unwrap_or(false) {
                            print!(" ");
                            offset += 1;
                        }

                        print!(" {}", openpgp::fmt::hex::encode(chunk));
                        offset += 1 + chunk_len * 2;
                    }
                    println!();
                }
            }
        }
    }

    Ok(())
}
