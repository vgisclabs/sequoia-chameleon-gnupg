//! Miscellaneous commands.

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    types::*,
};

use crate::{
    babel,
    colons,
};

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

    if all || items.iter().any(|i| *i == "digestname" || *i == "hashname") {
        print!("cfg:digestname:");
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

