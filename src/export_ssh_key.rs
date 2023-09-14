use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    crypto::mpi,
    packet::{
        Key,
        key::{PublicParts, UnspecifiedRole},
    },
    types::{Curve, KeyFlags},
};

use crate::{
    common::{Common, Query},
    error_codes,
    status::Status,
    utils,
};

/// Dispatches the --export-ssh-key command.
///
/// Exports the requested key material in a form suitable for
/// inclusion in ssh's authorized_keys file.
pub fn cmd_export_ssh_key(config: &mut crate::Config, args: &[String])
                          -> Result<()>
{
    if args.len() != 1 {
        config.wrong_args(format_args!("--export-ssh-key <user-id>"));
    }

    let query: Query = args[0].as_str().into();
    let certs = config.lookup_certs(&query)?;
    match certs.len() {
        0 => Err(anyhow::anyhow!(
            "key {:?} not found: No public key", args[0])),
        1 => {
            let key = export_ssh_key(config, &args[0], query,
                                     certs[0].1.as_cert()?)
                .map_err(|e| {
                    let _ = config.status().emit(Status::Failure {
                        location: "export-ssh-key",
                        error: error_codes::Error::GPG_ERR_UNUSABLE_PUBKEY,
                    });
                    config.warn(format_args!("{}", e));
                    anyhow::anyhow!("export as ssh key failed: Unusable public key")
                })?;
            let mut sink = if let Some(name) = config.outfile() {
                utils::create(config, name)?
            } else {
                Box::new(std::io::stdout())
            };
            writeln!(&mut sink, "{}", key)?;
            Ok(())
        },
        _ => Err(anyhow::anyhow!(
            "key {:?} not found: Ambiguous name", args[0])),
    }
}

fn export_ssh_key(config: &crate::Config,
                  query_str: &str,
                  query: Query,
                  cert: Cert)
                  -> Result<String> {
    use openssh_keys::{Data, PublicKey, Curve as SshCurve};
    let mut subkeys: Vec<_> = if let Query::ExactKey(h) = &query {
        cert.keys()
            .key_handle(h.clone())
            .map(|ka| ka.key())
            .collect()
    } else {
        cert.with_policy(config.policy(), None)?
            .keys()
            .key_flags(KeyFlags::empty().set_authentication())
            .map(|ka| ka.key())
            .collect()
    };

    if subkeys.is_empty() {
        return Err(anyhow::anyhow!("key {:?} not found: Unusable public key",
                                   query_str));
    }

    let primary = cert.fingerprint();
    let is_primary = |c: &Key<PublicParts, UnspecifiedRole>| {
        c.fingerprint() == primary
    };
    subkeys.sort_by(|a, b| {
        is_primary(a).cmp(&is_primary(b)).reverse()
            .then(a.creation_time().cmp(&b.creation_time()))
    });

    let data = match subkeys[0].mpis() {
        mpi::PublicKey::RSA { e, n } =>
            Data::Rsa {
                exponent: e.value().into(),
                modulus: n.value().into(),
            },
        mpi::PublicKey::DSA { p, q, g, y } =>
            Data::Dsa {
                p: p.value().into(),
                q: q.value().into(),
                g: g.value().into(),
                pub_key: y.value().into(),
            },
        mpi::PublicKey::EdDSA { curve, q } if curve == &Curve::Ed25519 =>
            Data::Ed25519 {
                // Compressed coordinates, no prefix.
                key: q.decode_point(curve)?.0.into(),
            },
        mpi::PublicKey::ECDSA { curve, q } =>
            Data::Ecdsa {
                curve: match curve {
                    Curve::NistP256 => SshCurve::Nistp256,
                    Curve::NistP384 => SshCurve::Nistp384,
                    Curve::NistP521 => SshCurve::Nistp521,
                    _ => return Err(anyhow::anyhow!(
                        "Unsupported public key algorithm")),
                },
                // Uncompressed coordinates, 0x04 prefix.
                key: q.value().into(),
            },
        _ => return Err(anyhow::anyhow!("Unsupported public key algorithm")),
    };

    Ok(PublicKey {
        options: None,
        data,
        comment: Some(
            format!("openpgp:0x{}",
                    subkeys[0].keyid().to_string()[8..].to_string())),
    }.to_key_format())
}
