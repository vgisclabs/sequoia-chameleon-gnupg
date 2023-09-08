use anyhow::Result;
use regex::bytes::Regex;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    parse::Parse,
    serialize::{
        Serialize,
        SerializeInto,
    },
};

use super::super::*;

const PLAINTEXT: &[u8] = b"plaintext";

#[test]
#[ntest::timeout(600000)]
fn general_purpose_cv25519() -> Result<()> {
    general_purpose(CipherSuite::Cv25519)
}

#[test]
#[ntest::timeout(600000)]
fn general_purpose_rsa2k() -> Result<()> {
    general_purpose(CipherSuite::RSA2k)
}

#[test]
#[ntest::timeout(600000)]
fn general_purpose_rsa3k() -> Result<()> {
    general_purpose(CipherSuite::RSA3k)
}

#[test]
#[ntest::timeout(600000)]
fn general_purpose_rsa4k() -> Result<()> {
    general_purpose(CipherSuite::RSA4k)
}

#[test]
#[ntest::timeout(600000)]
fn general_purpose_p256() -> Result<()> {
    general_purpose(CipherSuite::P256)
}

#[test]
#[ntest::timeout(600000)]
fn general_purpose_p384() -> Result<()> {
    general_purpose(CipherSuite::P384)
}

#[test]
#[ntest::timeout(600000)]
fn general_purpose_p521() -> Result<()> {
    general_purpose(CipherSuite::P521)
}

fn general_purpose(cs: CipherSuite) -> Result<()> {
    let mut experiment = make_experiment!(format!("{:?}", cs))?;
    let cert = experiment.artifact(
        "cert",
        || CertBuilder::general_purpose(
            cs, Some("Alice Lovelace <alice@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    test_key(cert, experiment, true)
}

fn test_key(cert: Cert, mut experiment: Experiment, expect_success: bool)
            -> Result<()>
{
    // Create the keyring stores.  Reduces the noise in the upcoming
    // experiments.
    experiment.invoke(&["--list-keys"])?.assert_success();

    eprintln!("Importing key...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("key", &cert.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();

    let diff = experiment.invoke(&[
        "--digest-algo=SHA512",
        "--sign",
        "--output", "signature",
        &experiment.store("plaintext", PLAINTEXT)?,
    ])?;
    if expect_success {
        diff.assert_success();
        diff.assert_limits(0, 0, 0);
        let signatures =
            diff.with_working_dir(|p| p.get("signature").cloned().ok_or_else(
                || anyhow::anyhow!("no signature produced")))?;

        test_verification(&mut experiment, signatures)?;
    } else {
        diff.assert_failure();
        diff.assert_limits(0, 0, 0);
        assert!(diff.with_working_dir(
            |p| Ok(p.get("signature").is_some()))?
                .iter().all(|&exists| exists == false));
    }

    let diff = experiment.invoke(&[
        "--digest-algo=SHA512",
        "--sign",
        "--textmode",
        "--output", "signature",
        &experiment.store("plaintext", PLAINTEXT)?,
    ])?;
    if expect_success {
        diff.assert_success();
        diff.assert_limits(0, 0, 0);
        let signatures =
            diff.with_working_dir(|p| p.get("signature").cloned().ok_or_else(
                || anyhow::anyhow!("no signature produced")))?;

        test_verification(&mut experiment, signatures)?;
    } else {
        diff.assert_failure();
        diff.assert_limits(0, 0, 0);
        assert!(diff.with_working_dir(
            |p| Ok(p.get("signature").is_some()))?
                .iter().all(|&exists| exists == false));
    }

    let diff = experiment.invoke(&[
        "--digest-algo=SHA512",
        "--clear-sign",
        "--output", "signature",
        &experiment.store("plaintext", PLAINTEXT)?,
    ])?;
    if expect_success {
        diff.assert_success();
        diff.assert_limits(0, 0, 0);
        let signatures =
            diff.with_working_dir(|p| p.get("signature").cloned().ok_or_else(
                || anyhow::anyhow!("no signature produced")))?;

        test_verification(&mut experiment, signatures)?;
    } else {
        diff.assert_failure();
        diff.assert_limits(0, 0, 0);
        assert!(diff.with_working_dir(
            |p| Ok(p.get("signature").is_some()))?
                .iter().all(|&exists| exists == false));
    }

    let diff = experiment.invoke(&[
        "--digest-algo=SHA512",
        "--detach-sign",
        "--output", "signature",
        &experiment.store("plaintext", PLAINTEXT)?,
    ])?;
    if expect_success {
        diff.assert_success();
        diff.assert_limits(0, 0, 0);
        let signatures =
            diff.with_working_dir(|p| p.get("signature").cloned().ok_or_else(
                || anyhow::anyhow!("no signature produced")))?;

        test_detached_verification(&mut experiment, signatures)?;
    } else {
        diff.assert_failure();
        diff.assert_limits(0, 0, 0);
        assert!(diff.with_working_dir(
            |p| Ok(p.get("signature").is_some()))?
                .iter().all(|&exists| exists == false));
    }

    Ok(())
}

fn test_verification(experiment: &mut Experiment,
                     signatures: Vec<Vec<u8>>)
                   -> Result<()> {
    for signature in signatures {
        let csf =
            signature.starts_with(b"-----BEGIN PGP SIGNED MESSAGE-----");
        let mut diff = experiment.invoke(&[
            "--verify",
            "--output", "output",
            &experiment.store("signature", &signature)?,
        ])?;
        diff.canonicalize_with(canonicalize_sig_id_and_salt)?;
        diff.assert_success();
        diff.assert_limits(0, 6, 96);
        diff.with_working_dir(|p| {
            if csf {
                // GnuPG will swallow the trailing newline, as will
                // Sequoia up to 1.16.
                assert_eq!(trim_ascii_end(p.get("output").expect("no output")),
                           trim_ascii_end(PLAINTEXT));
            } else {
                assert_eq!(p.get("output").expect("no output"), PLAINTEXT);
            }
            Ok(())
        })?;
    }

    Ok(())
}

fn test_detached_verification(experiment: &mut Experiment,
                              signatures: Vec<Vec<u8>>)
                              -> Result<()> {
    for signature in signatures {
        let mut diff = experiment.invoke(&[
            "--verify",
            &experiment.store("signature", &signature)?,
            &experiment.store("data", &PLAINTEXT)?,
        ])?;
        diff.canonicalize_with(canonicalize_sig_id_and_salt)?;
        diff.assert_success();
        diff.assert_limits(0, 6, 67);
    }

    Ok(())
}

fn canonicalize_sig_id_and_salt(o: &mut crate::Output) -> Result<()> {
    let sig_id = Regex::new(r"\[GNUPG:\] SIG_ID [0-9A-Za-z+/]{27}")
        .unwrap();
    let salt = Regex::new(r"(?-u)\[GNUPG:\] NOTATION_DATA .*\n")
        .unwrap();

    o.statusfd = sig_id.replace_all(
        &salt.replace_all(&o.statusfd,
                          &b"[GNUPG:] NOTATION_DATA <CANONICALIZED>"[..]),
        &b"[GNUPG:] SIG_ID <CANONICALIZED>"[..]).to_vec();

    Ok(())
}

fn trim_ascii_end(mut buf: &[u8]) -> &[u8] {
    while let Some(b) = buf.iter().last().clone() {
        if b.is_ascii_whitespace() {
            buf = &buf[..buf.len() - 1];
        } else {
            break;
        }
    }
    buf
}
