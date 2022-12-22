use anyhow::Result;

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
fn general_purpose_cv25519() -> Result<()> {
    general_purpose(CipherSuite::Cv25519)
}

#[test]
fn general_purpose_rsa2k() -> Result<()> {
    general_purpose(CipherSuite::RSA2k)
}

#[test]
fn general_purpose_rsa3k() -> Result<()> {
    general_purpose(CipherSuite::RSA3k)
}

#[test]
fn general_purpose_rsa4k() -> Result<()> {
    general_purpose(CipherSuite::RSA4k)
}

#[test]
fn general_purpose_p256() -> Result<()> {
    general_purpose(CipherSuite::P256)
}

#[test]
fn general_purpose_p384() -> Result<()> {
    general_purpose(CipherSuite::P384)
}

#[test]
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

#[test]
fn no_encryption_subkey() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        || CertBuilder::new()
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .set_creation_time(Experiment::now())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    test_key(cert, experiment, false)
}

fn test_key(cert: Cert, mut experiment: Experiment, expect_success: bool)
            -> Result<()>
{
    eprintln!("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 110);

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--no-auto-key-locate",
        "--always-trust",
        "--encrypt",
        "--recipient", "<alice@lovelace.name>",
        "--output", "ciphertext",
        &experiment.store("plaintext", PLAINTEXT)?,
    ])?;
    if expect_success {
        diff.assert_success();
        diff.assert_equal_up_to(70, 0);
        let ciphertexts =
            diff.with_working_dir(|p| p.get("ciphertext").cloned().ok_or_else(
                || anyhow::anyhow!("no ciphertext produced")))?;

        eprintln!("Importing key...");
        let diff = experiment.invoke(&[
            "--import",
            &experiment.store("key", &cert.as_tsk().to_vec()?)?,
        ])?;
        diff.assert_success();
        diff.assert_equal_up_to(0, 0);

        for ciphertext in ciphertexts {
            let diff = experiment.invoke(&[
                "--status-fd=1",
                "--decrypt",
                "--output", "plaintext",
                &experiment.store("ciphertext", &ciphertext)?,
            ])?;
            diff.assert_success();
            diff.assert_equal_up_to(140, 1);
            diff.with_working_dir(|p| {
                assert_eq!(p.get("plaintext").expect("no output"), PLAINTEXT);
                Ok(())
            })?;
        }
    } else {
        diff.assert_failure();
        diff.assert_equal_up_to(67, 0);
        assert!(diff.with_working_dir(
            |p| Ok(p.get("ciphertext").is_some()))?
                .iter().all(|&exists| exists == false));
    }

    Ok(())
}
