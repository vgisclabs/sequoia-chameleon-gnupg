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

#[test]
#[ntest::timeout(600000)]
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

#[test]
#[ntest::timeout(600000)]
fn recipient_file() -> Result<()> {
    let mut experiment = make_experiment!()?;
    // Create the keyring stores.  Reduces the noise in the upcoming
    // experiments.
    experiment.invoke(&["--list-keys"])?.assert_success();

    let cert = experiment.artifact(
        "cert",
        || CertBuilder::new()
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .set_creation_time(Experiment::now())
            .add_transport_encryption_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let diff = experiment.invoke(&[
        "--no-auto-key-locate",
        "--always-trust",
        "--encrypt",
        "--recipient-file", &experiment.store("cert", &cert.to_vec()?)?,
        "--output", "ciphertext",
        &experiment.store("plaintext", PLAINTEXT)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 1);
    let ciphertexts =
        diff.with_working_dir(|p| p.get("ciphertext").cloned().ok_or_else(
            || anyhow::anyhow!("no ciphertext produced")))?;

    test_decryption(cert, experiment, ciphertexts)
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
    diff.assert_limits(0, 110, 0);

    let diff = experiment.invoke(&[
        "--no-auto-key-locate",
        "--always-trust",
        "--encrypt",
        "--recipient", "<alice@lovelace.name>",
        "--output", "ciphertext",
        &experiment.store("plaintext", PLAINTEXT)?,
    ])?;
    if expect_success {
        diff.assert_success();
        diff.assert_limits(0, 0, 0);
        let ciphertexts =
            diff.with_working_dir(|p| p.get("ciphertext").cloned().ok_or_else(
                || anyhow::anyhow!("no ciphertext produced")))?;

        test_decryption(cert, experiment, ciphertexts)?;
    } else {
        diff.assert_failure();
        diff.assert_limits(0, 0, 0);
        assert!(diff.with_working_dir(
            |p| Ok(p.get("ciphertext").is_some()))?
                .iter().all(|&exists| exists == false));
    }

    Ok(())
}

fn test_decryption(cert: Cert,
                   mut experiment: Experiment,
                   ciphertexts: Vec<Vec<u8>>)
                   -> Result<()> {
    eprintln!("Importing key...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("key", &cert.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 78);

    for ciphertext in ciphertexts {
        let diff = experiment.invoke(&[
            "--decrypt",
            "--output", "plaintext",
            &experiment.store("ciphertext", &ciphertext)?,
        ])?;
        diff.assert_success();
        diff.assert_limits(0, 1, 140);
        diff.with_working_dir(|p| {
            assert_eq!(p.get("plaintext").expect("no output"), PLAINTEXT);
            Ok(())
        })?;
    }

    Ok(())
}
