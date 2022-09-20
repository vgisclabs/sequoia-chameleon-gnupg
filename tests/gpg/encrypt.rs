use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    serialize::{
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
    let (cert, _) =
        CertBuilder::general_purpose(cs,
                                     Some("Alice Lovelace <alice@lovelace.name>"))
        .generate()?;

    test_key(cert, None)
}

fn test_key<E>(cert: Cert, experiment: E) -> Result<()>
where
    E: Into<Option<Experiment>>,
{
    let experiment = if let Some(e) = experiment.into() {
        e
    } else {
        Experiment::new()?
    };

    eprintln!("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 110);

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--always-trust",
        "--encrypt",
        "--recipient", "<alice@lovelace.name>",
        "--output", "ciphertext",
        &experiment.store("ciphertext", PLAINTEXT)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(70, 0);
    let ciphertexts =
        diff.with_working_dir(|p| Ok(std::fs::read(p.join("ciphertext"))?))?;

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
            assert_eq!(&std::fs::read(p.join("plaintext"))?,
                       PLAINTEXT);
            Ok(())
        })?;
    }

    Ok(())
}
