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

#[test]
#[ntest::timeout(600000)]
fn ciphersuite_cv25519() -> Result<()> {
    ciphersuite(CipherSuite::Cv25519)
}

#[test]
#[ntest::timeout(600000)]
fn ciphersuite_rsa2k() -> Result<()> {
    ciphersuite(CipherSuite::RSA2k)
}

#[test]
#[ntest::timeout(600000)]
fn ciphersuite_rsa3k() -> Result<()> {
    ciphersuite(CipherSuite::RSA3k)
}

#[test]
#[ntest::timeout(600000)]
fn ciphersuite_rsa4k() -> Result<()> {
    ciphersuite(CipherSuite::RSA4k)
}

#[test]
#[ntest::timeout(600000)]
fn ciphersuite_p256() -> Result<()> {
    ciphersuite(CipherSuite::P256)
}

#[test]
#[ntest::timeout(600000)]
fn ciphersuite_p384() -> Result<()> {
    ciphersuite(CipherSuite::P384)
}

#[test]
#[ntest::timeout(600000)]
fn ciphersuite_p521() -> Result<()> {
    ciphersuite(CipherSuite::P521)
}

fn ciphersuite(cs: CipherSuite) -> Result<()> {
    let mut experiment = make_experiment!(format!("{:?}", cs))?;
    let cert = experiment.artifact(
        "cert",
        || CertBuilder::new()
            .set_cipher_suite(cs)
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .set_creation_time(Experiment::now())
            .add_authentication_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    test_key(cert, experiment, true)
}

#[test]
#[ntest::timeout(600000)]
fn no_authentication_subkey() -> Result<()> {
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
    experiment.section("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();

    let primary = cert.fingerprint().to_string();
    let diff = experiment.invoke(&[
        "--export-ssh-key", &primary,
    ])?;
    if expect_success {
        diff.assert_success();
        diff.assert_limits(0, 0, 0);
    } else {
        diff.assert_failure();
        diff.assert_limits(0, 0, 7);
    }

    if let Some(subkey) =
        cert.keys().subkeys().nth(0).map(|k| k.fingerprint().to_string())
    {
        let diff = experiment.invoke(&[
            "--export-ssh-key", &subkey,
        ])?;
        if expect_success {
            diff.assert_success();
            diff.assert_limits(0, 0, 0);
        } else {
            diff.assert_failure();
            diff.assert_limits(0, 0, 7);
        }

        let diff = experiment.invoke(&[
            "--export-ssh-key", &format!("{}!", &subkey),
        ])?;
        diff.assert_success();
        diff.assert_limits(0, 0, 0);
    } else {
        let diff = experiment.invoke(&[
            "--export-ssh-key", &format!("{}!", &primary),
        ])?;
        diff.assert_success();
        diff.assert_limits(0, 0, 0);
    }

    Ok(())
}
