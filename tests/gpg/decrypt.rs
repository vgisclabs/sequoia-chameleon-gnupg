use std::{
    io::Write,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    crypto::SessionKey,
    policy::StandardPolicy,
    parse::Parse,
    serialize::{
        Serialize,
        SerializeInto,
        stream::{
            Message, Encryptor2 as Encryptor, LiteralWriter,
        },
    },
    types::SymmetricAlgorithm,
};

use super::super::*;

const PLAINTEXT: &[u8] = b"plaintext";

#[test]
#[ntest::timeout(600000)]
fn symmetric_blowfish() -> Result<()> {
    symmetric(SymmetricAlgorithm::Blowfish)
}

#[test]
#[ntest::timeout(600000)]
fn symmetric_aes128() -> Result<()> {
    symmetric(SymmetricAlgorithm::AES128)
}

#[test]
#[ntest::timeout(600000)]
fn symmetric_aes192() -> Result<()> {
    symmetric(SymmetricAlgorithm::AES192)
}

#[test]
#[ntest::timeout(600000)]
fn symmetric_aes256() -> Result<()> {
    symmetric(SymmetricAlgorithm::AES256)
}

#[test]
#[ntest::timeout(600000)]
fn symmetric_twofish() -> Result<()> {
    symmetric(SymmetricAlgorithm::Twofish)
}

fn symmetric(algo: SymmetricAlgorithm) -> Result<()> {
    let mut experiment = make_experiment!(algo.to_string())?;

    let sk = SessionKey::from(vec![64; algo.key_size()?]);
    let ciphertext = experiment.artifact(
        "ciphertext", || {
            let mut buf = vec![];
            let message = Message::new(&mut buf);
            let message = Encryptor::with_session_key(
                message, algo, sk.clone())?
                .add_passwords(vec!["password"])
                .build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(PLAINTEXT)?;
            message.finalize()?;
            Ok(buf)
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;

    let diff = experiment.invoke(&[
        "--batch",
        "--pinentry-mode=loopback",
        "--decrypt",
        "--passphrase", "password",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_limits(0, 0, 0);

    let diff = experiment.invoke(&[
        "--batch",
        "--pinentry-mode=loopback",
        "--decrypt",
        "--verbose",
        "--passphrase", "password",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_limits(0, 0, 0);

    let diff = experiment.invoke(&[
        "--batch",
        "--pinentry-mode=loopback",
        "--decrypt",
        "--list-only",
        "--passphrase", "password",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_limits(0, 0, 0);

    let diff = experiment.invoke(&[
        "--batch",
        "--pinentry-mode=loopback",
        "--decrypt",
        "--list-only",
        "--verbose",
        "--passphrase", "password",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_limits(0, 0, 0);

    Ok(())
}

#[test]
#[ntest::timeout(600000)]
fn simple() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        ||  CertBuilder::new()
            .set_creation_time(Experiment::now())
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_transport_encryption_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let ciphertext = encrypt_for(&[&cert])?;
    test_key(cert, ciphertext, experiment)
}

#[test]
#[ntest::timeout(600000)]
fn locked_loopback() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        || CertBuilder::new()
            .set_creation_time(Experiment::now())
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_transport_encryption_subkey()
            .set_password(Some("streng geheim".into()))
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let ciphertext = encrypt_for(&[&cert])?;

    eprintln!("Importing key...");
    let diff = experiment.invoke(&[
        "--import",
        "--batch",
        &experiment.store("key", &cert.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();

    let diff = experiment.invoke(&[
        "--pinentry-mode=loopback",
        "--passphrase", "streng geheim",
        "--decrypt",
        "--output", "decrypted-plaintext",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 1, 140);
    diff.with_working_dir(|p| {
        assert_eq!(p.get("decrypted-plaintext").expect("no output"), PLAINTEXT);
        Ok(())
    })?;

    Ok(())
}

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

    let ciphertext = encrypt_for(&[&cert])?;
    test_key(cert, ciphertext, experiment)
}

fn test_key(cert: Cert, ciphertext: Vec<u8>, mut experiment: Experiment)
            -> Result<()>
{
    let diff = experiment.invoke(&[
        "--decrypt",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_limits(0, 0, 0);

    let diff = experiment.invoke(&[
        "--decrypt",
        "--verbose",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_limits(0, 0, 0);

    let diff = experiment.invoke(&[
        "--decrypt",
        "--list-only",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_limits(0, 0, 0);

    let diff = experiment.invoke(&[
        "--decrypt",
        "--list-only",
        "--verbose",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_limits(0, 0, 0);

    eprintln!("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--decrypt",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_limits(0, 1, 0);

    let diff = experiment.invoke(&[
        "--decrypt",
        "--verbose",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_limits(0, 1, 0);

    let diff = experiment.invoke(&[
        "--decrypt",
        "--list-only",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_limits(0, 1, 0);

    let diff = experiment.invoke(&[
        "--decrypt",
        "--list-only",
        "--verbose",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_limits(0, 1, 0);

    eprintln!("Importing key...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("key", &cert.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 78);

    let diff = experiment.invoke(&[
        "--decrypt",
        "--output", "decrypted-plaintext",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 1, 140);
    diff.with_working_dir(|p| {
        assert_eq!(p.get("decrypted-plaintext").expect("no output"), PLAINTEXT);
        Ok(())
    })?;

    let diff = experiment.invoke(&[
        "--decrypt",
        "--output", "decrypted-plaintext",
        "--verbose",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 110, 140);
    diff.with_working_dir(|p| {
        assert_eq!(p.get("decrypted-plaintext").expect("no output"), PLAINTEXT);
        Ok(())
    })?;

    let diff = experiment.invoke(&[
        "--decrypt",
        "--list-only",
        "--output", "nothing",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 1, 0);
    diff.with_working_dir(|p| {
        if let Some(o) = p.get("nothing") {
            assert_eq!(o, b"");
        }
        Ok(())
    })?;

    let diff = experiment.invoke(&[
        "--decrypt",
        "--list-only",
        "--output", "nothing",
        "--verbose",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 1, 0);
    diff.with_working_dir(|p| {
        if let Some(o) = p.get("nothing") {
            assert_eq!(o, b"");
        }
        Ok(())
    })?;

    Ok(())
}

fn encrypt_for(recipient_certs: &[&Cert]) -> Result<Vec<u8>> {
    let p = &StandardPolicy::new();
    let mut recipients = Vec::new();
    for cert in recipient_certs {
        // Make sure we add at least one subkey from every
        // certificate.
        let mut found_one = false;
        for key in cert.keys().with_policy(p, None)
            .supported().alive().revoked(false).for_transport_encryption()
        {
            recipients.push(key);
            found_one = true;
        }

        if ! found_one {
            return Err(anyhow::anyhow!("No suitable encryption subkey for {}",
                                       cert));
        }
    }

    let mut buf = Vec::new();
    let message = Message::new(&mut buf);
    let message = Encryptor::for_recipients(message, recipients).build()?;
    let mut w = LiteralWriter::new(message).build()?;
    w.write_all(PLAINTEXT)?;
    w.finalize()?;
    Ok(buf)
}

#[test]
fn empty() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let diff = experiment.invoke(&[
        "--decrypt",
        "--output", "nothing",
        &experiment.store("empty", &[])?,
    ])?;
    diff.assert_limits(0, 0, 0);
    Ok(())
}
