use std::{
    io::Write,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    policy::StandardPolicy,
    parse::Parse,
    serialize::{
        Serialize,
        SerializeInto,
        stream::{
            Message, Encryptor, LiteralWriter,
        },
    },
};

use super::super::*;

const PLAINTEXT: &[u8] = b"plaintext";

#[test]
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

    let ciphertext = encrypt_for(&[&cert])?;
    test_key(cert, ciphertext, experiment)
}

fn test_key(cert: Cert, ciphertext: Vec<u8>, mut experiment: Experiment)
            -> Result<()>
{
    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--decrypt",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_equal_up_to(0, 60);

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--decrypt",
        "--verbose",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--decrypt",
        "--list-only",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--decrypt",
        "--list-only",
        "--verbose",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_equal_up_to(0, 0);

    eprintln!("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 60);

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--decrypt",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_equal_up_to(0, 1);

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--decrypt",
        "--verbose",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_equal_up_to(0, 1);

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--decrypt",
        "--list-only",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_equal_up_to(0, 1);

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--decrypt",
        "--list-only",
        "--verbose",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_equal_up_to(0, 1);

    eprintln!("Importing key...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("key", &cert.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--decrypt",
        "--output", "decrypted-plaintext",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(140, 1);
    diff.with_working_dir(|p| {
        assert_eq!(p.get("decrypted-plaintext").expect("no output"), PLAINTEXT);
        Ok(())
    })?;

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--decrypt",
        "--output", "decrypted-plaintext",
        "--verbose",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(140, 110);
    diff.with_working_dir(|p| {
        assert_eq!(p.get("decrypted-plaintext").expect("no output"), PLAINTEXT);
        Ok(())
    })?;

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--decrypt",
        "--list-only",
        "--output", "nothing",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 1);
    diff.with_working_dir(|p| {
        if let Some(o) = p.get("nothing") {
            assert_eq!(o, b"");
        }
        Ok(())
    })?;

    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--decrypt",
        "--list-only",
        "--output", "nothing",
        "--verbose",
        &experiment.store("ciphertext", &ciphertext)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 1);
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
