use std::{
    time::*,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    serialize::SerializeInto,
    types::KeyFlags,
};

use super::super::*;

#[test]
fn empty() -> Result<()> {
    let experiment = Experiment::new()?;

    let diff = experiment.invoke(&[
        "--list-keys",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 100);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(3, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-secret",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-secret",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(3, 0);

    let diff = experiment.invoke(&[
        "--list-secret-keys",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--list-secret-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    Ok(())
}

#[test]
fn valid() -> Result<()> {
    let (cert, _) = CertBuilder::new()
        .add_userid("Alice Lovelace <alice@lovelace.name>")
        .add_signing_subkey()
        .generate()?;

    test_key(cert, None)
}

#[test]
fn revoked() -> Result<()> {
    let (cert, rev) = CertBuilder::new()
        .add_userid("Alice Lovelace <alice@lovelace.name>")
        .add_signing_subkey()
        .generate()?;
    let cert = cert.insert_packets(vec![rev])?;

    test_key(cert, None)
}

#[test]
fn expired() -> Result<()> {
    let a_week = Duration::new(7 * 24 * 3600, 0);
    let the_past = SystemTime::now()
        .checked_sub(2 * a_week)
        .unwrap();
    let (cert, _) = CertBuilder::new()
        .set_creation_time(the_past)
        .set_validity_period(a_week)
        .add_userid("Alice Lovelace <alice@lovelace.name>")
        .add_signing_subkey()
        .set_primary_key_flags(
            KeyFlags::empty().set_signing().set_certification())
        .generate()?;

    test_key(cert, None)
}

#[test]
fn disabled() -> Result<()> {
    let (cert, _) = CertBuilder::new()
        .add_userid("Alice Lovelace <alice@lovelace.name>")
        .add_signing_subkey()
        .generate()?;

    let experiment = Experiment::new()?;

    eprintln!("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 140);

    let diff = experiment.invoke(&[
        "--import-ownertrust",
        &experiment.store("ownertrust",
                          format!("{}:134:\n", cert.fingerprint()).as_bytes())?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 33);

    let diff = experiment.invoke(&[
        "--check-trustdb",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 150);

    test_key_cert_imported(cert, experiment)
}

/// Allows `errors` for every (sub)key in `cert`.
fn per_subkey(cert: &Cert, errors: usize) -> usize {
    cert.keys().count() * errors
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
    diff.assert_equal_up_to(0, 140);

    test_key_cert_imported(cert, experiment)
}

fn test_key_cert_imported<E>(cert: Cert, experiment: E) -> Result<()>
where
    E: Into<Option<Experiment>>,
{
    let experiment = if let Some(e) = experiment.into() {
        e
    } else {
        Experiment::new()?
    };

    let diff = experiment.invoke(&[
        "--list-keys",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(per_subkey(&cert, 1), 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-secret",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-secret",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(per_subkey(&cert, 1), 0);

    let diff = experiment.invoke(&[
        "--list-secret-keys",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--list-secret-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(per_subkey(&cert, 1), 0);

    eprintln!("Importing TSK...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(per_subkey(&cert, 1), 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-secret",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-secret",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(per_subkey(&cert, 1), 0);

    let diff = experiment.invoke(&[
        "--list-secret-keys",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--list-secret-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(per_subkey(&cert, 1), 0);

    Ok(())
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
    let (cert, _) =
        CertBuilder::general_purpose(cs,
                                     Some("Alice Lovelace <alice@lovelace.name>"))
        .generate()?;

    let experiment = Experiment::new()?;

    eprintln!("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 120);

    let diff = experiment.invoke(&[
        "--list-keys",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(per_subkey(&cert, 2), 0);

    eprintln!("Importing TSK...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--list-secret-keys",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--list-secret-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(per_subkey(&cert, 2), 0);

    Ok(())
}
