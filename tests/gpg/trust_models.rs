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

/// Tests --trust-model=always.
#[test]
#[ntest::timeout(600000)]
fn always() -> Result<()> {
    let mut experiment = make_experiment!()?;

    let cert = experiment.artifact(
        "cert",
        || CertBuilder::general_purpose(
            None, Some("Alice Lovelace <alice@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    experiment.section("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    run_test(cert, experiment, "always", true)
}

/// Tests --trust-model=pgp.
#[test]
#[ntest::timeout(600000)]
fn pgp() -> Result<()> {
    for (owner_trust, expectation) in [
        (None, false),
        (Some(2), false),
        (Some(3), false),
        (Some(4), false),
        (Some(5), false),
        (Some(6), true),
    ] {
        let mut experiment = make_experiment!(owner_trust.unwrap_or(0))?;

        let cert = experiment.artifact(
            "cert",
            || CertBuilder::general_purpose(
                None, Some("Alice Lovelace <alice@lovelace.name>"))
                .set_creation_time(Experiment::now())
                .generate()
                .map(|(cert, _rev)| cert),
            |a, f| a.as_tsk().serialize(f),
            |b| Cert::from_bytes(&b))?;

        experiment.section("Importing cert...");
        let diff = experiment.invoke(&[
            "--import",
            &experiment.store("cert", &cert.to_vec()?)?,
        ])?;
        diff.assert_success();
        diff.assert_equal_up_to(0, 0);

        if let Some(owner_trust) = owner_trust {
            experiment.section(
                format!("Setting ownertrust to {}...", owner_trust));
            let diff = experiment.invoke(&[
                "--import-ownertrust",
                &experiment.store("ownertrust",
                                  &format!("{:X}:{}:\n",
                                           cert.fingerprint(), owner_trust))?,
            ])?;
            diff.assert_success();
            diff.assert_equal_up_to(0, 9);
        }

        run_test(cert, experiment, "pgp", expectation)?;
    }

    Ok(())
}

/// Tests --trust-model=auto.
#[test]
#[ntest::timeout(600000)]
fn auto() -> Result<()> {
    for (owner_trust, expectation) in [
        (None, false),
        (Some(2), false),
        (Some(3), false),
        (Some(4), false),
        (Some(5), false),
        (Some(6), true),
    ] {
        let mut experiment = make_experiment!(owner_trust.unwrap_or(0))?;

        let cert = experiment.artifact(
            "cert",
            || CertBuilder::general_purpose(
                None, Some("Alice Lovelace <alice@lovelace.name>"))
                .set_creation_time(Experiment::now())
                .generate()
                .map(|(cert, _rev)| cert),
            |a, f| a.as_tsk().serialize(f),
            |b| Cert::from_bytes(&b))?;

        experiment.section("Importing cert...");
        let diff = experiment.invoke(&[
            "--import",
            &experiment.store("cert", &cert.to_vec()?)?,
        ])?;
        diff.assert_success();
        diff.assert_equal_up_to(0, 0);

        if let Some(owner_trust) = owner_trust {
            experiment.section(
                format!("Setting ownertrust to {}...", owner_trust));
            let diff = experiment.invoke(&[
                "--import-ownertrust",
                &experiment.store("ownertrust",
                                  &format!("{:X}:{}:\n",
                                           cert.fingerprint(), owner_trust))?,
            ])?;
            diff.assert_success();
            diff.assert_equal_up_to(0, 9);
        }

        run_test(cert, experiment, "auto", expectation)?;
    }

    Ok(())
}

/// Runs an experiment with both implementations.
///
/// First, we import a cert, let the caller modify the environment
/// with `frobber`, check the trust database, lists the cert comparing
/// the machine readable output (which includes trust information
/// derived from the trust model), and tries to authenticate the cert.
fn run_test(cert: Cert, mut experiment: Experiment, model: &'static str,
            expect_success: bool)
            -> Result<()>
{
    experiment.section("Checking the trust database...");
    let diff = experiment.invoke(&["--check-trustdb"])?;
    diff.assert_success();

    // Now list the certs.
    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(11, // Next trust db check time.
                            0);

    // Try to authenticate the certificate as a recipient.
    let diff = experiment.invoke(&[
        "--batch",
        "--no-auto-key-locate",
        "--trust-model", model,
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

        experiment.section("Importing key...");
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
            diff.assert_limits(0, 1, 0);
            diff.with_working_dir(|p| {
                assert_eq!(p.get("plaintext").expect("no output"), PLAINTEXT);
                Ok(())
            })?;
        }
    } else {
        diff.assert_failure();
        diff.assert_limits(0, 0, 0);
        assert!(diff.with_working_dir(
            |p| Ok(p.get("ciphertext").is_some()))?
                .iter().all(|&exists| exists == false));
    }

    Ok(())
}
