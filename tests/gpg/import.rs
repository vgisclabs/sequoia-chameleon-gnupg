use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Packet,
    cert::prelude::*,
    parse::Parse,
    serialize::{
        Serialize,
        SerializeInto,
    },
    types::ReasonForRevocation,
};

use super::super::*;

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
    test_key(&format!("{:?}", cs),
             "convert-sk-to-pk", // This is a NOP option.
             || CertBuilder::general_purpose(
                 cs, Some("Alice Lovelace <alice@lovelace.name>"))
             .set_creation_time(Experiment::now())
             .generate()
             .map(|(cert, _rev)| cert))?;
    test_key(&format!("{:?}", cs),
             "import-show",
             || CertBuilder::general_purpose(
                 cs, Some("Alice Lovelace <alice@lovelace.name>"))
             .set_creation_time(Experiment::now())
             .generate()
             .map(|(cert, _rev)| cert))?;
    Ok(())
}

fn test_key<F>(slug: &str, options: &str, cert_factory: F) -> Result<()>
where
    F: Fn() -> Result<Cert>,
{
    // We do the experiment twice, once to test the human readable
    // output, then to test the machine readable output.  As importing
    // material is inherently stateful, we need to do it in two
    // different experiments.

    // Human-readable experiment.
    let mut experiment =
        make_experiment!(format!("{}-{}-human-readable", options, slug))?;
    let cert = experiment.artifact(
        "cert",
        &cert_factory,
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    experiment.section("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        "--import-options", options,
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    experiment.section("Importing cert again, unchanged...");
    let diff = experiment.invoke(&[
        "--import",
        "--import-options", options,
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    experiment.section("Importing key...");
    let diff = experiment.invoke(&[
        "--import",
        "--import-options", options,
        &experiment.store("key", &cert.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();
    // STDOUT: agent gives spurious information to GnuPG because it
    // doesn't know the key yet.  GnuPG marks that with an #, but this
    // happens only during initial import, so it is more a fluke,
    // really.  Let's see if we can get away with not emulating that.
    diff.assert_limits(3, 0, 67);

    experiment.section("Importing key again, unchanged...");
    let diff = experiment.invoke(&[
        "--import",
        "--import-options", options,
        &experiment.store("key", &cert.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 67);

    // Machine-readable experiment.
    let mut experiment =
        make_experiment!(format!("{}-{}-machine-readable", options, slug))?;
    let cert = experiment.artifact(
        "cert",
        &cert_factory,
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    experiment.section("Importing cert...");
    let diff = experiment.invoke(&[
        "--with-colons",
        "--import",
        "--import-options", options,
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    // STDOUT: Curve25519 key length.
    diff.assert_limits(3, 0, 0);

    experiment.section("Importing cert again, unchanged...");
    let diff = experiment.invoke(&[
        "--with-colons",
        "--import",
        "--import-options", options,
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    // STDOUT: Curve25519 key length.
    diff.assert_limits(3, 0, 0);

    experiment.section("Importing key...");
    let diff = experiment.invoke(&[
        "--with-colons",
        "--import",
        "--import-options", options,
        &experiment.store("key", &cert.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();
    // STDOUT: agent gives spurious information to GnuPG because it
    // doesn't know the key yet.  GnuPG marks that with an #, but this
    // happens only during initial import, so it is more a fluke,
    // really.  Let's see if we can get away with not emulating that.
    // STDOUT: Curve25519 key length.
    diff.assert_limits(3 + 3, 0, 67);

    experiment.section("Importing key again, unchanged...");
    let diff = experiment.invoke(&[
        "--with-colons",
        "--import",
        "--import-options", options,
        &experiment.store("key", &cert.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();
    // STDOUT: Bug in GnuPG: Field 15, serial number of token, should
    // indicate with a '+' that the secret is available, but GnuPG
    // doesn't do that.
    // STDOUT: Curve25519 key length.
    diff.assert_limits(3 + 3, 0, 67);


    Ok(())
}

#[test]
#[ntest::timeout(600000)]
fn cert_revocation() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        || {
            let (cert, _) = CertBuilder::new()
                .set_creation_time(Experiment::now())
                .add_userid("Alice Lovelace <alice@lovelace.name>")
                .add_signing_subkey()
                .generate()?;
            Ok(cert)
        },
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let rev = experiment.artifact(
        "rev",
        || {
            // Create and sign a revocation certificate.
            let mut signer = cert.primary_key().key().clone()
                .parts_into_secret()?.into_keypair()?;
            CertRevocationBuilder::new()
                .set_signature_creation_time(Experiment::now())?
                .set_reason_for_revocation(ReasonForRevocation::KeyCompromised,
                                           b"It was the maid :/")?
                .build(&mut signer, &cert, None)
                .map(Packet::from)
        },
        |a, f| a.serialize(f),
        |b| Packet::from_bytes(&b))?;

    test_revocation(cert, rev, experiment)
}

fn test_revocation(cert: Cert, rev: Packet, mut experiment: Experiment)
                   -> Result<()>
{
    experiment.section("Importing revocation without knowing the cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("rev", &rev.to_vec()?)?,
    ])?;
    diff.assert_limits(0, 0, 0);

    experiment.section("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();

    experiment.section("Importing revocation...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("rev", &rev.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 38 /* no ultimately trusted keys found */, 0);

    Ok(())
}
