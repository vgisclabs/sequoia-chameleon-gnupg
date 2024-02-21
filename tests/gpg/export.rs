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

    test_key(cert, experiment)
}

/// GnuPG emits old-style packets, which will change the CTB and the
/// length encoding, incurring a per-packet difference.
fn n_packets(cert: &Cert) -> usize {
    cert.clone().into_packets2().count()
}

fn test_key(cert: Cert, mut experiment: Experiment) -> Result<()> {
    experiment.section("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    experiment.section("Exporting cert...");
    let diff = experiment.invoke(&[
        "--export",
    ])?;
    diff.assert_success();
    diff.assert_limits(n_packets(&cert) * 3, 0, 0);

    // The output is broken into chunks.  Undo that.
    let dane_re = regex::bytes::Regex::new("\n\t")?;
    let diff = experiment.invoke(&[
        "--export",
        "--export-options", "export-dane",
    ])?.canonicalize_with(
        |o| Ok(o.stdout = dane_re.replace_all(&o.stdout, b"").into()))?;
    diff.assert_success();
    // The diff is amplified because of the hex encoding.
    diff.assert_limits(n_packets(&cert) * 3 * 2, 0, 0);

    Ok(())
}
