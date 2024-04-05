use anyhow::Result;

use sequoia_openpgp::{
    cert::{Cert, CertBuilder},
    parse::Parse,
    serialize::{Serialize, SerializeInto},
};

use super::super::*;

#[test]
#[ntest::timeout(600000)]
fn add_key_no_arg() -> Result<()> {
    add_key(&[], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_default() -> Result<()> {
    add_key(&["default"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_future_default() -> Result<()> {
    add_key(&["future-default"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_rsa() -> Result<()> {
    add_key(&["rsa"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_rsa2048() -> Result<()> {
    add_key(&["rsa2048"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_dsa() -> Result<()> {
    add_key(&["dsa"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_ed25519() -> Result<()> {
    add_key(&["ed25519"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_cv25519() -> Result<()> {
    add_key(&["cv25519"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_nistp256() -> Result<()> {
    add_key(&["nistp256"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_default_default() -> Result<()> {
    add_key(&["default", "default"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_default_encr() -> Result<()> {
    add_key(&["default", "encr"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_default_encrypt() -> Result<()> {
    add_key(&["default", "encrypt"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_default_sign() -> Result<()> {
    add_key(&["default", "sign"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_default_auth() -> Result<()> {
    add_key(&["default", "auth"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_rsa_encrypt_sign() -> Result<()> {
    add_key(&["rsa", "encrypt,sign"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_rsa_encrypt_space_sign() -> Result<()> {
    add_key(&["rsa", "encrypt sign"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_default_default_never() -> Result<()> {
    add_key(&["default", "default", "never"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_default_default_none() -> Result<()> {
    add_key(&["default", "default", "none"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_default_default_dash() -> Result<()> {
    add_key(&["default", "default", "-"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_default_default_1y() -> Result<()> {
    add_key(&["default", "default", "1y"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_default_default_iso_date() -> Result<()> {
    add_key(&["default", "default", "2023-01-01"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_default_default_iso_time() -> Result<()> {
    add_key(&["default", "default", "20230101T123456"], make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn add_key_all_dashes() -> Result<()> {
    add_key(&["-", "-", "-"], make_experiment!()?)
}

fn add_key(parameters: &[&str], mut experiment: Experiment) -> Result<()>
{
    let key = experiment.artifact(
        "key",
        || CertBuilder::new()
            .set_creation_time(Experiment::now())
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    experiment.section("Importing key...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("key", &key.as_tsk().to_vec()?)?,
    ])?.canonicalize_fingerprints(0)?;
    diff.assert_success();
    diff.assert_limits(0, 0, 67);

    // Reduce noise.
    let diff = experiment.invoke(&[
        "--check-trustdb",
    ])?;
    diff.assert_success();

    experiment.section("Adding a subkey, quickly...");
    let fp = key.fingerprint().to_string();
    let args = [
        "--batch",
        "--passphrase=streng geheim",
        "--quick-add-key", fp.as_str(),
    ].iter().cloned()
        .chain(parameters.iter().cloned())
        .collect::<Vec<_>>();
    let diff = experiment.invoke(&args)?.canonicalize_fingerprints(1)?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    Ok(())
}

#[test]
#[ntest::timeout(600000)]
fn add_uid() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let key = experiment.artifact(
        "key",
        || CertBuilder::new()
            .set_creation_time(Experiment::now())
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    experiment.section("Importing key...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("key", &key.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();

    experiment.section("Adding a uid to key by fingerprint, quickly...");
    let fp = key.fingerprint().to_string();
    let diff = experiment.invoke(&[
        "--batch",
        "--quick-add-uid", fp.as_str(), "<hacker@example.org>",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    experiment.section("Adding a uid to key by email, quickly...");
    let diff = experiment.invoke(&[
        "--batch",
        "--quick-add-uid", "<alice@lovelace.name>", "<phreaker@example.net>",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    experiment.section("Adding a uid to key by substring match, quickly...");
    let diff = experiment.invoke(&[
        "--batch",
        "--quick-add-uid", "alice", "<punk@example.com>",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    Ok(())
}

#[test]
#[ntest::timeout(600000)]
fn revoke_uid() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let a_little_earlier = Experiment::now() - Duration::new(15, 0);
    let key = experiment.artifact(
        "key",
        || CertBuilder::new()
            .set_creation_time(a_little_earlier)
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_userid("<hacker@example.org>")
            .add_userid("<phreaker@example.net>")
            .add_userid("<punk@example.com>")
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    experiment.section("Importing key...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("key", &key.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();

    experiment.section("Revoking a uid by fingerprint, quickly...");
    let fp = key.fingerprint().to_string();
    let diff = experiment.invoke(&[
        "--batch",
        "--no-auto-check-trustdb",
        "--quick-revoke-uid", fp.as_str(), "<hacker@example.org>",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    experiment.section("Revoking a uid by email, quickly...");
    let diff = experiment.invoke(&[
        "--batch",
        "--no-auto-check-trustdb",
        "--quick-revoke-uid", "<alice@lovelace.name>", "<phreaker@example.net>",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, "gpg: please do a --check-trustdb\n".len(), 0);

    experiment.section("Revoking a uid by substring match, quickly...");
    let diff = experiment.invoke(&[
        "--batch",
        "--no-auto-check-trustdb",
        "--quick-revoke-uid", "alice", "<punk@example.com>",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, "gpg: please do a --check-trustdb\n".len(), 0);

    let diff = experiment.invoke(&[
        "--no-auto-check-trustdb",
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_limits(2, "gpg: please do a --check-trustdb\n".len(), 0);

    Ok(())
}
