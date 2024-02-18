use anyhow::Result;

use super::super::*;

#[test]
#[ntest::timeout(600000)]
fn rsa2k_rsa2k() -> Result<()> {
    test_key("Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Name
Name-Comment: Comment
Name-Email: name@example.org
Expire-Date: none
%no-protection
%commit
", make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn rsa2k_rsa2k_locked() -> Result<()> {
    test_key("Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Name
Name-Comment: Comment
Name-Email: name@example.org
Expire-Date: none
Passphrase: password
%commit
", make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn dsa_rsa2k_by_id() -> Result<()> {
    test_key("Key-Type: 17
Key-Length: 2048
# XXX Key-Curve: IgnoredForNonECCTypes
Subkey-Type: 1
Subkey-Length: 2048
Name-Real: Name
Name-Comment: Comment
Name-Email: name@example.org
Expire-Date: none
%no-protection
%commit
", make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn eddsa_ecdh_25519() -> Result<()> {
    test_key("Key-Type: EDDSA
Key-Curve: Ed25519
Subkey-Type: ECDH
Subkey-Curve: Cv25519
Name-Real: Name
Name-Comment: Comment
Name-Email: name@example.org
Expire-Date: none
%no-protection
%commit
", make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn ecdsa_ecdh_nistp256() -> Result<()> {
    test_key("Key-Type: ECDSA
Key-Curve: nistp256
Subkey-Type: ECDH
Subkey-Curve: nistp256
Name-Real: Name
Name-Comment: Comment
Name-Email: name@example.org
Expire-Date: none
%no-protection
%commit
", make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn usage() -> Result<()> {
    test_key("Key-Type: EDDSA
Key-Curve: Ed25519
Key-Usage: cert
Subkey-Type: EDDSA
Subkey-Curve: Ed25519
Subkey-Usage: sign
Name-Real: Name
Name-Comment: Comment
Name-Email: name@example.org
Expire-Date: none
%no-protection
%commit
", make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn creation_time() -> Result<()> {
    test_key("Key-Type: EDDSA
Key-Curve: Ed25519
Subkey-Type: ECDH
Subkey-Curve: Cv25519
Name-Real: Name
Name-Comment: Comment
Name-Email: name@example.org
Expire-Date: none
Creation-Date: 20220105T180052
%no-protection
%commit
", make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn keyserver() -> Result<()> {
    test_key("Key-Type: EDDSA
Key-Curve: Ed25519
Subkey-Type: ECDH
Subkey-Curve: Cv25519
Name-Real: Name
Name-Comment: Comment
Name-Email: name@example.org
Expire-Date: none
Creation-Date: 20220105T180052
Keyserver: https://example.org/my/cert.pgp
%no-protection
%commit
", make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn preferences() -> Result<()> {
    test_key("Key-Type: EDDSA
Key-Curve: Ed25519
Subkey-Type: ECDH
Subkey-Curve: Cv25519
Name-Real: Name
Name-Comment: Comment
Name-Email: name@example.org
Expire-Date: none
Creation-Date: 20220105T180052
Preferences: Z0 bzip2 cAmEllIa256 h1
%no-protection
%commit
", make_experiment!()?)
}

#[test]
#[ntest::timeout(600000)]
fn comments_and_directives() -> Result<()> {
    test_key("# This is a comment
%echo This prints a diagnostic.
%secring /tmp/this/is/a/nop/nowadays
# These are also NOPs with 2.1 and later
%ask-passphrase
%no-ask-passphrase
Key-Type: EDDSA
# ignored for ECC types:
Key-Length: 2048
Key-Curve: Ed25519
Subkey-Type: ECDH
Subkey-Curve: Cv25519
Name-Real: Name
Name-Comment: Comment
Name-Email: name@example.org
Expire-Date: none
%no-protection
%transient-key
%commit
", make_experiment!()?)
}

fn test_key(parameters: &str, mut experiment: Experiment) -> Result<()>
{
    // Reduce noise.
    let diff = experiment.invoke(&[
        "--list-keys",
    ])?;
    diff.assert_success();

    experiment.section("Generating key in batch mode...");
    let diff = experiment.invoke(&[
        "--status-fd=1",
        "--batch",
        "--generate-key",
        &experiment.store("parameters", parameters.as_bytes())?,
    ])?.canonicalize_fingerprints(0)?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    // Reduce noise.
    let diff = experiment.invoke(&[
        "--check-trustdb",
    ])?;
    diff.assert_success();

    test_key_generated(1, experiment)
}

fn test_key_generated(subkeys: usize, mut experiment: Experiment)
                      -> Result<()>
{
    let mut diff = experiment.invoke(&[
        "--list-keys",
        "--with-subkey-fingerprints",
    ])?;
    for i in 0..subkeys {
        diff = diff.canonicalize_fingerprints(1 + i)?;
    }
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let mut diff = experiment.invoke(&[
        "--list-keys",
        "--with-keygrip",
    ])?;
    for i in 0..1 + subkeys {
        diff = diff.canonicalize_fingerprints(i)?;
    }
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(5 + subkeys * 3, 0);

    let diff = experiment.invoke(&[
        "--fingerprint",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--fingerprint",
        "--fingerprint",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--fingerprint",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(5 + subkeys * 3, 0);

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
    diff.assert_equal_up_to(5 + subkeys * 3, 0);

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
    diff.assert_equal_up_to(5 + subkeys * 3, 0);

    Ok(())
}
