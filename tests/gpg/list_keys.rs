use std::{
    time::*,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    packet::{prelude::*, key::*},
    parse::Parse,
    serialize::{Serialize, SerializeInto},
    types::{Curve, KeyFlags, SignatureType},
};

use super::super::*;

#[test]
#[ntest::timeout(60000)]
fn empty() -> Result<()> {
    let mut experiment = make_experiment!()?;

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
#[ntest::timeout(60000)]
fn queries() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        ||  CertBuilder::new()
            .set_creation_time(Experiment::now())
            .add_userid("Alice Lovelace")
            .add_userid("<alice@lovelace.name>")
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    // Create the keyring stores.  Reduces the noise in the upcoming
    // experiments.
    let diff = experiment.invoke(&["--list-keys"])?;
    diff.assert_success();

    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    for query in ["alice",
                  "Alice",
                  "Lovelace",
                  "Alice Lovelace",
                  "<alice@lovelace.name>",
                  "Alice Lovelace <alice@lovelace.name>",
                  "ALICE",
                  "alice lovelace",
                  "<ALICE@lovelace.name>",
                  "<alice@LOVELACE.NAME>",
    ] {
        let diff = experiment.invoke(&[
            "--list-keys", query,
        ])?;
        diff.assert_success();
        diff.assert_limits(9, 0, 67);
    }

    // It is possible to specify multiple search terms.  In this case
    // gpg only fails if all search terms return nothing.
    let diff = experiment.invoke(&[
        "--list-keys",
        "not_present1@example.org",
        "not_present2@example.org",
    ])?;
    diff.assert_failure();
    diff.assert_limits(0, 0, 32);

    let diff = experiment.invoke(&[
        "--list-keys",
        "not_present1@example.org",
        "alice",
        "not_present2@example.org",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 67);

    // If two patterns match the same certificate, the certificate
    // should only be output once.
    let diff = experiment.invoke(&[
        "--list-keys",
        "not_present1@example.org",
        "alice",
        &cert.fingerprint().to_string(),
        "not_present2@example.org",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 67);

    Ok(())
}

#[test]
#[ntest::timeout(60000)]
fn valid() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        ||  CertBuilder::new()
            .set_creation_time(Experiment::now())
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    test_key(cert, experiment)
}

#[test]
#[ntest::timeout(60000)]
fn revoked() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        ||  {
            let (cert, rev) = CertBuilder::new()
                .set_creation_time(Experiment::now())
                .add_userid("Alice Lovelace <alice@lovelace.name>")
                .add_signing_subkey()
                .generate()?;
            cert.insert_packets(vec![rev])
        },
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    test_key(cert, experiment)
}

#[test]
#[ntest::timeout(60000)]
fn expired() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let a_week = Duration::new(7 * 24 * 3600, 0);
    let the_past = Experiment::now()
        .checked_sub(2 * a_week)
        .unwrap();
    let cert = experiment.artifact(
        "cert",
        || CertBuilder::new()
            .set_creation_time(the_past)
            .set_validity_period(a_week)
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .set_primary_key_flags(
                KeyFlags::empty().set_signing().set_certification())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    test_key(cert, experiment)
}

#[test]
#[ntest::timeout(60000)]
fn expired_subkey() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let a_week = Duration::new(7 * 24 * 3600, 0);
    let the_past = Experiment::now()
        .checked_sub(2 * a_week)
        .unwrap();
    let cert = experiment.artifact(
        "cert",
        || {
            let (cert, _rev) = CertBuilder::new()
                .set_creation_time(the_past)
                .add_userid("Alice Lovelace <alice@lovelace.name>")
                .set_primary_key_flags(
                    KeyFlags::empty().set_signing().set_certification())
                .generate()?;

            let primary = cert.primary_key().key().clone();
            let mut primary_signer =
                primary.clone().parts_into_secret()?.into_keypair()?;

            let mut subkey: Key<_, SubordinateRole> =
                Key4::generate_ecc(false, Curve::Cv25519)?.into();
            subkey.set_creation_time(the_past)?;
            let builder =
                SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_key_flags(KeyFlags::empty()
                               .set_transport_encryption()
                               .set_storage_encryption())?
                .set_signature_creation_time(the_past)?
                .set_key_validity_period(a_week)?;
            let binding =
                subkey.bind(&mut primary_signer, &cert, builder)?;

            cert.insert_packets(vec![Packet::from(subkey), binding.into()])
        },
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    test_key(cert, experiment)
}

#[test]
#[ntest::timeout(60000)]
fn locked() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        ||  CertBuilder::new()
            .set_creation_time(Experiment::now())
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .set_password(Some("password".into()))
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    test_key(cert, experiment)
}

#[test]
#[ntest::timeout(60000)]
fn disabled() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        ||  CertBuilder::new()
            .set_creation_time(Experiment::now())
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

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
    diff.assert_equal_up_to(0, 9);

    let diff = experiment.invoke(&[
        "--check-trustdb",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 150, 67);

    test_key_cert_imported(cert, experiment)
}

#[test]
#[ntest::timeout(60000)]
fn designated_revoker() -> Result<()> {
    let experiment = make_experiment!()?;
    let cert = Cert::from_bytes("
Thanks to Daniel Kahn Gillmor for providing the test keys.

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.10 (GNU/Linux)

mI0ES+OoSQEEAJUZ/+fC6DXN2X7Wxl4Huud/+i2qP1hcq+Qnbr7hVCKEnn0edYl+
6xfsKmAMBjl+qTZxPSDSx4r3ciMiIbnvXFtlBAQmji86kqoR6fm9s8BN7LTq7+2/
c2FHVF67D7zES7WgHc4i7CfiZnwXgkLvi5b1jBt+MTAOrFhdobxoy6/XABEBAAGI
twQfAQIAIQUCS+OsRRcMgAEO5b6XkoLYC591QPHM0u2U0hc56QIHAAAKCRA0t9EL
wQjoOrRXBACBqhigTcj8pJY14AkjV+ZzUbm55kJRDPdU7NQ1PSvczm7HZaL3b8Lr
Psa5c5+caVLjsGWkQycQl7lUIGU84KoUfwACQKVVLkqJz8LkL54lLcwkG70+1NH5
xoSNcHHVbYtqDLNeCOq5jEIoXuz44wiWVEfF+/B115PvgwZ63pjH1rRGVGVzdCBL
ZXkgRGVtb25zdHJhdGluZyBSZXZva2VyIFRyb3VibGUgKERPIE5PVCBVU0UpIDx0
ZXN0QGV4YW1wbGUubmV0Poi+BBMBAgAoBQJL46hJAhsDBQkACTqABgsJCAcDAgYV
CAIJCgsEFgIDAQIeAQIXgAAKCRA0t9ELwQjoOgLpA/9/si2QYmietY9a6VlAmMri
mhZeqo6zyn8zrO9RGU7+8jmeb5nVnXw1YmZcw2fiJgI9+tTMkTfomyR6k0EDvcEu
2Mg3USkVnJfrrkPjSL9EajW6VpOUNxlox3ZT1oyEo3OOnVF1gC1reWYfy7Ns9zIB
1leLXbMr86zYdCoXp0Xu4g==
=xsEd
-----END PGP PUBLIC KEY BLOCK-----
")?;

    test_key(cert, experiment)
}

/// Allows `errors` for every (sub)key in `cert`.
fn per_subkey(cert: &Cert, errors: usize) -> usize {
    cert.keys().count() * errors
}

fn test_key(cert: Cert, mut experiment: Experiment) -> Result<()>
{
    eprintln!("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();

    test_key_cert_imported(cert, experiment)
}

fn test_key_cert_imported(cert: Cert, mut experiment: Experiment) -> Result<()>
{
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
        "--batch",
        "--import",
        &experiment.store("cert", &cert.as_tsk().to_vec()?)?,
    ])?;
    diff.assert_success();

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
#[ntest::timeout(60000)]
fn general_purpose_cv25519() -> Result<()> {
    general_purpose(CipherSuite::Cv25519)
}

#[test]
#[ntest::timeout(60000)]
fn general_purpose_rsa2k() -> Result<()> {
    general_purpose(CipherSuite::RSA2k)
}

#[test]
#[ntest::timeout(60000)]
fn general_purpose_rsa3k() -> Result<()> {
    general_purpose(CipherSuite::RSA3k)
}

#[test]
#[ntest::timeout(60000)]
fn general_purpose_rsa4k() -> Result<()> {
    general_purpose(CipherSuite::RSA4k)
}

#[test]
#[ntest::timeout(60000)]
fn general_purpose_p256() -> Result<()> {
    general_purpose(CipherSuite::P256)
}

#[test]
#[ntest::timeout(60000)]
fn general_purpose_p384() -> Result<()> {
    general_purpose(CipherSuite::P384)
}

#[test]
#[ntest::timeout(60000)]
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

    eprintln!("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();

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
