use std::{
    time::*,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    packet::{prelude::*, key::*},
    parse::Parse,
    policy::StandardPolicy,
    serialize::{Serialize, SerializeInto},
    types::{Curve, KeyFlags, SignatureType},
};

use super::super::*;

#[test]
#[ntest::timeout(600000)]
fn empty() -> Result<()> {
    let mut experiment = make_experiment!()?;

    let diff = experiment.invoke(&[
        "--list-keys",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

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
#[ntest::timeout(600000)]
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
#[ntest::timeout(600000)]
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
#[ntest::timeout(600000)]
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
#[ntest::timeout(600000)]
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
#[ntest::timeout(600000)]
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
#[ntest::timeout(600000)]
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
#[ntest::timeout(600000)]
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

    experiment.section("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

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
#[ntest::timeout(600000)]
fn dsa_elgamal() -> Result<()> {
    let experiment = make_experiment!()?;
    let cert = Cert::from_bytes("
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1

lQG7BEZnyykRBACzCPjIpTYNL7Y2tQqlEGTTDlvZcWNLjF5f7ZzuyOqNOidLUgFD
36qch1LZLSZkShdR3Gae+bsolyjxrlFuFP0eXRPMtqK20aLw7WZvPFpEV1ThMne+
PRJjYrvghWw3L0VVIAIZ8GXwrVBuU99uEjHEI0ojYloOvFc2jVPgSaoBvwCg48Tj
fol2foSoJa7XUu9yAL8szg8D/RUsTzNF+I9hSRHl7MYKFMYoKEY9BDgrgAujp7YY
8qdGsiUb0Ggyzp2kRjZFt4lpcvKhGfHn5GEjmtk+fRbD5qPfMqKFW+T0NPfYlYmL
JJ4fs4qZ8Lx7x6iG6X51u+YNwsQuIGjMCC3CeNi3F7or651kkNYASbaQ1NROkCIN
NudyA/0aasvoZUoNJAc2cP5Ifs6WhXMWLfMR2p2XbfKwKNYneec60usnSComcKqh
sJVk0Gytvr3FOYVhRkXnKAbx+0W2urFP8OFVBTEKO6Ts2VygWGgneQYoHnqzwlUE
yjOjlr+lyf7u2s/KAxpKA6jnttEdRZAmzWkhuox1wwAUkr27/QAAn3TEzKR1pxxR
+R3dHuFpnnfatMIDC5O0IkMgTyBNaXR0ZXIgPGNvbW1pdHRlckBleGFtcGxlLmNv
bT6IXgQTEQIAHgUCRmfLKQIbAwYLCQgHAwIDFQIDAxYCAQIeAQIXgAAKCRATtvUe
zd5DDXQdAKC92f+wOrTkbmPEf+u+qA/Gv6BxQwCfQ128JXCi3MpMB8tI2Kmo15tY
gnmdAj0ERmfLThAIAM65eT9T6+gg0fJn+Qxhs3FFDPjxK6AOBS3SieWWmXO6stZZ
plvb7r2+sXYp8HMHntnOX3TRPolIx1dsdkv3W3w8yUzf9Lmo2XMPsZ3/isWdEbOI
A0rO3B1xwbQO7vEoWHeB7uyYIF6YsIH0pMqxkImciwB1tnJPB9OxqPHlD/HyyHr2
voj6nmEGaPQWj8/dkfyenXm6XmNZUZL/slk6tRhNwv4cW3QQLh39nbiz9rqvZMKF
XX8wkY4FdQkJjCGwqzG+7yJcyHvem29/iq//jRLZgdiN8BwV3MCTJyDp8/Wb/d9y
jZcUm1RdtwRiwfhfQ+zmpyspm7OxINfH65rf7f8ABA0IALRiMRs/eOD59jrYXmPS
ZQUbiALlbJJtuP2c9N3WZ5OgrhDiAW+SDIN+hgDynJ9b7C2dE3xNaud4zaXAAF44
J4J0bAo2ZtZoJajw+GXwaZfh4Z7nPNHwEcbFD4/uXPCj9jPkcLOJqGmUY1aXdygo
t3Hn5U/zo8JxPQ83YbJQhkzAOZ/HGowLNqKgGkLLHn1X9qay0CxlfTQeEN5RZyl3
b4qRzGgGALFvoheyZIUw1TbjRpbn3kqlJooEQY02VwXFXfLI/LwzglilH6sSckvs
0WHKLZ+0L6b3CgJHN2RsZ7QxwCBi1aemsvr65FeEXp/AYxaG5duUbsugG8PgoJ06
bsEAAVQNQO3cXWpuiJ/nNLLnWuPunBKJUlurkBdf2GD+m+muF0VpwDchhqqbTO4e
FqOISQQYEQIACQUCRmfLTgIbDAAKCRATtvUezd5DDcHsAKDQcoAtDWJFupVRqleB
Cezx4Q2khACcCs+/LtE8Lb9hC+2cvr3uH5p82AI=
=aEiU
-----END PGP PRIVATE KEY BLOCK-----
")?;

    test_key(cert, experiment)
}

#[test]
#[ntest::timeout(600000)]
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

fn test_key(cert: Cert, mut experiment: Experiment) -> Result<()>
{
    experiment.section("Importing cert...");
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
        "--list-options=show-uid-validity",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--list-options=no-show-uid-validity",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(9, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--list-options=show-uid-validity",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--list-options=no-show-uid-validity",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

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
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--fingerprint",
        "--fingerprint",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-fingerprint",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(1, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-fingerprint",
        "--with-fingerprint",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(1, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-fingerprint",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-fingerprint",
        "--with-fingerprint",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--keyid-format", "none",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(1, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--keyid-format", "lOng",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(1, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--keyid-format", "0xloNg",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(1, 0);

    // --keyid-format is ignored in colons mode.
    let diff = experiment.invoke(&[
        "--list-keys",
        "--keyid-format", "0xlong",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 0);

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
    diff.assert_equal_up_to(0, 0);

    experiment.section("Importing TSK...");
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
    diff.assert_equal_up_to(0, 0);

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
    diff.assert_equal_up_to(0, 0);

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

    experiment.section("Importing cert...");
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
    diff.assert_equal_up_to(0, 0);

    experiment.section("Importing TSK...");
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
    diff.assert_equal_up_to(0, 0);

    Ok(())
}

#[test]
#[ntest::timeout(600000)]
fn list_signatures() -> Result<()> {
    let mut experiment = make_experiment!("setup")?;

    fn certify<F>(certifier: &Cert, target_cert: Cert, target_userid: &UserID,
                  typ: SignatureType, frobber: F)
                  -> Result<Cert>
    where
        F: Fn(SignatureBuilder) -> Result<SignatureBuilder>,
    {
        let p = StandardPolicy::new();

        // Get a usable (alive, non-revoked) certification key.
        let key = certifier
            .keys().with_policy(&p, None)
            .for_certification().alive().revoked(false).nth(0).unwrap().key();
        // Derive a signer.
        let mut signer = key.clone().parts_into_secret()?.into_keypair()?;

        // Update the User ID's binding signature.
        let mut builder = SignatureBuilder::new(typ)
            .set_signature_creation_time(Experiment::now())?;
        builder = frobber(builder)?;
        let new_sig =
            builder.sign_userid_binding(&mut signer,
                                        Some(target_cert.primary_key().key()),
                                        target_userid)?;

        target_cert.insert_packets(vec![
            Packet::from(target_userid.clone()),
            Packet::from(new_sig),
        ])
    }

    let alice_uid: UserID = "Alice Lovelace <alice@lovelace.name>".into();
    let alice = experiment.artifact(
        "alice",
        || CertBuilder::general_purpose(
            None, Some(alice_uid.clone()))
            .set_creation_time(Experiment::now())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let barbara = experiment.artifact(
        "barbara",
        || CertBuilder::general_purpose(
            None, Some("Barbara Lovelace <barbara@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let clara = experiment.artifact(
        "clara",
        || CertBuilder::general_purpose(
            None, Some("Clara Lovelace <clara@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let daniela = experiment.artifact(
        "daniela",
        || CertBuilder::general_purpose(
            None, Some("Daniela Lovelace <daniela@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let emelie = experiment.artifact(
        "emelie",
        || CertBuilder::general_purpose(
            None, Some("Emelie Lovelace <emelie@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let finja = experiment.artifact(
        "finja",
        || CertBuilder::general_purpose(
            None, Some("Finja Lovelace <finja@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let gale = experiment.artifact(
        "gale",
        || CertBuilder::general_purpose(
            None, Some("Gale Lovelace <gale@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let hannah = experiment.artifact(
        "hannah",
        || CertBuilder::general_purpose(
            None, Some("Hannah Lovelace <hannah@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let alice = experiment.artifact(
        "alice-certified",
        || {
            let alice =
                certify(&barbara, alice.clone(), &alice_uid,
                        SignatureType::GenericCertification, |b| Ok(b))?;
            let alice =
                certify(&clara, alice, &alice_uid,
                        SignatureType::PersonaCertification, |b| Ok(b))?;
            let alice =
                certify(&daniela, alice, &alice_uid,
                        SignatureType::CasualCertification, |b| Ok(b))?;
            let alice =
                certify(&emelie, alice, &alice_uid,
                        SignatureType::PositiveCertification, |b| Ok(b))?;
            let alice =
                certify(&finja, alice, &alice_uid,
                        SignatureType::PositiveCertification,
                        |b: SignatureBuilder| b.set_trust_signature(3, 120))?;
            let alice =
                certify(&gale, alice, &alice_uid,
                        SignatureType::PositiveCertification,
                        |b: SignatureBuilder| b.set_signature_creation_time(
                            Experiment::now() - Duration::new(3600, 0)))?;
            let alice =
                certify(&gale, alice, &alice_uid,
                        SignatureType::CertificationRevocation,
                        |b: SignatureBuilder| b.set_signature_creation_time(
                            Experiment::now() - Duration::new(1800, 0)))?;
            let alice =
                certify(&hannah, alice, &"<alice@example.org>".into(),
                        SignatureType::PositiveCertification, |b| Ok(b))?;
            Ok(alice)
        },
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let mut experiment = make_experiment!("alice-only")?;

    experiment.section("Importing Alice's cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("alice", &alice.to_vec()?)?,
    ])?;
    diff.assert_success();

    let diff = experiment.invoke(&[
        "--list-keys",
    ])?;
    diff.assert_success();
    diff.assert_limits(1, 0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-sig-list",
    ])?;
    diff.assert_success();
    diff.assert_limits(1, 0, 67);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-sig-list",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 67);

    let diff = experiment.invoke(&[
        "--list-signatures",
    ])?;
    diff.assert_success();
    diff.assert_limits(1, 0, 67);

    let diff = experiment.invoke(&[
        "--list-signatures",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 67);

    let diff = experiment.invoke(&[
        "--list-signatures",
        "--fast-list-mode",
    ])?;
    diff.assert_success();
    diff.assert_limits(1, 0, 0);

    let diff = experiment.invoke(&[
        "--list-signatures",
        "--fast-list-mode",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_limits(4, 0, 0);

    let mut experiment = make_experiment!("all-certs")?;
    experiment.section("Importing the other certs ...");
    let mut certs =
        vec![alice, barbara, clara, daniela, emelie, finja, gale, hannah];
    certs.sort_by_cached_key(|c| c.fingerprint());
    let mut certs_bin = vec![];
    for c in certs {
        c.serialize(&mut certs_bin)?;
    }
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("certs", &certs_bin)?,
    ])?;
    diff.assert_success();

    let diff = experiment.invoke(&[
        "--list-keys",
    ])?;
    diff.assert_success();
    diff.assert_limits(1, 0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-sig-list",
    ])?;
    diff.assert_success();
    diff.assert_limits(1, 0, 536);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-sig-list",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 536);

    let diff = experiment.invoke(&[
        "--list-signatures",
    ])?;
    diff.assert_success();
    diff.assert_limits(1, 0, 536);

    let diff = experiment.invoke(&[
        "--list-signatures",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 536);

    Ok(())
}

#[test]
#[ntest::timeout(600000)]
fn unusable_uids() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        || {
            let aquarter =
                Duration::from_secs(60 * 60 * 24 * 30 * 3);
            let yesteryear = Experiment::now()
                - Duration::from_secs(60 * 60 * 24 * 365);
            let work: UserID =
                "<alice@workwork.example.org>".into();
            let fun: UserID =
                "<alice@funfun.example.org>".into();
            let (cert, _rev) = CertBuilder::new()
                .set_creation_time(yesteryear)
                .add_userid("Alice Lovelace <alice@lovelace.name>")
                .add_signing_subkey()
                .generate()?;
            let mut signer = cert.primary_key().key().clone()
                .parts_into_secret()?.into_keypair()?;

            let work_binding = work.bind(
                &mut signer, &cert,
                SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_signature_creation_time(yesteryear)?
                    .set_signature_validity_period(aquarter)?)?;

            let fun_binding = fun.bind(
                &mut signer, &cert,
                SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_signature_creation_time(yesteryear)?)?;
            let fun_revocation = fun.bind(
                &mut signer, &cert,
                SignatureBuilder::new(SignatureType::CertificationRevocation)
                    .set_signature_creation_time(yesteryear + aquarter)?)?;

            let cert = cert.insert_packets(vec![
                Packet::from(work),
                work_binding.into(),
                fun.into(),
                fun_binding.into(),
                fun_revocation.into(),
            ])?;
            assert_eq!(cert.bad_signatures().count(), 0);
            Ok(cert)
        },
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    experiment.section("Importing cert...");
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
    diff.assert_limits(1, 0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--list-options", "no-show-unusable-uids",
    ])?;
    diff.assert_success();
    diff.assert_limits(1, 0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
        "--list-options", "no-show-unusable-uids",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--list-options", "show-unusable-uids",
    ])?;
    diff.assert_success();
    diff.assert_limits(1, 0, 0);

    let diff = experiment.invoke(&[
        "--list-keys",
        "--with-colons",
        "--list-options", "show-unusable-uids",
    ])?;
    diff.assert_success();
    diff.assert_limits(0, 0, 0);

    Ok(())
}
