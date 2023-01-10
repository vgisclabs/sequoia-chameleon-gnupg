use std::{
    time::Duration,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    packet::{*, signature::*, key::*},
    types::*,
    parse::Parse,
    policy::StandardPolicy,
    serialize::{Serialize, SerializeInto},
};

use super::super::*;

const MSG: &[u8] = b"Hello, world!";
const MSG_BAD: &[u8] = b"Hello, world?";

#[test]
fn basic() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        || CertBuilder::new()
            .set_creation_time(Experiment::now())
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let sig = experiment.artifact(
        "sig",
        || -> Result<Packet> {
            let mut subkey_signer =
                cert.keys().subkeys().secret().next().unwrap()
                .key().clone().into_keypair()?;

            SignatureBuilder::new(SignatureType::Binary)
                .set_signature_creation_time(Experiment::now())?
                .sign_message(&mut subkey_signer, MSG)
                .map(Into::into)
        },
        |a, f| a.serialize(f),
        |b| Packet::from_bytes(&b))?;

    test_detached_sig(&mut experiment, &cert, sig)
}

#[test]
fn cipher_suites() -> Result<()> {
    use CipherSuite::*;
    for cs in vec![
        Cv25519,
        RSA3k,
        P256,
        P384,
        P521,
        RSA2k,
        RSA4k,
    ] {
        let mut experiment = make_experiment!(format!("{:?}", cs))?;
        let cert = experiment.artifact(
            "cert",
            || CertBuilder::new()
                .set_creation_time(Experiment::now())
                .set_cipher_suite(cs)
                .add_userid("Alice Lovelace <alice@lovelace.name>")
                .add_signing_subkey()
                .generate()
                .map(|(cert, _rev)| cert),
            |a, f| a.as_tsk().serialize(f),
            |b| Cert::from_bytes(&b))?;

        let sig = experiment.artifact(
            "sig",
            || -> Result<Packet> {
                let mut subkey_signer =
                    cert.keys().subkeys().secret().next().unwrap()
                    .key().clone().into_keypair()?;

                SignatureBuilder::new(SignatureType::Binary)
                    .set_signature_creation_time(Experiment::now())?
                    .sign_message(&mut subkey_signer, MSG)
                    .map(Into::into)
            },
            |a, f| a.serialize(f),
            |b| Packet::from_bytes(&b))?;

        test_detached_sig(&mut experiment, &cert, sig)?;
    }

    Ok(())
}

#[test]
fn hash_algos() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        || CertBuilder::new()
            .set_creation_time(Experiment::now())
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    use HashAlgorithm::*;
    for (i, algo) in vec![
        MD5,
        // XXX: Upstream doesn't consider SHA1 weak.
        // SHA1,
        // XXX: Upstream doesn't consider RipeMD weak.
        // RipeMD,
        SHA256,
        SHA384,
        SHA512,
        SHA224,
    ].into_iter().enumerate() {
        let sig = experiment.artifact(
            &format!("sig.{}", algo),
            || -> Result<Packet> {
                let mut subkey_signer =
                    cert.keys().subkeys().secret().next().unwrap()
                    .key().clone().into_keypair()?;

                SignatureBuilder::new(SignatureType::Binary)
                    .set_signature_creation_time(Experiment::now())?
                    .set_hash_algo(algo)
                    .sign_message(&mut subkey_signer, MSG)
                    .map(Into::into)
            },
            |a, f| a.serialize(f),
            |b| Packet::from_bytes(&b))?;

        test_detached_sig_with(&mut experiment,
                               i == 0, &cert,
                               sig,
                               vec![],
                               i > 0)?;
    }

    Ok(())
}

#[test]
fn weak_hash_algos() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        || CertBuilder::new()
            .set_creation_time(Experiment::now())
            .set_cipher_suite(CipherSuite::P521) // Forces SHA512.
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    use HashAlgorithm::*;
    for (i, algo) in vec![
        MD5,
        SHA1,
        RipeMD,
        SHA256,
        SHA384,
        SHA224,
        // Note: We don't test for SHA512 because that is what we use
        // in the binding signatures, and the Chameleon -unlike GnuPG-
        // also considers the weak algorithm set when evaluating
        // binding signatures.
        //
        // SHA512,
    ].into_iter().enumerate() {
        let sig = experiment.artifact(
            &format!("sig.{}", algo),
            || -> Result<Packet> {
                let mut subkey_signer =
                    cert.keys().subkeys().secret().next().unwrap()
                    .key().clone().into_keypair()?;

                SignatureBuilder::new(SignatureType::Binary)
                    .set_signature_creation_time(Experiment::now())?
                    .set_hash_algo(algo)
                    .sign_message(&mut subkey_signer, MSG)
                    .map(Into::into)
            },
            |a, f| a.serialize(f),
            |b| Packet::from_bytes(&b))?;

        test_detached_sig_with(&mut experiment,
                               i == 0, &cert,
                               sig,
                               vec!["--weak-digest", &algo.to_string()],
                               false)?;
    }

    Ok(())
}

#[test]
fn signature_types() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        || CertBuilder::new()
            .set_creation_time(Experiment::now())
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    use SignatureType::*;
    for (i, typ) in vec![
        Binary,
        Text,
        // Trick Sequoia into making weird signatures:
        Unknown(Standalone.into()),
        Unknown(GenericCertification.into()),
        Unknown(PersonaCertification.into()),
        Unknown(CasualCertification.into()),
        Unknown(PositiveCertification.into()),
        Unknown(AttestationKey.into()),
        Unknown(SubkeyBinding.into()),
        Unknown(PrimaryKeyBinding.into()),
        Unknown(DirectKey.into()),
        Unknown(KeyRevocation.into()),
        Unknown(SubkeyRevocation.into()),
        Unknown(CertificationRevocation.into()),
        Unknown(Timestamp.into()),
        Unknown(Confirmation.into()),
        Unknown(77),
    ].into_iter().enumerate() {
        let sig = experiment.artifact(
            &format!("sig.{}", u8::from(typ)),
            || -> Result<Packet> {
                let mut subkey_signer =
                    cert.keys().subkeys().secret().next().unwrap()
                    .key().clone().into_keypair()?;

                SignatureBuilder::new(typ)
                    .set_signature_creation_time(Experiment::now())?
                    .sign_message(&mut subkey_signer, MSG)
                    .map(Into::into)
            },
            |a, f| a.serialize(f),
            |b| Packet::from_bytes(&b))?;

        test_detached_sig_with(&mut experiment,
                               i == 0, &cert,
                               sig,
                               vec![],
                               i < 2)?;
    }

    Ok(())
}

#[test]
fn extended() -> Result<()> {
    let mut experiment = make_experiment!()?;

    let the_past = Experiment::now() - Duration::new(3600, 0);
    let cert = experiment.artifact(
        "cert",
        || CertBuilder::new()
            .set_creation_time(the_past)
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let sig = experiment.artifact(
        "sig",
        || -> Result<Packet> {
            let mut subkey_signer =
                cert.keys().subkeys().secret().next().unwrap()
                .key().clone().into_keypair()?;

            SignatureBuilder::new(SignatureType::Binary)
                .set_signature_creation_time(Experiment::now())?
                .sign_message(&mut subkey_signer, MSG)
                .map(Into::into)
        },
        |a, f| a.serialize(f),
        |b| Packet::from_bytes(&b))?;

    let primary =
        cert.primary_key().key().clone();
    let uid =
        cert.userids().next().unwrap().userid().clone();
    let uid_binding =
        cert.userids().next().unwrap().self_signatures().next().unwrap().clone();
    let subkey =
        cert.keys().subkeys().next().unwrap().key().clone();
    let subkey_binding =
        cert.keys().subkeys().next().unwrap().self_signatures().next().unwrap().clone();

    let mut primary_signer =
        primary.clone().parts_into_secret()?.into_keypair()?;

    let primary_revocation = experiment.artifact(
        "primary_revocation",
        || -> Result<Packet> {
            CertRevocationBuilder::new()
                .set_signature_creation_time(the_past)?
                .set_reason_for_revocation(ReasonForRevocation::KeyRetired,
                                           b"Revoking due to the recent \
                                             crypto vulnerabilities.")?
                .build(&mut primary_signer, &cert, None)
                .map(Into::into)
        },
        |a, f| a.serialize(f),
        |b| Packet::from_bytes(&b))?;

    let subkey_revocation = experiment.artifact(
        "subkey_revocation",
        || -> Result<Packet> {
            SubkeyRevocationBuilder::new()
                .set_signature_creation_time(the_past)?
                .set_reason_for_revocation(ReasonForRevocation::KeyRetired,
                                           b"Revoking due to the recent \
                                             crypto vulnerabilities.")?
                .build(&mut primary_signer, &cert, &subkey, None)
                .map(Into::into)
        },
        |a, f| a.serialize(f),
        |b| Packet::from_bytes(&b))?;

    let uid_binding_expired = experiment.artifact(
        "uid_binding_expired",
        || -> Result<Packet> {
            uid.bind(&mut primary_signer, &cert,
                     SignatureBuilder::from(uid_binding.clone())
                     .set_signature_creation_time(the_past)?
                     .set_key_validity_period(Duration::new(1800, 0))?)
                .map(Into::into)
        },
        |a, f| a.serialize(f),
        |b| Packet::from_bytes(&b))?;

    let subkey_binding_expired = experiment.artifact(
        "subkey_binding_expired",
        || -> Result<Packet> {
            subkey.bind(&mut primary_signer, &cert,
                        SignatureBuilder::from(subkey_binding.clone())
                        .set_signature_creation_time(the_past)?
                        .set_key_validity_period(Duration::new(1800, 0))?)
                .map(Into::into)
        },
        |a, f| a.serialize(f),
        |b| Packet::from_bytes(&b))?;

    let mut i = 0;
    for primary_revoked in vec![false, true] {
        for primary_expired in vec![false, true] {
            for subkey_revoked in vec![false, true] {
                for subkey_expired in vec![false, true] {
                    dbg!((primary_revoked, primary_expired,
                          subkey_revoked, subkey_expired));

                    let mut acc = vec![
                        Packet::from(primary.clone()),
                    ];

                    if primary_revoked {
                        acc.push(primary_revocation.clone().into());
                    }

                    acc.push(uid.clone().into());
                    acc.push(
                        if primary_expired {
                            uid_binding_expired.clone().into()
                        } else {
                            uid_binding.clone().into()
                        }
                    );

                    acc.push(subkey.clone().into());
                    if subkey_revoked {
                        acc.push(subkey_revocation.clone().into());
                    }

                    acc.push(
                        if subkey_expired {
                            subkey_binding_expired.clone().into()
                        } else {
                            subkey_binding.clone().into()
                        }
                    );

                    let cert = Cert::from_packets(acc.into_iter())?;

                    if false {
                        let name = format!(
                            "/tmp/key-{:?}-{:?}-{:?}-{:?}",
                            primary_revoked, primary_expired,
                            subkey_revoked, subkey_expired);
                        std::fs::write(name, cert.to_vec()?)?;
                    }

                    test_detached_sig_with(&mut experiment,
                                           i == 0, &cert,
                                           sig.clone(), vec![],
                                           true)?;
                    i += 1;
                }
            }
        }
    }

    Ok(())
}

#[test]
fn wrong_key() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let cert = experiment.artifact(
        "cert",
        || CertBuilder::new()
            .set_cipher_suite(CipherSuite::RSA2k)
            .set_creation_time(Experiment::now() - Duration::new(3600, 0))
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .add_authentication_subkey()
            .add_storage_encryption_subkey()
            .add_transport_encryption_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let standalone: Key<SecretParts, UnspecifiedRole> =
        experiment.artifact(
            "standalone",
            || -> Result<Key<SecretParts, UnspecifiedRole>> {
                Ok(Key4::generate_ecc(true, Curve::Ed25519)?.into())
            },
            |a, f| {
                use sequoia_openpgp::serialize::Marshal;
                a.serialize(f)
            },
            |b| { Ok(Key::from_bytes(&b)?.try_into()?) })?;

    let p = StandardPolicy::new();
    let vcert = cert.with_policy(&p, Experiment::now())?;
    for (i, (mut signer, signing_capable)) in vcert
        .keys()
        .map(|ka| (ka.key().clone().parts_into_secret().unwrap(),
                   ka.for_signing()))
        .chain(std::iter::once((standalone, false)))
        .map(|(key, signing_capable)|
             (key.into_keypair().unwrap(), signing_capable))
        .enumerate()
    {
        dbg!(i);
        let sig = experiment.artifact(
            &format!("sig.{}", i),
            || -> Result<Packet> {
                SignatureBuilder::new(SignatureType::Binary)
                    .set_signature_creation_time(Experiment::now())?
                    .sign_message(&mut signer, MSG)
                    .map(Into::into)
            },
            |a, f| a.serialize(f),
            |b| Packet::from_bytes(&b))?;


        if false {
            std::fs::write("/tmp/key", cert.to_vec()?)?;
            std::fs::write("/tmp/sig", sig.clone().to_vec()?)?;
            std::fs::write("/tmp/msg", MSG)?;
        }

        test_detached_sig_with(&mut experiment,
                               i == 0, &cert,
                               sig, vec![],
                               signing_capable)?;
    }

    Ok(())
}

fn test_detached_sig(experiment: &mut Experiment, cert: &Cert, sig: Packet)
                     -> Result<()>
{
    test_detached_sig_with(experiment, true, cert, sig, vec![], true)
}

fn test_detached_sig_with<'a>(experiment: &mut Experiment,
                              pristine_experiment: bool,
                              cert: &Cert,
                              sig: Packet, extra_args: Vec<&'a str>,
                              expect_success: bool)
                              -> Result<()>
{
    let data_good = vec![
        experiment.store("sig", &sig.to_vec()?)?,
        experiment.store("msg", &MSG)?,
    ];

    let data_bad = vec![
        data_good[0].clone(),
        experiment.store("msg_bad", &MSG_BAD)?,
    ];

    let mut args_good = vec![
        "--status-fd=1",
        "--verify",
    ];
    args_good.extend_from_slice(&extra_args);
    data_good.iter().for_each(|a| args_good.push(a));

    let mut args_bad = vec![
        "--status-fd=1",
        "--verify",
    ];
    args_bad.extend_from_slice(&extra_args);
    data_bad.iter().for_each(|a| args_bad.push(a));

    // If we reuse the `experiment` in a loop, we only import the cert
    // once, and we can only test the failures related to the missing
    // key before we import it.
    if pristine_experiment {
        // Create the keyring stores.  Reduces the noise in the upcoming
        // experiments.
        let diff = experiment.invoke(&["--list-keys"])?;
        diff.assert_success();

        // First without the cert.
        let diff = experiment.invoke(&args_good)?;
        diff.assert_failure();
        diff.assert_equal_up_to(0, 20);

        let diff = experiment.invoke(&args_bad)?;
        diff.assert_failure();
        diff.assert_equal_up_to(0, 20);

        // Now try gpgv.
        let empty_keyring = experiment.store("empty", b"")?;
        let mut args_good = vec![
            "gpgv",
            "--keyring", &empty_keyring,
            "--status-fd=1",
        ];
        args_good.extend_from_slice(&extra_args);
        data_good.iter().for_each(|a| args_good.push(a));
        let diff = experiment.invoke(&args_good)?;
        diff.assert_failure();
        diff.assert_equal_up_to(0, 20);

        let mut args_bad = vec![
            "gpgv",
            "--keyring", &empty_keyring,
            "--status-fd=1",
        ];
        args_bad.extend_from_slice(&extra_args);
        data_bad.iter().for_each(|a| args_bad.push(a));
        let diff = experiment.invoke(&args_bad)?;
        diff.assert_failure();
        diff.assert_equal_up_to(0, 20);

        eprintln!("Importing cert...");
        let diff = experiment.invoke(&[
            "--import",
            &experiment.store("cert", &cert.to_vec()?)?,
        ])?;
        diff.assert_success();
        diff.assert_equal_up_to(0, 20);
    }

    let diff = experiment.invoke(&args_good)?;
    if expect_success {
        diff.assert_success();
        diff.assert_equal_up_to(134, 10);
    } else {
        diff.assert_failure();
        diff.assert_equal_up_to(0, 10);
    }

    let diff = experiment.invoke(&args_bad)?;
    diff.assert_failure();
    if expect_success {
        diff.assert_equal_up_to(134, 10);
    } else {
        diff.assert_equal_up_to(0, 10);
    }

    // Now try gpgv.
    let cert = &experiment.store("cert", &cert.to_vec()?)?;
    let mut args_good = vec![
        "gpgv",
        "--keyring", &cert,
        "--status-fd=1",
    ];
    args_good.extend_from_slice(&extra_args);
    data_good.iter().for_each(|a| args_good.push(a));
    let diff = experiment.invoke(&args_good)?;
    if expect_success {
        diff.assert_success();
        //diff.assert_equal_up_to(0, 10);
    } else {
        diff.assert_failure();
        diff.assert_equal_up_to(0, 10);
    }

    let mut args_bad = vec![
        "gpgv",
        "--keyring", &cert,
        "--status-fd=1",
    ];
    args_bad.extend_from_slice(&extra_args);
    data_bad.iter().for_each(|a| args_bad.push(a));
    let diff = experiment.invoke(&args_bad)?;
    diff.assert_failure();
    if expect_success {
        //diff.assert_equal_up_to(200, 10);
    } else {
        diff.assert_equal_up_to(0, 10);
    }

    Ok(())
}
