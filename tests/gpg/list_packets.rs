use std::{
    io::Write,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    crypto::SessionKey,
    packet::prelude::*,
    parse::Parse,
    serialize::{Serialize, SerializeInto, stream::*},
    types::*,
};
use openpgp::serialize::stream::Encryptor2 as Encryptor;

use super::super::*;

const PLAINTEXT: &[u8] = b"plaintext";

#[test]
#[ntest::timeout(60000)]
fn marker() -> Result<()> {
    let mut experiment = make_experiment!()?;
    list_packets(&mut experiment, vec![0xca, 0x03, 0x50, 0x47, 0x50])?;
    list_packets(&mut experiment,
                 vec![0xca, 0xff, 0x00, 0x00, 0x00, 0x03, 0x50, 0x47, 0x50])?;
    // Legacy CTB.
    list_packets(&mut experiment, vec![0xa8, 0x03, 0x50, 0x47, 0x50])?;
    list_packets(&mut experiment, vec![0xa9, 0x00, 0x03, 0x50, 0x47, 0x50])?;
    list_packets(&mut experiment,
                 vec![0xaa, 0x00, 0x00, 0x00, 0x03, 0x50, 0x47, 0x50])?;
    Ok(())
}

// XXX: For some reason, upon listing this packet, GnuPG will return
// an error.  Ignore for now.
//
//#[test]
//#[ntest::timeout(60000)]
#[allow(dead_code)]
fn trust() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let trust = openpgp::Packet::Trust(vec![23, 24].into());
    list_packets(&mut experiment, trust.to_vec()?)?;
    Ok(())
}

#[test]
#[ntest::timeout(60000)]
fn mdc() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let mdc = Packet::from(MDC::new(Default::default(), Default::default()));
    list_packets(&mut experiment, mdc.to_vec()?)?;
    Ok(())
}

#[test]
#[ntest::timeout(60000)]
fn literal() -> Result<()> {
    let mut experiment = make_experiment!()?;

    let p = experiment.artifact(
        "literal", || {
            let mut l = Literal::new(DataFormat::Binary);
            l.set_body(PLAINTEXT.into());
            Packet::from(l).to_vec()
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    let p = experiment.artifact(
        "text", || {
            let mut l = Literal::new(DataFormat::Text);
            l.set_body(PLAINTEXT.into());
            Packet::from(l).to_vec()
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    let p = experiment.artifact(
        "unknown", || {
            let mut l = Literal::new(b'X'.into());
            l.set_body(PLAINTEXT.into());
            Packet::from(l).to_vec()
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    let p = experiment.artifact(
        "literal_with_metadata", || {
            let mut l = Literal::new(DataFormat::Binary);
            l.set_filename("this is the filename")?;
            l.set_date(Timestamp::from(1685957299))?;
            l.set_body(PLAINTEXT.into());
            Packet::from(l).to_vec()
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    Ok(())
}

#[test]
#[ntest::timeout(60000)]
fn compressed_data() -> Result<()> {
    let mut experiment = make_experiment!()?;

    let p = experiment.artifact(
        "uncompressed", || {
            let mut buf = vec![];
            let message = Message::new(&mut buf);
            let message = Compressor::new(message)
                .algo(CompressionAlgorithm::Uncompressed)
                .build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(PLAINTEXT)?;
            message.finalize()?;
            Ok(buf)
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    let p = experiment.artifact(
        "Zip", || {
            let mut buf = vec![];
            let message = Message::new(&mut buf);
            let message = Compressor::new(message)
                .algo(CompressionAlgorithm::Zip)
                .build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(PLAINTEXT)?;
            message.finalize()?;
            Ok(buf)
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    let p = experiment.artifact(
        "zlib", || {
            let mut buf = vec![];
            let message = Message::new(&mut buf);
            let message = Compressor::new(message)
                .algo(CompressionAlgorithm::Zlib)
                .build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(PLAINTEXT)?;
            message.finalize()?;
            Ok(buf)
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    let p = experiment.artifact(
        "bzip2", || {
            let mut buf = vec![];
            let message = Message::new(&mut buf);
            let message = Compressor::new(message)
                .algo(CompressionAlgorithm::BZip2)
                .build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(PLAINTEXT)?;
            message.finalize()?;
            Ok(buf)
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    Ok(())
}

#[test]
#[ntest::timeout(60000)]
fn userid() -> Result<()> {
    let mut experiment = make_experiment!()?;

    list_packets(&mut experiment, Packet::from(UserID::from("")).to_vec()?)?;

    let p = experiment.artifact(
        "userid_1", || {
            Packet::from(UserID::from("this is UTF-8")).to_vec()
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    let p = experiment.artifact(
        "userid_2", || {
            Packet::from(UserID::from(vec![0; 7])).to_vec()
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    Ok(())
}

#[test]
#[ntest::timeout(60000)]
fn user_attribute() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let ua = b"-----BEGIN PGP ARMORED FILE-----

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
=IFdv
-----END PGP ARMORED FILE-----
";

    list_packets(&mut experiment, ua.to_vec())
}

#[test]
#[ntest::timeout(60000)]
fn signature() -> Result<()> {
    use key::UnspecifiedRole;
    let mut experiment = make_experiment!()?;

    let p = experiment.artifact(
        "binary-sig", || {
            let mut sink = vec![];
            let pair =
                Key4::<_, UnspecifiedRole>::generate_ecc(true, Curve::Ed25519)?
                .into_keypair()?;
            let message = Message::new(&mut sink);
            let mut signer = Signer::new(message, pair)
                .detached().build()?;
            signer.write_all(PLAINTEXT)?;
            signer.finalize()?;
            Ok(sink)
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    let p = experiment.artifact(
        "text-sig", || {
            let mut sink = vec![];
            let pair =
                Key4::<_, UnspecifiedRole>::generate_ecc(true, Curve::Ed25519)?
                .into_keypair()?;
            let message = Message::new(&mut sink);
            let mut signer = Signer::with_template(
                message, pair, SignatureBuilder::new(SignatureType::Text))
                .detached().build()?;
            signer.write_all(PLAINTEXT)?;
            signer.finalize()?;
            Ok(sink)
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    let p = experiment.artifact(
        "clowncar-sig", || {
            use openpgp::types::*;
            use openpgp::packet::signature::subpacket::*;

            let mut sink = vec![];
            let pair =
                Key4::<_, UnspecifiedRole>::generate_ecc(true, Curve::Ed25519)?
                .into_keypair()?;
            let cert = Cert::from_packets(
                vec![Packet::from(pair.public().clone().role_into_primary())]
                    .into_iter())?;
            let message = Message::new(&mut sink);
            let h = HashAlgorithm::default();
            let t = SignatureBuilder::new(SignatureType::Binary)
                .set_attested_certifications(
                    vec![vec![b'@'; h.context()?.digest_size()]])?
                .set_exportable_certification(false)?
                .set_features(Features::sequoia())?
                .set_intended_recipients(
                    vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?])?
                .set_issuer("AAAAAAAAAAAAAAAA".parse()?)?
                .set_issuer_fingerprint(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?)?
                .set_key_validity_period(
                    std::time::Duration::new(1234, 0))?
                .set_key_flags(KeyFlags::empty().set_authentication())?
                .set_key_server_preferences(
                    KeyServerPreferences::empty().set_no_modify())?
                .set_notation(
                    "user@namespace.example",
                    b"a human readable value \"'\\\r\n\t)",
                    NotationDataFlags::empty().set_human_readable(),
                    false)?
                .set_notation(
                    "iana_namespace_example",
                    b"a non-human readable value \"'\\\r\n\t)",
                    NotationDataFlags::empty(),
                    true)?
                .set_policy_uri("https://a.policy.example/\"'\\\r\n\t)")?
                .set_preferred_compression_algorithms(
                    vec![CompressionAlgorithm::Zip])?
                .set_preferred_hash_algorithms(
                    vec![HashAlgorithm::SHA384])?
                .set_preferred_symmetric_algorithms(
                    vec![SymmetricAlgorithm::Camellia128])?
                .set_primary_userid(true)?
                .set_reason_for_revocation(
                    ReasonForRevocation::Unknown(253),
                    b"something bad happened \"'\\\r\n\t)")?
                .set_regular_expression(b"o.O \"'\\\r\n\t)")?
                .set_revocable(true)?
                .set_revocation_key(vec![(&cert).into()])?
                .set_signature_target(
                    PublicKeyAlgorithm::DSA,
                    HashAlgorithm::SHA384,
                    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?
                .set_signature_validity_period(std::time::Duration::new(0, 0))?
                .set_signers_user_id(b"some@example.org \"'\\\r\n\t)")?
                .set_trust_signature(23, 42)?
                .modify_hashed_area(|mut a| {
                    a.add(Subpacket::new(SubpacketValue::Unknown {
                        tag: SubpacketTag::Unknown(253),
                        body: vec![23, 24, 25],
                    }, false)?)?;
                    Ok(a)
                })?;
            let mut signer = Signer::with_template(message, pair, t)
                .detached().build()?;
            signer.write_all(PLAINTEXT)?;
            signer.finalize()?;
            Ok(sink)
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    Ok(())
}

#[test]
#[ntest::timeout(60000)]
fn inline_signed() -> Result<()> {
    use key::UnspecifiedRole;
    let mut experiment = make_experiment!()?;

    let p = experiment.artifact(
        "inline-signed", || {
            let mut buf = vec![];
            let message = Message::new(&mut buf);
            let pair =
                Key4::<_, UnspecifiedRole>::generate_ecc(true, Curve::Ed25519)?
                .into_keypair()?;
            let message = Signer::new(message, pair)
                .build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(PLAINTEXT)?;
            message.finalize()?;
            Ok(buf)
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    Ok(())
}

#[test]
#[ntest::timeout(60000)]
fn encrypted() -> Result<()> {
    let mut experiment = make_experiment!()?;

    let algo = SymmetricAlgorithm::AES128;
    let sk = SessionKey::from(vec![64; algo.key_size()?]);

    let p = experiment.artifact(
        "with-password", || {
            let mut buf = vec![];
            let message = Message::new(&mut buf);
            let message = Encryptor::with_session_key(
                message, algo, sk.clone())?
                .add_passwords(vec!["password"])
                .build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(PLAINTEXT)?;
            message.finalize()?;
            Ok(buf)
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets_(&mut experiment, true, false,
                  vec![format!("--override-session-key={}:{}",
                               u8::from(algo),
                               openpgp::fmt::hex::encode(&sk))],
                  // The offset inside the encryption container is
                  // wrong, but that is a nonsensical value in GnuPG
                  // anyways, so for now I don't bother.
                  2,
                  0,
                  0,
                  p)?;

    let key = experiment.artifact(
        "key",
        ||  CertBuilder::new()
            .set_creation_time(Experiment::now())
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_transport_encryption_subkey()
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.as_tsk().serialize(f),
        |b| Cert::from_bytes(&b))?;

    let p = experiment.artifact(
        "for-cert", || {
            let mut buf = vec![];
            let message = Message::new(&mut buf);
            let message = Encryptor::with_session_key(
                message, algo, sk.clone())?
                .add_recipients(vec![
                    key.keys().subkeys().nth(0).unwrap().key(),
                ])
                .build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(PLAINTEXT)?;
            message.finalize()?;
            Ok(buf)
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets_(&mut experiment, true, false,
                  vec![format!("--override-session-key={}:{}",
                               u8::from(algo),
                               openpgp::fmt::hex::encode(&sk))],
                  // The offset inside the encryption container is
                  // wrong, but that is a nonsensical value in GnuPG
                  // anyways, so for now I don't bother.
                  2
                  // Further, GnuPG reports the size of the ECDH
                  // encrypted session key as one byte smaller for
                  // some reason.
                  + 2,
                  0,
                  0,
                  p.clone())?;

    experiment.section("Importing key...");
    experiment.invoke(&[
        "--import",
        &experiment.store("key", &key.as_tsk().to_vec()?)?,
    ])?.assert_success();

    list_packets_(&mut experiment, true, false,
                  vec![],
                  // The offset inside the encryption container is
                  // wrong, but that is a nonsensical value in GnuPG
                  // anyways, so for now I don't bother.
                  2
                  // Further, GnuPG reports the size of the ECDH
                  // encrypted session key as one byte smaller for
                  // some reason.
                  + 2,
                  // 255 bit key vs 256 bit key.
                  1,
                  0,
                  p)?;

    Ok(())
}

#[test]
#[ntest::timeout(60000)]
fn key_packets() -> Result<()> {
    use key::{PrimaryRole, SubordinateRole};

    let mut experiment = make_experiment!()?;

    let p = experiment.artifact(
        "public primary", || {
            let key: Key<_, _> =
                Key4::<_, PrimaryRole>::generate_ecc(true, Curve::Ed25519)?
                .parts_into_public()
                .into();
            Packet::from(key).to_vec()
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    let p = experiment.artifact(
        "public subkey", || {
            let key: Key<_, _> =
                Key4::<_, SubordinateRole>::generate_ecc(true, Curve::Ed25519)?
                .parts_into_public()
                .into();
            Packet::from(key).to_vec()
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    let p = experiment.artifact(
        "secret primary", || {
            let key: Key<_, _> =
                Key4::<_, PrimaryRole>::generate_ecc(true, Curve::Ed25519)?
                .into();
            Packet::from(key).to_vec()
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

    let p = experiment.artifact(
        "secret subkey", || {
            let key: Key<_, _> =
                Key4::<_, SubordinateRole>::generate_ecc(true, Curve::Ed25519)?
                .into();
            Packet::from(key).to_vec()
        },
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, p)?;

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
            .and_then(|(cert, _rev)| cert.to_vec()),
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, cert)?;

    let key = experiment.artifact(
        "key",
        || CertBuilder::general_purpose(
            cs, Some("Alice Lovelace <alice@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .generate()
            .and_then(|(key, _rev)| key.as_tsk().to_vec()),
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, key)?;

    let key = experiment.artifact(
        "revocation",
        || CertBuilder::general_purpose(
            cs, Some("Alice Lovelace <alice@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .generate()
            .and_then(|(_key, rev)| Packet::from(rev).to_vec()),
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, key)?;

    Ok(())
}

#[test]
#[ntest::timeout(60000)]
fn locked_key() -> Result<()> {
    let mut experiment = make_experiment!()?;

    let key = experiment.artifact(
        "key",
        || CertBuilder::general_purpose(
            None,
            Some("Alice Lovelace <alice@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .set_password(Some("password".into()))
            .generate()
            .and_then(|(key, _rev)| key.as_tsk().to_vec()),
        |a, f| f.write_all(a).map_err(Into::into),
        |b| Ok(b.to_vec()))?;
    list_packets(&mut experiment, key)?;

    Ok(())
}

fn list_packets(experiment: &mut Experiment, p: Vec<u8>) -> Result<()>
{
    list_packets_(experiment, true, false, vec![], 0, 0, 0, p)
}

fn list_packets_(experiment: &mut Experiment,
                 expect_success: bool, expect_failure: bool,
                 additional_args: Vec<String>,
                 out_slack: usize,
                 err_slack: usize,
                 statusfd_slack: usize,
                 p: Vec<u8>) -> Result<()>
{
    let mut args = vec![
        "--list-packets",
    ];
    args.extend(additional_args.iter().map(|s| s.as_str()));
    let packets = experiment.store("packets", &p)?;
    args.push(&packets);

    let diff = experiment.invoke(&args)?;
    if expect_success {
        diff.assert_success();
    }
    if expect_failure {
        diff.assert_failure();
    }
    diff.assert_limits(out_slack, err_slack, statusfd_slack);

    Ok(())
}
