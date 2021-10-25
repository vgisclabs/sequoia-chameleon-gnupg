use std::{
    collections::BTreeSet,
    fmt,
    fs,
    process::*,
    time::*,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    packet::{*, signature::*},
    types::{ReasonForRevocation, SignatureType},
    serialize::SerializeInto,
};

const MSG: &[u8] = b"Hello, world!";
const MSG_BAD: &[u8] = b"Hello, world?";

lazy_static::lazy_static! {
    static ref GPGV: [&'static str; 1] =
        [std::env::var("REAL_GPGV_BIN")
          .map(|s| &*Box::leak(s.into_boxed_str()))
          .unwrap_or("/usr/bin/gpgv")];
}

const GPGV_CHAMELEON: &[&str] =
    &["cargo", "run", "--quiet", "--bin", "sequoia-chameleon-gpgv", "--"];
const GPGV_CHAMELEON_BUILD: &[&str] =
    &["cargo", "run", "--quiet", "--bin", "sequoia-chameleon-gpgv"];

const STDERR_EDIT_DISTANCE_THRESHOLD: usize = 20;

#[test]
fn basic() -> Result<()> {
    setup();

    let (cert, _) = CertBuilder::new()
        .add_userid("Alice Lovelace <alice@lovelace.name>")
        .add_signing_subkey()
        .generate()?;

    let mut subkey_signer =
        cert.keys().subkeys().secret().next().unwrap()
        .key().clone().into_keypair()?;

    let sig = SignatureBuilder::new(SignatureType::Binary)
        .sign_message(&mut subkey_signer, MSG)?;

    let oracle = invoke(&cert, &sig, &GPGV[..])?;
    let us = invoke(&cert, &sig, GPGV_CHAMELEON)?;

    eprintln!("oracle: {}", oracle);
    eprintln!("us: {}", us);

    assert_eq!(oracle.status, us.status);
    assert_eq!(oracle.normalized_status_messages(),
               us.normalized_status_messages());
    assert!(oracle.stderr_edit_distance(&us) < STDERR_EDIT_DISTANCE_THRESHOLD);

    Ok(())
}

#[test]
fn cipher_suites() -> Result<()> {
    setup();

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
        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(cs)
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .generate()?;

        let mut subkey_signer =
            cert.keys().subkeys().secret().next().unwrap()
            .key().clone().into_keypair()?;

        let sig = SignatureBuilder::new(SignatureType::Binary)
            .sign_message(&mut subkey_signer, MSG)?;

        let oracle = invoke(&cert, &sig, &GPGV[..])?;
        let us = invoke(&cert, &sig, GPGV_CHAMELEON)?;

        eprintln!("oracle: {}", oracle);
        eprintln!("us: {}", us);

        assert_eq!(oracle.status, us.status);
        assert_eq!(oracle.normalized_status_messages(),
                   us.normalized_status_messages());
        assert!(oracle.stderr_edit_distance(&us)
                < STDERR_EDIT_DISTANCE_THRESHOLD);
    }

    Ok(())
}

#[test]
fn signature_types() -> Result<()> {
    setup();

    use SignatureType::*;
    for typ in vec![
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
    ] {
        let (cert, _) = CertBuilder::new()
            .add_userid("Alice Lovelace <alice@lovelace.name>")
            .add_signing_subkey()
            .generate()?;

        let mut subkey_signer =
            cert.keys().subkeys().secret().next().unwrap()
            .key().clone().into_keypair()?;

        let sig = SignatureBuilder::new(typ)
            .sign_message(&mut subkey_signer, MSG)?;

        let oracle = invoke(&cert, &sig, &GPGV[..])?;
        let us = invoke(&cert, &sig, GPGV_CHAMELEON)?;

        eprintln!("oracle: {}", oracle);
        eprintln!("us: {}", us);

        assert_eq!(oracle.status, us.status);
        assert_eq!(oracle.normalized_status_messages(),
                   us.normalized_status_messages());
        assert!(oracle.stderr_edit_distance(&us)
                < STDERR_EDIT_DISTANCE_THRESHOLD);
    }

    Ok(())
}

#[test]
fn extended() -> Result<()> {
    setup();

    let (cert, primary_revocation) = CertBuilder::new()
        .set_creation_time(SystemTime::now() - Duration::new(3600, 0))
        .add_userid("Alice Lovelace <alice@lovelace.name>")
        .add_signing_subkey()
        .generate()?;

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
    let mut subkey_signer =
        subkey.clone().parts_into_secret()?.into_keypair()?;

    let uid_binding_expired =
        uid.bind(&mut primary_signer, &cert,
                 SignatureBuilder::from(uid_binding.clone())
                 .set_key_validity_period(Duration::new(1800, 0))?)?;

    let subkey_binding_expired =
        subkey.bind(&mut primary_signer, &cert,
                    SignatureBuilder::from(subkey_binding.clone())
                    .set_key_validity_period(Duration::new(1800, 0))?)?;

    let subkey_revocation =
        SubkeyRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyRetired,
                                   b"Revoking due to the recent crypto vulnerabilities.")?
        .build(&mut primary_signer, &cert, &subkey, None)?;

    for primary_revoked in vec![false, true] {
        for primary_expired in vec![false, true] {
            for subkey_revoked in vec![false, true] {
                for subkey_expired in vec![false, true] {
                    for good in vec![false, true] {
                        dbg!((primary_revoked, primary_expired,
                              subkey_revoked, subkey_expired,
                              good));

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
                                "/tmp/key-{:?}-{:?}-{:?}-{:?}-{:?}",
                                primary_revoked, primary_expired,
                                subkey_revoked, subkey_expired,
                                good);
                            std::fs::write(name, cert.to_vec()?)?;
                        }

                        let sig = SignatureBuilder::new(SignatureType::Binary)
                            .sign_message(
                                &mut subkey_signer,
                                if good { MSG } else { MSG_BAD })?;

                        let oracle = invoke(&cert, &sig, &GPGV[..])?;
                        let us = invoke(&cert, &sig, GPGV_CHAMELEON)?;

                        eprintln!("oracle: {}", oracle);
                        eprintln!("us: {}", us);

                        assert_eq!(oracle.status, us.status);
                        assert_eq!(oracle.normalized_status_messages(),
                                   us.normalized_status_messages());
                        assert!(oracle.stderr_edit_distance(&us)
                                < STDERR_EDIT_DISTANCE_THRESHOLD);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Sets up the test environment.
fn setup() {
    check_gpgv_oracle();
    build();
}

/// Makes sure that we're talking to the right oracle.
fn check_gpgv_oracle() {
    use std::sync::Once;

    static START: Once = Once::new();
    START.call_once(|| {
        let o = Command::new(&GPGV[0])
            .arg("--version").output().unwrap();
        if String::from_utf8_lossy(&o.stdout).contains("equoia") {
            panic!("The oracle {:?} is Sequoia-based, please provide the \
                    stock gpgv in REAL_GPGV_BIN", GPGV[0]);
        }
    });
}

/// Makes sure that the chameleon is built once.
fn build() {
    use std::sync::Once;

    static START: Once = Once::new();
    START.call_once(|| {
        let prog = GPGV_CHAMELEON_BUILD;
        let mut c = Command::new(&prog[0]);
        for arg in &prog[1..] {
            c.arg(arg);
        }
        c.output().unwrap();
    });
}

fn invoke(cert: &Cert, sig: &Signature, prog: &[&str]) -> Result<Output> {
    let temp = tempfile::tempdir()?;
    let wd = temp.path();

    fs::write(wd.join("cert"), &cert.to_vec()?)?;
    fs::write(wd.join("msg"), MSG)?;
    fs::write(wd.join("sig"), &Packet::from(sig.clone()).to_vec()?)?;

    let mut c = Command::new(&prog[0]);
    for arg in &prog[1..] {
        c.arg(arg);
    }

    c.arg("--status-fd=1")
        .arg("--keyring").arg(wd.join("cert"))
        .arg(wd.join("sig"))
        .arg(wd.join("msg"));
    let out = c.output()?;

    Ok(Output {
        stderr: out.stderr,
        status_fd: out.stdout.split(|c| *c == b'\n').map(Into::into).collect(),
        status: out.status,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct Output {
    stderr: Vec<u8>,
    status_fd: Vec<Box<[u8]>>,
    status: ExitStatus,
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_lines =
            self.status_fd.iter().map(|l| String::from_utf8_lossy(l))
            .collect::<Vec<_>>();

        write!(f, "stderr:\n{}\n\nstatus_fd:\n{}\n\nstatus: {}",
               String::from_utf8_lossy(&self.stderr),
               status_lines.join("\n"),
               self.status)
    }
}

impl Output {
    fn status_messages(&self) -> impl Iterator<Item = &[u8]> {
        self.status_fd.iter()
            .filter(|l| l.starts_with(b"[GNUPG:]"))
            .map(|l| &l[9..])
    }

    fn normalized_status_messages(&self) -> BTreeSet<String> {
        self.status_messages()
            .filter(|l| ! l.starts_with(b"NOTATION_DATA")) // GnuPG bug 5667
            .map(|l| String::from_utf8_lossy(l).to_string())
        // GnuPG emits those if primary key is expired but the subkey
        // is not.  Filter it out, because even the DETAILS admits
        // that this status line is not helpful:
        //
        // > This status line is not very useful because
        // > it will also be emitted for expired subkeys even if this subkey is
        // > not used.  To check whether a key used to sign a message has
        // > expired, the EXPKEYSIG status line is to be used.
            .filter(|l| l != "KEYEXPIRED 0")
        // XXX: For now, exclude compliance messages.
            .filter(|l| ! l.contains("_COMPLIANCE_MODE "))
            .map(|l| {
                if l.starts_with("GOODSIG")
                    || l.starts_with("EXPSIG")
                    || l.starts_with("EXPSIG")
                    || l.starts_with("EXPKEYSIG")
                    || l.starts_with("REVKEYSIG")
                    || l.starts_with("BADSIG")
                {
                    // Normalize to keyid.
                    let mut s = l.splitn(3, " ");
                    let status = s.next().unwrap();
                    let fp = s.next().unwrap();
                    let rest = s.next().unwrap();
                    if fp.len() == 40 {
                        format!("{} {} {}", status, &fp[24..], rest)
                    } else {
                        l
                    }
                } else {
                    l
                }
            })
            .collect()
    }

    fn stderr_edit_distance(&self, to: &Self) -> usize {
        edit_distance::edit_distance(
            &String::from_utf8_lossy(&self.stderr).to_string(),
            &String::from_utf8_lossy(&to.stderr).to_string())
    }
}
