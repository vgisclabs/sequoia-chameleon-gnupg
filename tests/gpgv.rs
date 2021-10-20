use std::{
    collections::BTreeSet,
    fmt,
    fs,
    process::*,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    packet::{*, signature::*},
    types::*,
    serialize::SerializeInto,
};

const MSG: &[u8] = b"Hello, world!";
const GPGV: &[&str] =
    &["/usr/bin/gpgv"];
const GPGV_CHAMELEON: &[&str] =
    &["cargo", "run", "--quiet", "--bin", "sequoia-chameleon-gpgv", "--"];
const GPGV_CHAMELEON_BUILD: &[&str] =
    &["cargo", "run", "--quiet", "--bin", "sequoia-chameleon-gpgv"];

const STDERR_EDIT_DISTANCE_THRESHOLD: usize = 20;

#[test]
fn basic() -> Result<()> {
    build();

    let (cert, rev) = CertBuilder::new()
        .add_userid("Alice Lovelace <alice@lovelace.name>")
        .add_signing_subkey()
        .generate()?;

    let mut subkey_signer =
        cert.keys().subkeys().secret().next().unwrap()
        .key().clone().into_keypair()?;

    let sig = SignatureBuilder::new(SignatureType::Binary)
        .sign_message(&mut subkey_signer, MSG)?;

    let oracle = invoke(&cert, &sig, GPGV)?;
    let us = invoke(&cert, &sig, GPGV_CHAMELEON)?;

    eprintln!("oracle: {}", oracle);
    eprintln!("us: {}", us);

    assert_eq!(oracle.status, us.status);
    assert_eq!(oracle.normalized_status_messages(),
               us.normalized_status_messages());
    assert!(oracle.stderr_edit_distance(&us) < STDERR_EDIT_DISTANCE_THRESHOLD);

    Ok(())
}

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
