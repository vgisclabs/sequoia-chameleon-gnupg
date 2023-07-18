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

const PLAINTEXT: &[u8] = b"plaintext";

// We import a certificate, which is not ultimately trusted, and use
// --command-fd and --status-fd.  When gpg is run, it should prompt
// for confirmation via status-fd using a machine readable (rather
// than human readable) prompt.
#[test]
#[ntest::timeout(60000)]
fn untrusted_certificate_prompt() -> Result<()> {
    let cs = CipherSuite::Cv25519;

    let mut experiment = make_experiment!(format!("{:?}", cs))?;
    let cert = experiment.artifact(
        "cert",
        || CertBuilder::general_purpose(
            cs, Some("Alice Lovelace <alice@lovelace.name>"))
            .set_creation_time(Experiment::now())
            .generate()
            .map(|(cert, _rev)| cert),
        |a, f| a.serialize(f),
        |b| Cert::from_bytes(&b))?;

    eprintln!("Importing cert...");
    let diff = experiment.invoke(&[
        "--import",
        &experiment.store("cert", &cert.to_vec()?)?,
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(0, 110);

    let diff = experiment.invoke(&[
        "--command-fd=0",
        "--encrypt",
        "--recipient", "<alice@lovelace.name>",
        "--output", "ciphertext",
        &experiment.store("plaintext", PLAINTEXT)?,
    ])?;

    diff.assert_failure();
    // Why such a big edit distance?  On stdout, gpg prints three
    // KEY_CONSIDERED lines, but the chameleon only prints one and at
    // a different point in time.  With respect to stderr, gpg prints
    // some warning directly to the tty, but the chameleon prints them
    // to stderr.  This is a bug in the chameleon.  When it is fixed,
    // reduce the expected edit distance for stderr to 0.
    diff.assert_limits(0, 395, 245);

    Ok(())
}
