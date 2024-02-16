use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    parse::Parse,
    serialize::{
        Serialize,
    },
};

use super::super::*;

#[test]
#[ntest::timeout(600000)]
fn migration_from_secring() -> Result<()> {
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

    // Store secring.gpg into the GNUPGHOME directories.
    for homedir in [
        experiment.oracle.home.path(),
        experiment.us.home.path(),
    ] {
        cert.as_tsk().serialize(
            &mut fs::File::create(homedir.join("secring.gpg"))?)?;
    }

    let diff = experiment.invoke(&[
        "--list-secret-keys",
    ])?;
    diff.assert_success();
    diff.assert_limits(1, 0, 67);

    let diff = experiment.invoke(&[
        "--list-secret-keys",
    ])?;
    diff.assert_success();
    diff.assert_limits(1, 0, 0);

    Ok(())
}
