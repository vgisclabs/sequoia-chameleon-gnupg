use anyhow::Result;

use super::super::*;

#[test]
#[ntest::timeout(60000)]
fn version() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let diff = experiment.invoke(&[
        "--version",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(100, 0); // Different libraries, contact.
    Ok(())
}

#[test]
#[ntest::timeout(60000)]
fn help() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let diff = experiment.invoke(&[
        "--help",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(489, 0); // Card options and more.
    Ok(())
}

#[test]
#[ntest::timeout(60000)]
fn dump_options() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let diff = experiment.invoke(&[
        "--dump-options",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(
        51 // Card options.
            + 89 // Sequoia-specific options.
            + 0,
        0);
    Ok(())
}
