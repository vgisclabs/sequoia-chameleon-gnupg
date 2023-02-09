use anyhow::Result;

use super::super::*;

#[test]
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
fn help() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let diff = experiment.invoke(&[
        "--help",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(370, 0); // Card options and more.
    Ok(())
}

#[test]
fn dump_options() -> Result<()> {
    let mut experiment = make_experiment!()?;
    let diff = experiment.invoke(&[
        "--dump-options",
    ])?;
    diff.assert_success();
    diff.assert_equal_up_to(
        51 // Card options.
            + 23 // Sequoia-specific options.
            + 0,
        0);
    Ok(())
}
