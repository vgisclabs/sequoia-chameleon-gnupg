use anyhow::Result;

use super::super::*;

#[test]
#[ntest::timeout(600000)]
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
