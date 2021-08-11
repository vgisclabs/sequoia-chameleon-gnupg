use anyhow::Context;

#[allow(dead_code)]
mod argparse;

fn real_main() -> anyhow::Result<()> {
    for rarg in argparse::Source::Args(std::env::args()).parse() {
        let (cmd, value) =
            rarg.context("Error parsing command-line arguments")?;
        eprintln!("{:?}: {:?}", cmd, value);
    }
    Ok(())
}

fn main() {
    use std::process::exit;

    match real_main() {
        Ok(()) => exit(0),
        Err(e) => {
            print_error_chain(&e);
            exit(1);
        },
    }
}

/// Prints the error and causes, if any.
fn print_error_chain(err: &anyhow::Error) {
    eprintln!("           {}", err);
    err.chain().skip(1).for_each(|cause| eprintln!("  because: {}", cause));
}
