use anyhow::Context;

#[allow(dead_code)]
mod argparse;

fn real_main() -> anyhow::Result<()> {
    use argparse::CmdOrOpt;

    // First pass: handle --help and other implicit commands.
    for rarg in argparse::Source::parse_command_line() {
        let (cmd, _value) =
            rarg.context("Error parsing command-line arguments")?;
        match cmd {
            CmdOrOpt::aHelp => return Ok(argparse::help()),
            CmdOrOpt::aVersion => return Ok(argparse::version()),
            CmdOrOpt::aWarranty => return Ok(argparse::warranty()),
            CmdOrOpt::aDumpOptions => return Ok(argparse::dump_options()),
            CmdOrOpt::aDumpOpttbl => return Ok(argparse::dump_options_table()),
            _ => (),
        }
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
