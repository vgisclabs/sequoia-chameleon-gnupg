use std::{
    path::PathBuf,
};

use anyhow::{Context, Result};

#[macro_use]
mod macros;
#[allow(dead_code)]
mod argparse;

struct Config {
    homedir: PathBuf,
    no_homedir_creation: bool,
    no_perm_warn: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            homedir: std::env::var_os("GNUPGHOME")
                .map(Into::into)
                .unwrap_or_else(|| dirs::home_dir()
                                .expect("cannot get user's home directory")
                                .join(".gnupg")),
            no_homedir_creation: false,
            no_perm_warn: false,
        }
    }
}

impl Config {
    /// Checks whether the permissions on the state directory are
    /// sane.
    fn check_homedir_permissions(&self) -> Result<()> {
        if ! self.homedir.exists() {
            // Not yet created.
            return Ok(());
        }

        platform! {
            unix => {
                use std::os::unix::fs::MetadataExt;

                // The homedir must be x00, a directory, and owned by
                // the user.
                let m = std::fs::metadata(&self.homedir)?;

                if ! m.is_dir() {
                    eprintln!("WARNING: homedir {:?} is not a directory",
                              self.homedir);
                }

                if m.uid() != unsafe { libc::getuid() } {
                    eprintln!("WARNING: unsafe ownership on homedir {:?}",
                              self.homedir);
                }

                if m.mode() & (libc::S_IRWXG | libc::S_IRWXO) > 0 {
                    eprintln!("WARNING: unsafe permissions on homedir {:?}",
                              self.homedir);
                }
            },

            windows => {
                // XXX: What can we check?
            },
        }

        Ok(())
    }
}

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

    let mut opt = Config::default();

    // Second pass: check special options.
    for rarg in argparse::Source::parse_command_line() {
        let (cmd, value) =
            rarg.context("Error parsing command-line arguments")?;
        match cmd {
            CmdOrOpt::oNoOptions => opt.no_homedir_creation = true,
            CmdOrOpt::oHomedir =>
                opt.homedir = value.as_str().unwrap().into(),
            CmdOrOpt::oNoPermissionWarn => opt.no_perm_warn = true,
            _ => (),
        }
    }

    opt.check_homedir_permissions()?;

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
