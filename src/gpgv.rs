use std::{
    collections::HashSet,
    convert::TryInto,
    fs,
    io,
    path::PathBuf,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    types::*,
};

#[macro_use]
mod macros;
#[allow(dead_code)]
mod argparse;
use argparse::{Opt, flags::*};

/// Commands and options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum CmdOrOpt {
    oQuiet        = 'q' as isize,
    oVerbose      = 'v' as isize,
    oOutput       = 'o' as isize,
    o300 = 300,
    oKeyring,
    oIgnoreTimeConflict,
    oStatusFD,
    oLoggerFD,
    oLoggerFile,
    oHomedir,
    oWeakDigest,
    oEnableSpecialFilenames,
    oDebug,

    // Special, implicit commands.
    aHelp = 'h' as isize,
    aVersion = 32769,
    aWarranty = 32770,
    aDumpOptions = 32771,
    aDumpOpttbl = 32772,
}

impl From<CmdOrOpt> for isize {
    fn from(c: CmdOrOpt) -> isize {
        c as isize
    }
}

use CmdOrOpt::*;

const OPTIONS: &[Opt<CmdOrOpt>] = &[
    Opt { short_opt: o300, long_opt: "", flags: 0, description: "@\nOptions:\n", },
    Opt { short_opt: oVerbose, long_opt: "verbose", flags: TYPE_NONE, description: "verbose", },
    Opt { short_opt: oQuiet, long_opt: "quiet", flags: TYPE_NONE, description: "be somewhat more quiet", },
    Opt { short_opt: oKeyring, long_opt: "keyring", flags: TYPE_STRING, description: "|FILE|take the keys from the keyring FILE", },
    Opt { short_opt: oOutput, long_opt: "output", flags: TYPE_STRING, description: "|FILE|write output to FILE", },
    Opt { short_opt: oIgnoreTimeConflict, long_opt: "ignore-time-conflict", flags: TYPE_NONE, description: "make timestamp conflicts only a warning", },
    Opt { short_opt: oStatusFD, long_opt: "status-fd", flags: TYPE_INT, description: "|FD|write status info to this FD", },
    Opt { short_opt: oLoggerFD, long_opt: "logger-fd", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oLoggerFile, long_opt: "log-file", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oHomedir, long_opt: "homedir", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oWeakDigest, long_opt: "weak-digest", flags: TYPE_STRING, description: "|ALGO|reject signatures made with ALGO", },
    Opt { short_opt: oEnableSpecialFilenames, long_opt: "enable-special-filenames", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oDebug, long_opt: "debug", flags: TYPE_STRING, description: "@", },

    // Special, implicit commands.
    Opt { short_opt: aHelp, long_opt: "help", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aVersion, long_opt: "version", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aWarranty, long_opt: "warranty", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aDumpOptions, long_opt: "dump-options", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aDumpOpttbl, long_opt: "dump-option-table", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
];

struct Config {
    // Configuration.
    debug: u32,
    enable_special_filenames: bool,
    homedir: PathBuf,
    ignore_time_conflict: bool,
    list_sigs: bool,
    outfile: Option<String>,
    quiet: bool,
    verbose: usize,
    verify_options: u32,
    weak_digest: HashSet<HashAlgorithm>,

    // Streams.
    logger_fd: Box<dyn io::Write>,
    status_fd: Box<dyn io::Write>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            // Configuration.
            debug: 0,
            enable_special_filenames: false,
            homedir: std::env::var_os("GNUPGHOME")
                .map(Into::into)
                .unwrap_or_else(|| dirs::home_dir()
                                .expect("cannot get user's home directory")
                                .join(".gnupg")),
            ignore_time_conflict: false,
            list_sigs: false,
            outfile: None,
            quiet: false,
            verbose: 0,
            verify_options: 0,
            weak_digest: Default::default(),

            // Streams.
            logger_fd: Box::new(io::sink()),
            status_fd: Box::new(io::sink()),
        }
    }
}

fn sink_from_fd(fd: i64) -> Result<Box<dyn io::Write>> {
    platform! {
        unix => {
            use std::os::unix::io::FromRawFd;
            let fd = fd.try_into().context(
                format!("Not a valid file descriptor: {}", fd))?;
            Ok(Box::new(unsafe {
                fs::File::from_raw_fd(fd)
            }))
        },
        windows => {
            unimplemented!()
        },
    }
}

fn source_from_fd(fd: i64) -> Result<Box<dyn io::Read>> {
    platform! {
        unix => {
            use std::os::unix::io::FromRawFd;
            let fd = fd.try_into().context(
                format!("Not a valid file descriptor: {}", fd))?;
            Ok(Box::new(unsafe {
                fs::File::from_raw_fd(fd)
            }))
        },
        windows => {
            unimplemented!()
        },
    }
}

fn real_main() -> anyhow::Result<()> {
    let parser = argparse::Parser::new("gpgv", &OPTIONS);
    for rarg in parser.parse_command_line() {
        let (cmd, _value) =
            rarg.context("Error parsing command-line arguments")?;
        match cmd {
            CmdOrOpt::aHelp => return Ok(parser.help()),
            CmdOrOpt::aVersion => return Ok(parser.version()),
            CmdOrOpt::aWarranty => return Ok(parser.warranty()),
            CmdOrOpt::aDumpOptions => return Ok(parser.dump_options()),
            CmdOrOpt::aDumpOpttbl => return Ok(parser.dump_options_table()),
            _ => (),
        }
    }

    let mut opt = Config::default();
    let mut keyrings = Vec::<String>::new();

    // Parse the command line again.
    for rarg in parser.parse_command_line()
    {
        let (cmd, value) =
            rarg.context("Error parsing command-line arguments")?;

        use CmdOrOpt::*;
        match cmd {
	    oQuiet => {
                opt.quiet = true;
            },

	    oVerbose => {
	        opt.verbose += 1;
                opt.list_sigs = true;
	    },

	    oDebug => {
                // XXX:
                //parse_debug_flag (value.as_str().unwrap(), &opt.debug, debug_flags))?;
            },

	    oKeyring => {
                keyrings.push(value.as_str().unwrap().into());
            },

	    oOutput => {
                opt.outfile = Some(value.as_str().unwrap().into());
            },

	    oStatusFD => {
                opt.status_fd = sink_from_fd(value.as_int().unwrap())?;
            },

	    oLoggerFD => {
                opt.logger_fd = sink_from_fd(value.as_int().unwrap())?;
            },
            oLoggerFile => {
                opt.logger_fd =
                    Box::new(fs::File::create(value.as_str().unwrap())?);
            },

            oHomedir => {
                opt.homedir = value.as_str().unwrap().into();
            },

	    oWeakDigest => {
                opt.weak_digest.insert(
                    argparse::utils::parse_digest(value.as_str().unwrap())?);
            },

            oIgnoreTimeConflict => {
                opt.ignore_time_conflict = true;
            },

            oEnableSpecialFilenames => {
                opt.enable_special_filenames = true;
            },

            aHelp
                | aVersion
                | aWarranty
                | aDumpOptions
                | aDumpOpttbl => unreachable!("handled above"),
            o300 => unreachable!("not a real option"),
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
