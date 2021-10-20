use std::{
    collections::HashSet,
    fs,
    io,
    path::{Path, PathBuf},
};

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    types::*,
    policy::{Policy, StandardPolicy},
};

#[macro_use]
mod macros;
#[allow(dead_code)]
mod argparse;
use argparse::{Argument, Opt, flags::*};
mod control;
mod keydb;
mod status;
mod utils;
mod verify;

/// Commands and options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum CmdOrOpt {
    oQuiet        = 'q' as isize,
    oVerbose      = 'v' as isize,
    oOutput       = 'o' as isize,
    o300 = 300,
    o301,
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

    Opt { short_opt: o301, long_opt: "", flags: 0, description: "@\n", },
];

#[allow(dead_code)]
struct Config {
    // Configuration.
    debug: u32,
    enable_special_filenames: bool,
    homedir: PathBuf,
    ignore_time_conflict: bool,
    keydb: keydb::KeyDB,
    list_sigs: bool,
    outfile: Option<String>,
    quiet: bool,
    verbose: usize,
    verify_options: u32,
    weak_digest: HashSet<HashAlgorithm>,

    // Streams.
    logger_fd: Box<dyn io::Write>,
    status_fd: status::Fd,
}

const POLICY: &dyn Policy = &StandardPolicy::new();

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
            keydb: keydb::KeyDB::for_gpgv(),
            list_sigs: false,
            outfile: None,
            quiet: false,
            verbose: 0,
            verify_options: 0,
            weak_digest: Default::default(),

            // Streams.
            logger_fd: Box::new(io::sink()),
            status_fd: Box::new(io::sink()).into(),
        }
    }
}

impl control::Common for Config {
    fn debug(&self) -> u32 {
        self.debug
    }

    fn homedir(&self) -> &Path {
        &self.homedir
    }

    fn keydb(&self) -> &keydb::KeyDB {
        &self.keydb
    }

    fn outfile(&self) -> Option<&String> {
        self.outfile.as_ref()
    }

    fn policy(&self) -> &dyn Policy {
        POLICY
    }

    fn quiet(&self) -> bool {
        self.quiet
    }

    fn verbose(&self) -> usize {
        self.verbose
    }

    fn special_filenames(&self) -> bool {
        self.enable_special_filenames
    }

    fn logger(&mut self) -> &mut dyn io::Write {
        &mut self.logger_fd
    }

    fn status(&self) -> &status::Fd {
        &self.status_fd
    }
}

fn real_main() -> anyhow::Result<()> {
    let parser = argparse::Parser::new(
        "gpgv",
        "Check signatures against known trusted keys",
        &OPTIONS);
    for rarg in parser.parse_command_line().quietly() {
        let arg =
            rarg.context("Error parsing command-line arguments")?;
        match arg {
            Argument::Option(aHelp, _) =>
                return Ok(parser.help()),
            Argument::Option(aVersion, _) =>
                return Ok(parser.version()),
            Argument::Option(aWarranty, _) =>
                return Ok(parser.warranty()),
            Argument::Option(aDumpOptions, _) =>
                return Ok(parser.dump_options()),
            Argument::Option(aDumpOpttbl, _) =>
                return Ok(parser.dump_options_table()),
            _ => (),
        }
    }

    let mut opt = Config::default();
    let mut args = Vec::new();
    let mut keyrings = Vec::<String>::new();

    // Parse the command line again.
    for rarg in parser.parse_command_line()
    {
        let argument =
            rarg.context("Error parsing command-line arguments")?;

        match argument {
	    Argument::Option(oQuiet, _) => {
                opt.quiet = true;
            },

	    Argument::Option(oVerbose, _) => {
	        opt.verbose += 1;
                opt.list_sigs = true;
	    },

	    Argument::Option(oDebug, _) => {
                // XXX:
                //parse_debug_flag (value.as_str().unwrap(), &opt.debug, debug_flags))?;
            },

	    Argument::Option(oKeyring, value) => {
                keyrings.push(value.as_str().unwrap().into());
            },

	    Argument::Option(oOutput, value) => {
                opt.outfile = Some(value.as_str().unwrap().into());
            },

	    Argument::Option(oStatusFD, value) => {
                opt.status_fd =
                    utils::sink_from_fd(value.as_int().unwrap())?.into();
            },

	    Argument::Option(oLoggerFD, value) => {
                opt.logger_fd = utils::sink_from_fd(value.as_int().unwrap())?;
            },
            Argument::Option(oLoggerFile, value) => {
                opt.logger_fd =
                    Box::new(fs::File::create(value.as_str().unwrap())?);
            },

            Argument::Option(oHomedir, value) => {
                opt.homedir = value.as_str().unwrap().into();
            },

	    Argument::Option(oWeakDigest, value) => {
                opt.weak_digest.insert(
                    argparse::utils::parse_digest(value.as_str().unwrap())?);
            },

            Argument::Option(oIgnoreTimeConflict, _) => {
                opt.ignore_time_conflict = true;
            },

            Argument::Option(oEnableSpecialFilenames, _) => {
                opt.enable_special_filenames = true;
            },

            Argument::Option(aHelp, _)
                | Argument::Option(aVersion, _)
                | Argument::Option(aWarranty, _)
                | Argument::Option(aDumpOptions, _)
                | Argument::Option(aDumpOpttbl, _) =>
                unreachable!("handled above"),
            Argument::Option(o300, _)
                | Argument::Option(o301, _)
                => unreachable!("not a real option"),

            Argument::Positional(a) => args.push(a),
        }
    }

    // Get the default one if no keyring has been specified.
    if keyrings.is_empty() {
        opt.keydb.add_resource(&opt.homedir, "trustedkeys.kbx", true, true)?;
    }

    for path in keyrings {
        opt.keydb.add_resource(&opt.homedir, path, true, false)?;
    }

    opt.keydb.initialize()?;

    verify::cmd_verify(&opt, &args)?;

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
