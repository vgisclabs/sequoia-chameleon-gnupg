#![allow(unused_macros, dead_code)]

use std::{
    env,
    fmt,
    fs,
    path::PathBuf,
};

use clap::{Arg, Command, ValueEnum};

#[macro_use]
#[path = "src/print.rs"]
mod print;

#[macro_use]
#[path = "src/macros.rs"]
mod macros;

/// To appease the argparse module.
struct Config(());

mod argparse {
    include!("src/argparse/mod.rs");
}

#[path = "src/gpg_args.rs"]
mod gpg_args;

#[path = "src/gpgv_args.rs"]
mod gpgv_args;

fn main() {
    let mut gpg_sq = cli_gpg_sq();
    let mut gpgv_sq = cli_gpgv_sq();

    generate_shell_completions(&mut gpg_sq, &mut gpgv_sq).unwrap();
    generate_man_pages(gpg_sq, gpgv_sq).unwrap();
}

/// Variable name to control the asset out directory with.
const ASSET_OUT_DIR: &str = "ASSET_OUT_DIR";

/// Returns the directory to write the given assets to.
fn asset_out_dir(asset: &str) -> Result<PathBuf> {
    println!("cargo:rerun-if-env-changed={}", ASSET_OUT_DIR);
    let outdir: PathBuf =
        env::var_os(ASSET_OUT_DIR).unwrap_or_else(
            || env::var_os("OUT_DIR").expect("OUT_DIR not set")).into();
    if outdir.exists() && ! outdir.is_dir() {
        return Err(Error(
            format!("{}={:?} is not a directory", ASSET_OUT_DIR, outdir)).into());
    }

    let path = outdir.join(asset);
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Generates shell completions.
fn generate_shell_completions(gpg_sq: &mut clap::Command,
                              gpgv_sq: &mut clap::Command)
                              -> Result<()> {
    let path = asset_out_dir("shell-completions")?;

    for shell in clap_complete::Shell::value_variants() {
        clap_complete::generate_to(*shell, gpg_sq, "gpg-sq", &path)?;
        clap_complete::generate_to(*shell, gpgv_sq, "gpgv-sq", &path)?;
    };

    println!("cargo:warning=shell completions written to {}", path.display());
    Ok(())
}

/// Generates man pages.
fn generate_man_pages(gpg_sq: clap::Command,
                      gpgv_sq: clap::Command)
                      -> Result<()> {
    let path = asset_out_dir("man-pages")?;

    generate_man_page(gpg_sq, fs::File::create(path.join("gpg-sq.1"))?)?;
    generate_man_page(gpgv_sq, fs::File::create(path.join("gpgv-sq.1"))?)?;

    println!("cargo:warning=man pages written to {}", path.display());

    Ok(())
}

/// Generates man pages.
fn generate_man_page(cmd: clap::Command, mut sink: fs::File)
                     -> Result<()> {
    let has_authors = cmd.get_author().is_some();
    let man = clap_mangen::Man::new(cmd);

    man.render_title(&mut sink)?;
    man.render_name_section(&mut sink)?;
    man.render_synopsis_section(&mut sink)?;
    man.render_description_section(&mut sink)?;
    man.render_options_section(&mut sink)?;

    use roff::{Roff, bold, roman};
    let mut roff = Roff::default();
    roff.control("SH", ["ENVIRONMENT"]);
    roff.control("TP", []);
    roff.text(vec![bold("SEQUOIA_CRYPTO_POLICY")]);
    roff.text(vec![roman("If set, must contain an absolute path to a
configuration file that changes which cryptographic algorithms are
acceptable.  By default, /etc/crypto-policies/back-ends/sequoia.config
is read, which on Fedora contains a reasonable policy set by the
distribution.
See
https://docs.rs/sequoia-policy-config/latest/sequoia_policy_config/#format
for a description of the file format.")]);

    roff.control("SH", ["FILES"]);
    roff.control("TP", []);
    roff.text(vec![bold("/etc/crypto-policies/back-ends/sequoia.config")]);
    roff.text(vec![roman("Default cryptographic policy.
On Fedora, this contains a reasonable policy set by the distribution.
Can be overridden using the SEQUOIA_POLICY_CONFIG environment variable.
See
https://docs.rs/sequoia-policy-config/latest/sequoia_policy_config/#format
for a description of the file format.")]);

    roff.to_writer(&mut sink)?;

    man.render_version_section(&mut sink)?;

    if has_authors {
        man.render_authors_section(&mut sink)?;
    }

    Ok(())
}

fn cli_gpg_sq() -> Command {
    let c = Command::new("gpg-sq")
        .version(env!("CARGO_PKG_VERSION"))
        .about("OpenPGP encryption and signing tool like gpg")
        .long_about(
            "This is a re-implementation and drop-in replacement of gpg using the Sequoia OpenPGP implementation.

gpg-sq is not feature-complete. It currently implements a commonly used subset of the signature creation and verification commands, the encryption and decryption commands, the key listing commands, and some miscellaneous commands.

Support for trust models is limited. Currently, the Web-of-Trust (\"pgp\") and always trust (\"always\") are implemented.",
        )
        .arg_required_else_help(true)
        .allow_external_subcommands(true);

    add_options(gpg_args::OPTIONS, c)
}

fn cli_gpgv_sq() -> Command {
    let c = Command::new("gpgv-sq")
        .version(env!("CARGO_PKG_VERSION"))
        .about("gpgv-sq - Verify OpenPGP signatures like gpgv")
        .long_about(
            "This is a re-implementation and drop-in replacement of gpgv using the Sequoia OpenPGP implementation.

gpgv-sq is feature-complete. Please report any problems you encounter when replacing gpgv with gpgv-sq.",
        )
        .arg_required_else_help(true)
        .allow_external_subcommands(true);

    add_options(gpgv_args::OPTIONS, c)
}

fn add_options<T>(options: &[argparse::Opt<T>], mut c: Command)
                  -> Command
where
    T: Copy + fmt::Debug + Into<isize>
{
    use argparse::flags;
    use std::sync::Mutex;
    for commands in [true, false] {
        let section = Mutex::new(None);
        for o in options.iter()
            .filter(|o| if o.flags & flags::OPT_HEADER > 0 {
                *section.lock().unwrap() = Some(o.description.trim());
                false
            } else if o.flags == 0 && o.description.starts_with("@")
                    && o.description.len() > 1 {
                *section.lock().unwrap() = Some(&o.description[1..].trim());
                false
            } else {
                true
            })
            .filter(|o| o.description != "@")
            .filter(|o| (o.flags & flags::OPT_COMMAND > 0) == commands)
        {
            let (description, value_name) = if o.description.starts_with('|') {
                let d = &o.description[1..];
                let i = d.find('|').expect("matching | after value name");
                (&d[i + 1..], Some(&d[..i]))
            } else {
                (o.description, None)
            };

            let mut arg = Arg::new(o.long_opt)
                .long(o.long_opt)
                .help(description);

            if let Some(name) = value_name {
                arg = arg.value_name(name);
            }

            if let Some(s) = section.lock().unwrap().as_ref() {
                // XXX: This is not yet used, but might be in the future:
                // https://github.com/clap-rs/clap/issues/3363
                arg = arg.help_heading(s);
            }

            let short_opt: isize = o.short_opt.into();
            if short_opt < 256 {
                arg = arg.short(short_opt as u8 as char);
            }

            c = c.arg(arg);
        }
    }

    c
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}
