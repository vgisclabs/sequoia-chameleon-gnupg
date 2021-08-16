use std::{
    path::PathBuf,
};

use anyhow::{Context, Result};

#[macro_use]
mod macros;
#[allow(dead_code)]
mod argparse;

struct Config {
    default_keyring: bool,
    homedir: PathBuf,
    no_homedir_creation: bool,
    no_perm_warn: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            default_keyring: true,
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

fn set_cmd(cmd: &mut Option<argparse::CmdOrOpt>, new_cmd: argparse::CmdOrOpt)
           -> anyhow::Result<()> {
    use argparse::CmdOrOpt::*;
    dbg!((&cmd, new_cmd));
    match cmd.as_ref().clone() {
        None => *cmd = Some(new_cmd),
        Some(c) if *c == new_cmd => (),

        Some(aSign) if new_cmd == aEncr => *cmd = Some(aSignEncr),
        Some(aEncr) if new_cmd == aSign => *cmd = Some(aSignEncr),

        Some(aSign) if new_cmd == aSym => *cmd = Some(aSignSym),
        Some(aSym) if new_cmd == aSign => *cmd = Some(aSignSym),

        Some(aSym) if new_cmd == aEncr => *cmd = Some(aEncrSym),
        Some(aEncr) if new_cmd == aSym => *cmd = Some(aEncrSym),

        Some(aSignEncr) if new_cmd == aSym => *cmd = Some(aSignEncrSym),
        Some(aSignSym) if new_cmd == aEncr => *cmd = Some(aSignEncrSym),
        Some(aEncrSym) if new_cmd == aSign => *cmd = Some(aSignEncrSym),

        Some(aSign) if new_cmd == aClearsign => *cmd = Some(aClearsign),
        Some(aClearsign) if new_cmd == aSign => *cmd = Some(aClearsign),

        _ => return Err(anyhow::anyhow!("Conflicting commands {:?} and {:?}",
                                        cmd.unwrap(), new_cmd)),
    }
    Ok(())
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
    let mut command = None;
    let mut greeting = false;
    let mut no_greeting = false;

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

    // Third pass: parse config file(s) and the command line again.
    for rarg in
        argparse::Source::try_parse_file(config.homedir.join("gpg.conf"))?
        .chain(argparse::Source::parse_command_line())
    {
        let (cmd, value) =
            rarg.context("Error parsing command-line arguments")?;
        eprintln!("{:?} {:?}", cmd, value);

        use CmdOrOpt::*;
        match cmd {
	    aListConfig
	        | aListGcryptConfig
                | aGPGConfList
                | aGPGConfTest =>
            {
                set_cmd(&mut command, cmd)?;
                config.default_keyring = false;
            },

	    aCheckKeys
	        | aListPackets
	        | aImport
	        | aFastImport
	        | aSendKeys
	        | aRecvKeys
	        | aSearchKeys
	        | aRefreshKeys
	        | aFetchKeys
	        | aExport
                | aCardStatus
                | aCardEdit
                | aChangePIN
	        | aListKeys
	        | aLocateKeys
	        | aLocateExtKeys
	        | aListSigs
	        | aExportSecret
	        | aExportSecretSub
	        | aExportSshKey
	        | aSym
	        | aClearsign
	        | aGenRevoke
	        | aDesigRevoke
	        | aPrimegen
	        | aGenRandom
	        | aPrintMD
	        | aPrintMDs
	        | aListTrustDB
	        | aCheckTrustDB
	        | aUpdateTrustDB
	        | aFixTrustDB
	        | aListTrustPath
	        | aDeArmor
	        | aEnArmor
	        | aSign
	        | aQuickSignKey
	        | aQuickLSignKey
	        | aQuickRevSig
	        | aSignKey
	        | aLSignKey
	        | aStore
	        | aQuickKeygen
	        | aQuickAddUid
	        | aQuickAddKey
	        | aQuickRevUid
	        | aQuickSetExpire
	        | aQuickSetPrimaryUid
	        | aExportOwnerTrust
	        | aImportOwnerTrust
                | aRebuildKeydbCaches =>
            {
                set_cmd(&mut command, cmd)?;
            },

	    aKeygen
	        | aFullKeygen
	        | aEditKey
	        | aDeleteSecretKeys
	        | aDeleteSecretAndPublicKeys
	        | aDeleteKeys
                | aPasswd =>
            {
                set_cmd(&mut command, cmd)?;
                greeting = true;
            },

            _ => (),
        }
    }

    if greeting && ! no_greeting {
        eprintln!("Greetings from the people of earth!");
    }

    dbg!(command);

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
