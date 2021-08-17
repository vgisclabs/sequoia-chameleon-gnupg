use std::{
    convert::TryInto,
    fs,
    io,
    path::PathBuf,
    time,
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
#[allow(dead_code)]
mod flags;
use flags::*;

struct Config {
    // Configuration.
    answer_no: bool,
    answer_yes: bool,
    ask_cert_expire: bool,
    ask_cert_level: bool,
    ask_sig_expire: bool,
    armor: bool,
    batch: bool,
    cert_policy_url: Vec<URL>,
    check_sigs: bool,
    comments: Vec<String>,
    completes_needed: i64,
    compliance: Compliance,
    compress_level: i64,
    debug: u32,
    def_cert_expire: Option<time::Duration>,
    def_cert_level: i64,
    def_recipient: Option<String>,
    def_recipient_self: bool,
    def_secret_key: Vec<String>,
    def_sig_expire: Option<time::Duration>,
    default_keyring: bool,
    dry_run: bool,
    emit_version: usize,
    encrypt_to_default_key: usize,
    expert: bool,
    fingerprint: usize,
    flags: Flags,
    force_ownertrust: bool,
    homedir: PathBuf,
    import_options: u32,
    input_size_hint: Option<u64>,
    interactive: bool,
    list_options: u32,
    list_sigs: bool,
    marginals_needed: i64,
    max_cert_depth: i64,
    max_output: Option<u64>,
    mimemode: bool,
    min_cert_level: i64,
    no_armor: bool,
    no_encrypt_to: bool,
    no_homedir_creation: bool,
    no_perm_warn: bool,
    outfile: Option<String>,
    passphrase: Option<String>,
    passphrase_repeat: i64,
    photo_viewer: Option<PathBuf>,
    pinentry_mode: PinentryMode,
    quiet: bool,
    rfc2440_text: bool,
    s2k_count: Option<i64>,
    s2k_mode: i64,
    secret_keys_to_try: Vec<String>,
    sender_list: Vec<String>,
    set_filename: Option<PathBuf>,
    sig_keyserver_url: Vec<URL>,
    sig_policy_url: Vec<URL>,
    skip_hidden_recipients: bool,
    skip_verify: bool,
    textmode: usize,
    throw_keyids: bool,
    tofu_default_policy: TofuPolicy,
    trust_model: TrustModel,
    use_embedded_filename: bool,
    verbose: usize,
    verify_options: u32,
    with_colons: bool,
    with_fingerprint: bool,
    with_icao_spelling: bool,
    with_key_data: bool,
    with_key_origin: bool,
    with_keygrip: bool,
    with_secret: bool,
    with_subkey_fingerprint: bool,
    with_tofu_info: bool,
    with_wkd_hash: bool,

    // Streams.
    status_fd: Box<dyn io::Write>,
    attribute_fd: Box<dyn io::Write>,
    logger_fd: Box<dyn io::Write>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            // Configuration.
            answer_no: false,
            answer_yes: false,
            armor: false,
            ask_cert_expire: false,
            ask_cert_level: false,
            ask_sig_expire: false,
            batch: false,
            cert_policy_url: Vec::new(),
            check_sigs: false,
            comments: Vec::new(),
            completes_needed: 0, // XXX
            compliance: Default::default(),
            compress_level: 5,
            debug: 0,
            def_cert_expire: None,
            def_cert_level: 0, // XXX
            def_recipient: None,
            def_recipient_self: false,
            def_secret_key: Default::default(),
            def_sig_expire: None,
            default_keyring: true,
            dry_run: false,
            emit_version: 0,
            encrypt_to_default_key: 0, // XXX
            expert: false,
            fingerprint: 0,
            flags: Default::default(),
            force_ownertrust: false,
            homedir: std::env::var_os("GNUPGHOME")
                .map(Into::into)
                .unwrap_or_else(|| dirs::home_dir()
                                .expect("cannot get user's home directory")
                                .join(".gnupg")),
            import_options: Default::default(),
            input_size_hint: None,
            interactive: false,
            list_options: Default::default(),
            list_sigs: false,
            marginals_needed: 0, // XXX
            max_cert_depth: 0, // XXX
            max_output: None,
            mimemode: false,
            min_cert_level: 0,
            no_armor: false,
            no_encrypt_to: false,
            no_homedir_creation: false,
            no_perm_warn: false,
            outfile: None,
            passphrase: None,
            passphrase_repeat: 0, // XXX
            photo_viewer: None,
            pinentry_mode: Default::default(),
            quiet: false,
            rfc2440_text: false,
            s2k_count: None,
            s2k_mode: 3,
            secret_keys_to_try: Vec::new(),
            sender_list: Vec::new(),
            set_filename: None,
            sig_keyserver_url: Vec::new(),
            sig_policy_url: Vec::new(),
            skip_hidden_recipients: false,
            skip_verify: false,
            textmode: 0,
            throw_keyids: false,
            tofu_default_policy: Default::default(),
            trust_model: Default::default(),
            use_embedded_filename: false,
            verbose: 0,
            verify_options: 0,
            with_colons: false,
            with_fingerprint: false,
            with_icao_spelling: false,
            with_key_data: false,
            with_key_origin: false,
            with_keygrip: false,
            with_secret: false,
            with_subkey_fingerprint: false,
            with_tofu_info: false,
            with_wkd_hash: false,

            // Streams.
            status_fd: Box::new(io::sink()),
            attribute_fd: Box::new(io::sink()),
            logger_fd: Box::new(io::sink()),
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

#[derive(Default)]
struct Flags {
    disable_signer_uid: bool,
    force_sign_key: bool,
    include_key_block: bool,
    use_embedded_filename: bool,
}

enum Compliance {
    OpenPGP,
    RFC2440,
    RFC4880,
    RFC4880bis,
    PGP6,
    PGP7,
    PGP8,
    GnuPG,
    DeVs,
}

impl Default for Compliance {
    fn default() -> Self {
        Compliance::GnuPG
    }
}

impl std::str::FromStr for Compliance {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "gnupg" => Ok(Compliance::GnuPG),
            "openpgp" => Ok(Compliance::OpenPGP),
            "rfc4880bis" => Ok(Compliance::RFC4880bis),
            "rfc4880" => Ok(Compliance::RFC4880),
            "rfc2440" => Ok(Compliance::RFC2440),
            "pgp6" => Ok(Compliance::PGP6),
            "pgp7" => Ok(Compliance::PGP7),
            "pgp8" => Ok(Compliance::PGP8),
            "de-vs" => Ok(Compliance::DeVs),
            _ => Err(anyhow::anyhow!("Invalid value for option '--compliance': \
                                      {:?}", s)),
        }
    }
}

enum TrustModel {
    PGP,
    Classic,
    Always,
    Direct,
    Tofu,
    TofuPGP,
    Auto,
}

impl Default for TrustModel {
    fn default() -> Self {
        TrustModel::PGP // XXX
    }
}

impl std::str::FromStr for TrustModel {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pgp" => Ok(TrustModel::PGP),
            "classic" => Ok(TrustModel::Classic),
            "direct" => Ok(TrustModel::Direct),
            "tofu" => Ok(TrustModel::Tofu),
            "tofu+pgp" => Ok(TrustModel::TofuPGP),
            "auto" => Ok(TrustModel::Auto),
            _ => Err(anyhow::anyhow!("Unknown trust model {:?}", s)),
        }
    }
}

enum TofuPolicy {
    Auto,
    Good,
    Unknown,
    Bad,
    Ask,
}

impl Default for TofuPolicy {
    fn default() -> Self {
        TofuPolicy::Auto // XXX
    }
}

impl std::str::FromStr for TofuPolicy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(TofuPolicy::Auto),
            "good" => Ok(TofuPolicy::Good),
            "unknown" => Ok(TofuPolicy::Unknown),
            "bad" => Ok(TofuPolicy::Bad),
            "ask" => Ok(TofuPolicy::Ask),
            _ => Err(anyhow::anyhow!("Unknown TOFU policy {:?}", s)),
        }
    }
}

enum PinentryMode {
    Ask,
    Cancel,
    Error,
    Loopback,
}

impl Default for PinentryMode {
    fn default() -> Self {
        PinentryMode::Ask
    }
}

impl std::str::FromStr for PinentryMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ask" => Ok(PinentryMode::Ask),
            "default" => Ok(PinentryMode::Ask),
            "cancel" => Ok(PinentryMode::Cancel),
            "error" => Ok(PinentryMode::Error),
            "loopback" => Ok(PinentryMode::Loopback),
            _ => Err(anyhow::anyhow!("Unknown pinentry mode {:?}", s)),
        }
    }
}

#[derive(Clone)]
struct URL {
    url: String,
    critical: bool,
}

impl URL {
    fn new(u: &str) -> Self {
        let critical = u.starts_with("!");
        URL {
            url: if critical { u[1..].into() } else { u.into() },
            critical,
        }
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

fn obsolete_option(s: &str) {
    eprintln!("WARNING: {:?} is an obsolete option - it has no effect", s);
}

fn deprecated_warning(s: &str, repl1: &str, repl2: &str) {
    eprintln!("WARNING: {:?} is a deprecated option, \
               please use \"{}{}\" instead",
              s, repl1, repl2);
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

enum Keyring {
    Primary(PathBuf),
    Secondary(PathBuf),
}

struct Recipient {
    name: String,
    hidden: bool,
    config: bool,
    from_file: bool,
    additional: bool,
}

struct Sender {
    name: String,
    config: bool,
}

fn parse_digest(_s: &str) -> Result<HashAlgorithm> {
    unimplemented!("match gcry_md_map_name, [Hh]n notation")
}

fn parse_cipher(_s: &str) -> Result<SymmetricAlgorithm> {
    unimplemented!("match gcry_cipher_map_name, [Ss]n notation")
}

fn parse_expiration(_s: &str) -> Result<time::Duration> {
    unimplemented!("xxx")
}

fn mailbox_from_userid(_s: &str) -> Result<String> {
    unimplemented!("xxx")
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
    let mut detached_sig = false;
    let mut multifile = false;
    let mut keyrings = Vec::new();
    let mut debug_level = None;
    let mut logfile = None;
    let mut fpr_maybe_cmd = false;
    let mut default_keyring = false;
    let mut trustdb_name = None;
    let mut eyes_only = false;
    let mut s2k_digest: Option<HashAlgorithm> = None;
    let mut s2k_cipher: Option<SymmetricAlgorithm> = None;
    let mut remote_user: Vec<Recipient> = Vec::new();
    let mut local_user: Vec<Sender> = Vec::new();
    let mut any_explicit_recipient = false;
    let mut pwfd: Option<Box<dyn io::Read>> = None;

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
    let homedir_conf = opt.homedir.join("gpg.conf");
    for (config_file, rarg) in
        argparse::Source::try_parse_file(&homedir_conf)?
        .map(|rarg| (Some(&homedir_conf), rarg))
        .chain(argparse::Source::parse_command_line()
               .map(|rarg| (None, rarg)))
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
                opt.default_keyring = false;
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

	    aShowKeys =>
            {
                set_cmd(&mut command, cmd)?;
                opt.import_options |= IMPORT_SHOW;
                opt.import_options |= IMPORT_DRY_RUN;
                opt.import_options &= !IMPORT_REPAIR_KEYS;
                opt.list_options |= LIST_SHOW_UNUSABLE_UIDS;
                opt.list_options |= LIST_SHOW_UNUSABLE_SUBKEYS;
                opt.list_options |= LIST_SHOW_NOTATIONS;
                opt.list_options |= LIST_SHOW_POLICY_URLS;
            },

	    aDetachedSign => {
                detached_sig = true;
                set_cmd(&mut command, aSign )?;
            },

	    aDecryptFiles => {
                multifile = true;
                set_cmd(&mut command, aDecrypt)?;
            },
	    aDecrypt => {
                set_cmd(&mut command, aDecrypt)?;
            },

	    aEncrFiles => {
                multifile = true;
                set_cmd(&mut command, aEncr)?;
            },
	    aEncr => {
                set_cmd(&mut command, aEncr)?;
            },

	    aVerifyFiles => {
                multifile = true;
                set_cmd(&mut command, aVerify)?;
            },
	    aVerify => {
                set_cmd(&mut command, aVerify)?;
            },

            aServer => {
                set_cmd(&mut command, cmd)?;
                opt.batch = true;
            },

            aTOFUPolicy => {
                set_cmd(&mut command, cmd)?;
            },

	    oArmor => {
                opt.armor = true;
                opt.no_armor = false;
            },
	    oOutput => {
                opt.outfile = Some(value.as_str().unwrap().into());
            },

	    oMaxOutput => {
                opt.max_output = Some(value.as_uint().unwrap());
            },

            oInputSizeHint => {
                opt.input_size_hint = Some(value.as_uint().unwrap());
            },

	    oQuiet => {
                opt.quiet = true;
            },
	    oNoTTY => {
                // XXX: tty_no_terminal(1);
            },
	    oDryRun => {
                opt.dry_run = true;
            },
	    oInteractive => {
                opt.interactive = true;
            },

	    oVerbose => {
	        opt.verbose += 1;
	        opt.list_options |= LIST_SHOW_UNUSABLE_UIDS;
	        opt.list_options |= LIST_SHOW_UNUSABLE_SUBKEYS;
	    },

	    oBatch => {
                opt.batch = true;
                no_greeting = true;
            }

            oUseAgent => (), /* Dummy. */

            oNoUseAgent => {
	        obsolete_option("no-use-agent");
            },
	    oGpgAgentInfo => {
	        obsolete_option("gpg-agent-info");
            },
            oReaderPort => {
	        obsolete_option("reader-port");
            },
            octapiDriver => {
	        obsolete_option("ctapi-driver");
            },
            opcscDriver => {
	        obsolete_option("pcsc-driver");
            },
            oDisableCCID => {
	        obsolete_option("disable-ccid");
            },
            oHonorHttpProxy => {
	        obsolete_option("honor-http-proxy");
            },

	    oAnswerYes => {
                opt.answer_yes = true;
            },
	    oAnswerNo => {
                opt.answer_no = true;
            },

            oForceSignKey => {
                opt.flags.force_sign_key = true;
            },

	    oKeyring => {
                keyrings.push(
                    Keyring::Secondary(value.as_str().unwrap().into()));
            },
	    oPrimaryKeyring => {
                keyrings.push(
                    Keyring::Primary(value.as_str().unwrap().into()));
	    },
	    oShowKeyring => {
	        deprecated_warning("--show-keyring",
			           "--list-options ", "show-keyring");
	        opt.list_options |= LIST_SHOW_KEYRING;
	    },

	    oDebug => {
                // XXX:
                //parse_debug_flag (value.as_str().unwrap(), &opt.debug, debug_flags))?;
            },

	    oDebugAll => {
                opt.debug = !0;
            },
            oDebugLevel => {
                debug_level = Some(value.as_str().unwrap().to_string());
            },

            oDebugIOLBF => {
                /* Already set in pre-parse step.  */
            },

	    oStatusFD => {
                opt.status_fd = sink_from_fd(value.as_int().unwrap())?;
            },
	    oStatusFile => {
                opt.status_fd =
                    Box::new(fs::File::create(value.as_str().unwrap())?);
            },
	    oAttributeFD => {
                opt.attribute_fd = sink_from_fd(value.as_int().unwrap())?;
            },
	    oAttributeFile => {
                opt.attribute_fd =
                    Box::new(fs::File::create(value.as_str().unwrap())?);
            },
	    oLoggerFD => {
                opt.logger_fd = sink_from_fd(value.as_int().unwrap())?;
            },
            oLoggerFile => {
                // XXX: Why is this different from opt.logger_fd??
                logfile = Some(PathBuf::from(value.as_str().unwrap()));
            },

	    oWithFingerprint => {
                opt.with_fingerprint = true;
                opt.fingerprint += 1;
            },
	    oWithSubkeyFingerprint => {
                opt.with_subkey_fingerprint = true;
            },
	    oWithICAOSpelling => {
                opt.with_icao_spelling = true;
            },
	    oFingerprint => {
                opt.fingerprint += 1;
                fpr_maybe_cmd = true;
            },

	    oWithKeygrip => {
                opt.with_keygrip = true;
            },

	    oWithSecret => {
                opt.with_secret = true;
            },

	    oWithWKDHash => {
                opt.with_wkd_hash = true;
            },

	    oWithKeyOrigin => {
                opt.with_key_origin = true;
            },

	    oSecretKeyring => {
                /* Ignore this old option.  */
            },

	    oNoArmor => {
                opt.no_armor = true;
                opt.armor = false;
            },

	    oNoDefKeyring => {
                default_keyring = false;
            },
	    oNoKeyring => {
                default_keyring = false;
            },

	    oNoGreeting => {
                no_greeting = true;
            },
	    oNoVerbose => {
                opt.verbose = 0;
                opt.list_sigs = false;
            },
            oQuickRandom => (),
	    oEmitVersion => {
                opt.emit_version += 1;
            },
	    oNoEmitVersion => {
                opt.emit_version = 0;
            },
	    oCompletesNeeded => {
                opt.completes_needed = value.as_int().unwrap();
            },
	    oMarginalsNeeded => {
                opt.marginals_needed = value.as_int().unwrap();
            },
	    oMaxCertDepth => {
                opt.max_cert_depth = value.as_int().unwrap();
            },

	    oTrustDBName => {
                trustdb_name = Some(value.as_str().unwrap());
            },

	    oDefaultKey => {
                opt.def_secret_key.push(value.as_str().unwrap().into());
                // XXX:
                // sl->flags = (pargs.r_opt << PK_LIST_SHIFT);
                // if (configname)
                //   sl->flags |= PK_LIST_CONFIG;
            },
	    oDefRecipient => {
                if let Some(v) = value.as_str() {
		    opt.def_recipient = Some(v.into());
	        }
            },
	    oDefRecipientSelf => {
                opt.def_recipient = None;
                opt.def_recipient_self = true;
            },
            oNoDefRecipient => {
                opt.def_recipient = None;
                opt.def_recipient_self = false;
            },
            oHomedir => (),
	    oNoBatch => {
                opt.batch = false;
            },

            oWithTofuInfo => {
                opt.with_tofu_info = true;
            },

	    oWithKeyData => {
                opt.with_key_data = true; /*FALLTHRU*/
                opt.with_colons = true;
            }
	    oWithColons => {
                opt.with_colons = true;
            },

            oWithSigCheck => {
                opt.check_sigs = true; /*FALLTHRU*/
                opt.list_sigs = true;
            },
            oWithSigList => {
                opt.list_sigs = true;
            },

	    oSkipVerify => {
                opt.skip_verify = true;
            },

	    oSkipHiddenRecipients => {
                opt.skip_hidden_recipients = true;
            },
	    oNoSkipHiddenRecipients => {
                opt.skip_hidden_recipients = false;
            },

	    aListSecretKeys => {
                set_cmd(&mut command, aListSecretKeys)?;
            },

	    // There are many programs (like mutt) that call gpg with
	    // --always-trust so keep this option around for a long
	    // time.
	    oAlwaysTrust => {
                opt.trust_model = TrustModel::Always;
            },

	    oTrustModel => {
	        opt.trust_model = value.as_str().unwrap().parse()?;
	    },

	    oTOFUDefaultPolicy => {
	        opt.tofu_default_policy = value.as_str().unwrap().parse()?;
	    },
	    oTOFUDBFormat => {
	        obsolete_option ("tofu-db-format");
	    },

	    oForceOwnertrust => {
	        eprintln!("Note: {} is not for normal use!",
		          "--force-ownertrust");
	        opt.force_ownertrust = value.as_str().unwrap().parse()?;
	    },
	    oLoadExtension => {
                // Dummy so that gpg 1.4 conf files can work. Should
                // eventually be removed.
	    },

            oCompliance => {
	        opt.compliance = value.as_str().unwrap().parse()?;
            },
            oOpenPGP => opt.compliance = Compliance::OpenPGP,
            oRFC2440 => opt.compliance = Compliance::RFC2440,
            oRFC4880 => opt.compliance = Compliance::RFC4880,
            oRFC4880bis => opt.compliance = Compliance::RFC4880bis,
            oPGP6 => opt.compliance = Compliance::PGP6,
            oPGP7 => opt.compliance = Compliance::PGP7,
            oPGP8 => opt.compliance = Compliance::PGP8,
            oGnuPG => opt.compliance = Compliance::GnuPG,

            oRFC2440Text => {
                opt.rfc2440_text = true;
            },
            oNoRFC2440Text => {
                opt.rfc2440_text = false;
            },

 	    oSetFilename => {
                opt.set_filename = Some(value.as_str().unwrap().into());
 	    },
	    oForYourEyesOnly => {
                eyes_only = true;
            },
	    oNoForYourEyesOnly => {
                eyes_only = false;
            },
	    oSetPolicyURL => {
                let url = URL::new(value.as_str().unwrap());
                opt.cert_policy_url.push(url.clone());
                opt.sig_policy_url.push(url);
	    },
	    oSigPolicyURL => {
                let url = URL::new(value.as_str().unwrap());
                opt.sig_policy_url.push(url);
            },
	    oCertPolicyURL => {
                let url = URL::new(value.as_str().unwrap());
                opt.cert_policy_url.push(url);
            },
            oShowPolicyURL => {
	        deprecated_warning("--show-policy-url",
			           "--list-options ", "show-policy-urls");
	        deprecated_warning("--show-policy-url",
			           "--verify-options ", "show-policy-urls");
	        opt.list_options |= LIST_SHOW_POLICY_URLS;
	        opt.verify_options |= VERIFY_SHOW_POLICY_URLS;
	    },
	    oNoShowPolicyURL => {
	        deprecated_warning("--no-show-policy-url",
			           "--list-options ", "no-show-policy-urls");
	        deprecated_warning("--no-show-policy-url",
			           "--verify-options ", "no-show-policy-urls");
	        opt.list_options &= !LIST_SHOW_POLICY_URLS;
	        opt.verify_options &= !VERIFY_SHOW_POLICY_URLS;
	    },
	    oSigKeyserverURL => {
                opt.sig_keyserver_url.push(URL::new(value.as_str().unwrap()));
            },
	    oUseEmbeddedFilename => {
	        opt.flags.use_embedded_filename = true;
	    },
	    oNoUseEmbeddedFilename => {
	        opt.flags.use_embedded_filename = false;
	    },
	    oComment => {
	        if let Some(v) = value.as_str() {
	            opt.comments.push(v.into());
                }
	    },
	    oDefaultComment => {
	        deprecated_warning("--default-comment", "--no-comments", "");
	        /* fall through */
                opt.comments.clear();
            },
	    oNoComments => {
                opt.comments.clear();
	    },
	    oThrowKeyids => {
                opt.throw_keyids = true;
            },
	    oNoThrowKeyids => {
                opt.throw_keyids = false;
            },
	    oShowPhotos => {
	        deprecated_warning("--show-photos",
			           "--list-options ","show-photos");
	        deprecated_warning("--show-photos",
			           "--verify-options ","show-photos");
	        opt.list_options |= LIST_SHOW_PHOTOS;
	        opt.verify_options |= VERIFY_SHOW_PHOTOS;
	    },
	    oNoShowPhotos => {
	        deprecated_warning("--no-show-photos",
			           "--list-options ","no-show-photos");
	        deprecated_warning("--no-show-photos",
			           "--verify-options ","no-show-photos");
	        opt.list_options &= !LIST_SHOW_PHOTOS;
	        opt.verify_options &= !VERIFY_SHOW_PHOTOS;
	    },
	    oPhotoViewer => {
                opt.photo_viewer = Some(value.as_str().unwrap().into());
            },

            oDisableSignerUID => {
                opt.flags.disable_signer_uid = true;
            },
            oIncludeKeyBlock => {
                opt.flags.include_key_block = true;
            },
            oNoIncludeKeyBlock => {
                opt.flags.include_key_block = false;
            },

	    oS2KMode => {
                opt.s2k_mode = value.as_int().unwrap();
            },
	    oS2KDigest => {
                s2k_digest = Some(parse_digest(value.as_str().unwrap())?);
            },
	    oS2KCipher => {
                s2k_cipher = Some(parse_cipher(value.as_str().unwrap())?);
            },
	    oS2KCount => {
	        if let Some(v) = value.as_int() {
                    opt.s2k_count = Some(v);
                } else {
                    opt.s2k_count = None;  /* Auto-calibrate when needed.  */
                }
	    },

	    oRecipient
	        | oHiddenRecipient
	        | oRecipientFile
	        | oHiddenRecipientFile
	        | oEncryptTo
	        | oHiddenEncryptTo =>
            {
                remote_user.push(Recipient {
                    name: value.as_str().unwrap().into(),
                    hidden: cmd == oHiddenRecipient
                        || cmd == oHiddenRecipientFile
                        || cmd == oHiddenEncryptTo,
                    config: config_file.is_some(),
                    from_file: cmd == oRecipientFile
                        || cmd == oHiddenRecipientFile,
                    additional: cmd == oEncryptTo
                        || cmd == oHiddenEncryptTo,
                });
                any_explicit_recipient = true;
	    },

	    oNoEncryptTo => {
                opt.no_encrypt_to = true;
            },
            oEncryptToDefaultKey => {
                opt.encrypt_to_default_key =
                    if config_file.is_some() {
                        2
                    } else {
                        1
                    };
            },

	    oTrySecretKey => {
                opt.secret_keys_to_try.push(value.as_str().unwrap().into());
	    },

            oMimemode => {
                opt.mimemode = true;
                opt.textmode = 1;
            },
	    oTextmodeShort => {
                opt.textmode = 2;
            },
	    oTextmode => {
                opt.textmode = 1;
            },
	    oNoTextmode => {
                opt.textmode = 0;
                opt.mimemode = false;
            },

	    oExpert => {
                opt.expert = true;
            },
	    oNoExpert => {
                opt.expert = false;
            },
	    oDefSigExpire => {
		opt.def_sig_expire =
                    Some(parse_expiration(value.as_str().unwrap())?);
	    },
	    oAskSigExpire => {
                opt.ask_sig_expire = true;
            },
	    oNoAskSigExpire => {
                opt.ask_sig_expire = false;
            },
	    oDefCertExpire => {
		opt.def_cert_expire =
                    Some(parse_expiration(value.as_str().unwrap())?);
	    },
	    oAskCertExpire => {
                opt.ask_cert_expire = true;
            },
	    oNoAskCertExpire => {
                opt.ask_cert_expire = false;
            },
            oDefCertLevel => {
                opt.def_cert_level = value.as_int().unwrap();
            },
            oMinCertLevel => {
                opt.min_cert_level = value.as_int().unwrap();
            },
	    oAskCertLevel => {
                opt.ask_cert_level = true;
            },
	    oNoAskCertLevel => {
                opt.ask_cert_level = false;
            },
	    oLocalUser => {
                // store the local users */
                local_user.push(Sender {
                    name: value.as_str().unwrap().into(),
                    config: config_file.is_some(),
                });
	    },
	    oSender => {
                opt.sender_list.push(
                    mailbox_from_userid (value.as_str().unwrap())?);
	    },
	    oCompress
                | oCompressLevel
                | oBZ2CompressLevel =>
            {
	        opt.compress_level = value.as_int().unwrap();
	    },
	    oBZ2DecompressLowmem => (),
	    oPassphrase => {
                opt.passphrase = value.as_str().map(Into::into);
	    },
	    oPassphraseFD => {
                pwfd = Some(source_from_fd(value.as_int().unwrap())?);
            },
	    oPassphraseFile => {
                pwfd = Some(Box::new(fs::File::open(value.as_str().unwrap())?));
            },
	    oPassphraseRepeat => {
                opt.passphrase_repeat = value.as_int().unwrap();
            },

            oPinentryMode => {
	        opt.pinentry_mode = value.as_str().unwrap().parse()?;
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
