use std::{
    cell::{OnceCell, RefCell},
    collections::BTreeSet,
    fmt,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time,
};

use anyhow::{Context, Result};
use indexmap::IndexMap;

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    KeyHandle,
    cert::prelude::*,
    crypto::Password,
    packet::{
        prelude::*,
        key::{PublicParts, UnspecifiedRole},
    },
    policy::Policy,
    serialize::Serialize,
    types::*,
};

use sequoia_cert_store::{
    LazyCert,
    Store,
};

use sequoia_gpg_agent as gpg_agent;

pub mod gnupg_interface;

#[macro_use]
mod print;
#[macro_use]
mod macros;
pub mod tracing;
#[macro_use]
pub mod argparse;
use argparse::{Argument, Opt, flags::*};
pub mod babel;
pub mod clock;
pub mod common;
use common::{Common, Compliance, Query, TrustModel, Validity};
pub mod compliance;
pub mod homedir;
mod interactive;
pub mod keydb;
pub mod policy;
use policy::GPGPolicy;
pub mod error_codes;
pub mod status;
pub mod trust;
pub mod colons;
pub mod utils;
pub mod commands;
pub mod verify;
pub mod decrypt;
pub mod export;
pub mod export_ssh_key;
pub mod import;
pub mod keyserver;
pub mod sign;
pub mod encrypt;
pub mod list_keys;
pub mod list_packets;
pub mod locate;
use locate::AutoKeyLocate;
pub mod parcimonie;
pub mod dirmngr;
pub mod migrate;
pub mod generate_key;
pub mod filter;
pub mod quick;
pub mod assert_pubkey_algo;

/// Commands and options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum CmdOrOpt {
    aNull = 0,
    o1 = 1,
    oArmor	  = 'a' as isize,
    aDetachedSign = 'b' as isize,
    aSym	  = 'c' as isize,
    aDecrypt	  = 'd' as isize,
    aEncr	  = 'e' as isize,
    oRecipientFile       = 'f' as isize,
    oHiddenRecipientFile = 'F' as isize,
    oInteractive  = 'i' as isize,
    aListKeys	  = 'k' as isize,
    oDryRun	  = 'n' as isize,
    oOutput	  = 'o' as isize,
    oQuiet	  = 'q' as isize,
    oRecipient	  = 'r' as isize,
    oHiddenRecipient = 'R' as isize,
    aSign	  = 's' as isize,
    oTextmodeShort= 't' as isize,
    oLocalUser	  = 'u' as isize,
    oVerbose	  = 'v' as isize,
    oCompress	  = 'z' as isize,
    oSetNotation  = 'N' as isize,
    aListSecretKeys = 'K' as isize,
    o300 = 300,
    o301,
    o302,
    o303,
    o309 = 309,
    oBatch	  = 500,
    oMaxOutput,
    oInputSizeHint,
    oSigNotation,
    oCertNotation,
    oShowNotation,
    oNoShowNotation,
    oKnownNotation,
    aEncrFiles,
    aEncrSym,
    aDecryptFiles,
    aClearsign,
    aStore,
    aQuickKeygen,
    aFullKeygen,
    aKeygen,
    aSignEncr,
    aSignEncrSym,
    aSignSym,
    aSignKey,
    aLSignKey,
    aQuickSignKey,
    aQuickLSignKey,
    aQuickRevSig,
    aQuickAddUid,
    aQuickAddKey,
    aQuickRevUid,
    aQuickSetExpire,
    aQuickSetPrimaryUid,
    aListConfig,
    aListGcryptConfig,
    aGPGConfList,
    aGPGConfTest,
    aListPackets,
    aEditKey,
    aDeleteKeys,
    aDeleteSecretKeys,
    aDeleteSecretAndPublicKeys,
    aImport,
    aFastImport,
    aVerify,
    aVerifyFiles,
    aListSigs,
    aSendKeys,
    aRecvKeys,
    aLocateKeys,
    aLocateExtKeys,
    aSearchKeys,
    aRefreshKeys,
    aFetchKeys,
    aShowKeys,
    aExport,
    aExportSecret,
    aExportSecretSub,
    aExportSshKey,
    aCheckKeys,
    aGenRevoke,
    aDesigRevoke,
    aPrimegen,
    aPrintMD,
    aPrintMDs,
    aCheckTrustDB,
    aUpdateTrustDB,
    aFixTrustDB,
    aListTrustDB,
    aListTrustPath,
    aExportOwnerTrust,
    aImportOwnerTrust,
    aDeArmor,
    aEnArmor,
    aGenRandom,
    aRebuildKeydbCaches,
    aCardStatus,
    aCardEdit,
    aChangePIN,
    aPasswd,
    aServer,
    aTOFUPolicy,

    oMimemode,
    oTextmode,
    oNoTextmode,
    oExpert,
    oNoExpert,
    oDefSigExpire,
    oAskSigExpire,
    oNoAskSigExpire,
    oDefCertExpire,
    oAskCertExpire,
    oNoAskCertExpire,
    oDefCertLevel,
    oMinCertLevel,
    oAskCertLevel,
    oNoAskCertLevel,
    oFingerprint,
    oWithFingerprint,
    oWithSubkeyFingerprint,
    oWithICAOSpelling,
    oWithKeygrip,
    oWithSecret,
    oWithWKDHash,
    oWithColons,
    oWithKeyData,
    oWithKeyOrigin,
    oWithTofuInfo,
    oWithSigList,
    oWithSigCheck,
    oAnswerYes,
    oAnswerNo,
    oKeyring,
    oPrimaryKeyring,
    oSecretKeyring,
    oShowKeyring,
    oDefaultKey,
    oDefRecipient,
    oDefRecipientSelf,
    oNoDefRecipient,
    oTrySecretKey,
    oOptions,
    oDebug,
    oDebugLevel,
    oDebugAll,
    oDebugIOLBF,
    oStatusFD,
    oStatusFile,
    oAttributeFD,
    oAttributeFile,
    oEmitVersion,
    oNoEmitVersion,
    oCompletesNeeded,
    oMarginalsNeeded,
    oMaxCertDepth,
    oLoadExtension,
    oCompliance,
    oGnuPG,
    oRFC2440,
    oRFC4880,
    oRFC4880bis,
    oOpenPGP,
    oPGP6,
    oPGP7,
    oPGP8,
    oDE_VS,
    oMinRSALength,
    oRFC2440Text,
    oNoRFC2440Text,
    oCipherAlgo,
    oDigestAlgo,
    oCertDigestAlgo,
    oCompressAlgo,
    oCompressLevel,
    oBZ2CompressLevel,
    oBZ2DecompressLowmem,
    oPassphrase,
    oPassphraseFD,
    oPassphraseFile,
    oPassphraseRepeat,
    oPinentryMode,
    oCommandFD,
    oCommandFile,
    oQuickRandom,
    oNoVerbose,
    oTrustDBName,
    oNoSecmemWarn,
    oRequireSecmem,
    oNoRequireSecmem,
    oNoPermissionWarn,
    oNoArmor,
    oNoDefKeyring,
    oNoKeyring,
    oNoGreeting,
    oNoTTY,
    oNoOptions,
    oNoBatch,
    oHomedir,
    oSkipVerify,
    oSkipHiddenRecipients,
    oNoSkipHiddenRecipients,
    oAlwaysTrust,
    oTrustModel,
    oForceOwnertrust,
    oSetFilename,
    oForYourEyesOnly,
    oNoForYourEyesOnly,
    oSetPolicyURL,
    oSigPolicyURL,
    oCertPolicyURL,
    oShowPolicyURL,
    oNoShowPolicyURL,
    oSigKeyserverURL,
    oUseEmbeddedFilename,
    oNoUseEmbeddedFilename,
    oComment,
    oDefaultComment,
    oNoComments,
    oThrowKeyids,
    oNoThrowKeyids,
    oShowPhotos,
    oNoShowPhotos,
    oPhotoViewer,
    oS2KMode,
    oS2KDigest,
    oS2KCipher,
    oS2KCount,
    oDisplayCharset,
    oNotDashEscaped,
    oEscapeFrom,
    oNoEscapeFrom,
    oLockOnce,
    oLockMultiple,
    oLockNever,
    oKeyServer,
    oKeyServerOptions,
    oImportOptions,
    oImportFilter,
    oExportOptions,
    oExportFilter,
    oListOptions,
    oVerifyOptions,
    oTempDir,
    oExecPath,
    oEncryptTo,
    oHiddenEncryptTo,
    oNoEncryptTo,
    oEncryptToDefaultKey,
    oLoggerFD,
    oLoggerFile,
    oUtf8Strings,
    oNoUtf8Strings,
    oDisableCipherAlgo,
    oDisablePubkeyAlgo,
    oAllowNonSelfsignedUID,
    oNoAllowNonSelfsignedUID,
    oAllowFreeformUID,
    oNoAllowFreeformUID,
    oAllowSecretKeyImport,
    oEnableSpecialFilenames,
    oNoLiteral,
    oSetFilesize,
    oHonorHttpProxy,
    oFastListMode,
    oListOnly,
    oIgnoreTimeConflict,
    oIgnoreValidFrom,
    oIgnoreCrcError,
    oIgnoreMDCError,
    oShowSessionKey,
    oOverrideSessionKey,
    oOverrideSessionKeyFD,
    oOverrideComplianceCheck,
    oNoRandomSeedFile,
    oAutoKeyRetrieve,
    oNoAutoKeyRetrieve,
    oAutoKeyImport,
    oNoAutoKeyImport,
    oUseAgent,
    oNoUseAgent,
    oGpgAgentInfo,
    oMergeOnly,
    oTryAllSecrets,
    oTrustedKey,
    oNoExpensiveTrustChecks,
    oFixedListMode,
    oLegacyListMode,
    oNoSigCache,
    oAutoCheckTrustDB,
    oNoAutoCheckTrustDB,
    oPreservePermissions,
    oDefaultPreferenceList,
    oDefaultKeyserverURL,
    oPersonalCipherPreferences,
    oPersonalDigestPreferences,
    oPersonalCompressPreferences,
    oAgentProgram,
    oDirmngrProgram,
    oDisableDirmngr,
    oDisplay,
    oTTYname,
    oTTYtype,
    oLCctype,
    oLCmessages,
    oXauthority,
    oGroup,
    oUnGroup,
    oNoGroups,
    oStrict,
    oNoStrict,
    oMangleDosFilenames,
    oNoMangleDosFilenames,
    oEnableProgressFilter,
    oMultifile,
    oKeyidFormat,
    oExitOnStatusWriteError,
    oLimitCardInsertTries,
    oReaderPort,
    octapiDriver,
    opcscDriver,
    oDisableCCID,
    oRequireCrossCert,
    oNoRequireCrossCert,
    oAutoKeyLocate,
    oNoAutoKeyLocate,
    oAllowMultisigVerification,
    oEnableLargeRSA,
    oDisableLargeRSA,
    oEnableDSA2,
    oDisableDSA2,
    oAllowMultipleMessages,
    oNoAllowMultipleMessages,
    oAllowWeakDigestAlgos,
    oAllowWeakKeySignatures,
    oFakedSystemTime,
    oNoAutostart,
    oPrintPKARecords,
    oPrintDANERecords,
    oTOFUDefaultPolicy,
    oTOFUDBFormat,
    oDefaultNewKeyAlgo,
    oWeakDigest,
    oUnwrap,
    oOnlySignTextIDs,
    oDisableSignerUID,
    oSender,
    oKeyOrigin,
    oRequestOrigin,
    oNoSymkeyCache,
    oUseOnlyOpenPGPCard,
    oIncludeKeyBlock,
    oNoIncludeKeyBlock,
    oForceSignKey,
    oForbidGenKey,
    oRequireCompliance,
    oAssertPubkeyAlgo,

    oNoop,

    // Our own extensions.
    aXSequoiaParcimonie,
    oXSequoiaAutostartParcimonie,
    aXSequoiaParcimonieDaemonize,
    oXSequoiaQuietFakedSystemTime,

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

include!("gpg.option.inc");

pub struct Config<'store> {
    // Runtime.
    clock: clock::Clock,
    fail: std::cell::Cell<bool>,
    override_status_code: std::cell::Cell<Option<i32>>,
    policy: GPGPolicy,
    trustdb: trust::db::TrustDB,
    trust_model_impl: Box<dyn trust::Model>,
    de_vs_producer: compliance::DeVSProducer,

    /// Emulates GnuPG's pk_cache.
    pk_cache: Mutex<BTreeSet<Fingerprint>>,

    // Configuration.
    answer_no: bool,
    answer_yes: bool,
    armor: bool,
    ask_cert_expire: bool,
    ask_cert_level: bool,
    ask_sig_expire: bool,
    auto_key_locate: Vec<AutoKeyLocate>,
    batch: bool,
    cert_digest: Option<HashAlgorithm>,
    cert_policy_url: Vec<URL>,
    check_sigs: bool,
    comments: Vec<String>,
    completes_needed: Option<i64>,
    compliance: Compliance,
    compress_algo: Option<CompressionAlgorithm>,
    compress_level: i64,
    debug: u32,
    def_cert_expire: Option<time::Duration>,
    def_cert_level: i64,
    def_cipher: Option<SymmetricAlgorithm>,
    def_digest: Option<HashAlgorithm>,
    def_keyserver_url: Option<KeyserverURL>,
    def_preferences: Preferences,
    def_recipient: Option<String>,
    def_recipient_self: bool,
    def_secret_key: Vec<String>,
    def_sig_expire: Option<time::Duration>,
    default_keyring: bool,
    dotlock_disable: bool,
    dry_run: bool,
    emit_version: usize,
    encrypt_to_default_key: usize,
    escape_from: bool,
    expert: bool,
    export_options: export::ExportOptions,
    fingerprint: usize,
    flags: Flags,
    forbid_gen_key: bool,
    force_ownertrust: bool,
    groups: IndexMap<String, Vec<String>>,
    homedir: PathBuf,
    import_options: import::ImportOptions,
    input_size_hint: Option<u64>,
    interactive: bool,
    keydb: keydb::KeyDB<'store>,
    keyid_format: KeyIDFormat,
    keyserver: Vec<KeyserverURL>,
    keyserver_options: keyserver::KeyserverOptions,
    list_only: bool,
    list_options: list_keys::ListOptions,
    local_user: Vec<Sender>,
    lock_once: bool,
    marginals_needed: Option<i64>,
    max_cert_depth: Option<i64>,
    max_output: Option<u64>,
    mimemode: bool,
    min_cert_level: i64,
    no_armor: bool,
    no_encrypt_to: bool,
    no_homedir_creation: bool,
    no_perm_warn: bool,
    not_dash_escaped: bool,
    outfile: Option<String>,
    override_session_key: Option<SessionKey>,
    passphrase_repeat: i64,
    personal_cipher_prefs: Option<Vec<SymmetricAlgorithm>>,
    personal_digest_prefs: Option<Vec<HashAlgorithm>>,
    personal_compress_prefs: Option<Vec<CompressionAlgorithm>>,
    photo_viewer: Option<PathBuf>,
    pinentry_mode: gpg_agent::PinentryMode,
    quiet: bool,
    remote_user: Vec<Recipient>,
    request_origin: RequestOrigin,
    rfc2440_text: bool,
    s2k_count: Option<i64>,
    s2k_mode: i64,
    secret_keys_to_try: Vec<String>,
    sender_list: Vec<String>,
    set_filename: Option<PathBuf>,
    show_session_key: bool,
    sig_keyserver_url: Vec<URL>,
    sig_policy_url: Vec<URL>,
    skip_hidden_recipients: bool,
    skip_verify: bool,
    special_filenames: bool,
    static_passphrase: std::cell::RefCell<Option<Password>>,
    textmode: usize,
    throw_keyids: bool,
    tofu_default_policy: trust::TofuPolicy,
    trust_model: Option<trust::TrustModel>,
    trusted_keys: Vec<openpgp::Fingerprint>,
    unwrap_encryption: bool,
    use_tor: OnceCell<bool>,
    verbose: usize,
    verify_options: verify::VerifyOptions,
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

    // Backported from GnuPG 2.4.5.
    pubkey_algo_policy: assert_pubkey_algo::Policy,

    // Extension.
    autostart_parcimonie: bool,

    // Streams.
    attribute_fd: Box<dyn io::Write>,
    command_fd: interactive::Fd,
    logger_fd: Mutex<RefCell<Box<dyn io::Write>>>,
    status_fd: status::Fd,
}

impl<'store> Config<'store> {
    fn new() -> Result<Self> {
        Ok(Config {
            // Runtime.
            clock: Default::default(),
            fail: Default::default(),
            override_status_code: Default::default(),
            policy: GPGPolicy::new()?,
            trustdb: Default::default(),
            trust_model_impl: common::null_model(),
            de_vs_producer: compliance::DeVSProducer::default(),

            // Emulation.
            pk_cache: Default::default(),

            // Configuration.
            answer_no: false,
            answer_yes: false,
            armor: false,
            ask_cert_expire: false,
            ask_cert_level: false,
            ask_sig_expire: false,
            auto_key_locate: vec![],
            batch: false,
            cert_digest: Default::default(),
            cert_policy_url: vec![],
            check_sigs: false,
            comments: vec![],
            completes_needed: None,
            compliance: Default::default(),
            compress_algo: Default::default(),
            compress_level: 5,
            debug: 0,
            def_cert_expire: None,
            def_cert_level: 0, // XXX
            def_cipher: Default::default(),
            def_digest: Default::default(),
            def_keyserver_url: None,
            def_preferences: Default::default(),
            def_recipient: None,
            def_recipient_self: false,
            def_secret_key: vec![],
            def_sig_expire: None,
            default_keyring: true,
            dotlock_disable: false,
            dry_run: false,
            emit_version: 0,
            encrypt_to_default_key: 0, // XXX
            escape_from: false,
            expert: false,
            export_options: Default::default(),
            fingerprint: 0,
            flags: Default::default(),
            forbid_gen_key: false,
            force_ownertrust: false,
            groups: Default::default(),
            homedir: std::env::var_os("GNUPGHOME")
                .filter(|v| ! v.is_empty())
                .map(Into::into)
                .ok_or_else(|| anyhow::anyhow!("for conversion to err"))
                .or_else(|_| homedir::default())?,
            import_options: Default::default(),
            input_size_hint: None,
            interactive: false,
            keydb: keydb::KeyDB::for_gpg(),
            keyid_format: Default::default(),
            keyserver: Default::default(),
            keyserver_options: Default::default(),
            list_only: false,
            list_options: Default::default(),
            local_user: vec![],
            lock_once: false,
            marginals_needed: None,
            max_cert_depth: None,
            max_output: None,
            mimemode: false,
            min_cert_level: 0,
            no_armor: false,
            no_encrypt_to: false,
            no_homedir_creation: false,
            no_perm_warn: false,
            not_dash_escaped: false,
            outfile: None,
            override_session_key: None,
            passphrase_repeat: 0, // XXX
            personal_cipher_prefs: None,
            personal_digest_prefs: None,
            personal_compress_prefs: None,
            photo_viewer: None,
            pinentry_mode: Default::default(),
            quiet: false,
            remote_user: vec![],
            request_origin: Default::default(),
            rfc2440_text: false,
            s2k_count: None,
            s2k_mode: 3,
            secret_keys_to_try: vec![],
            sender_list: vec![],
            set_filename: None,
            show_session_key: false,
            sig_keyserver_url: vec![],
            sig_policy_url: vec![],
            skip_hidden_recipients: false,
            skip_verify: false,
            special_filenames: false,
            static_passphrase: Default::default(),
            textmode: 0,
            throw_keyids: false,
            tofu_default_policy: Default::default(),
            trust_model: None,
            trusted_keys: vec![],
            unwrap_encryption: false,
            use_tor: Default::default(),
            verbose: 0,
            verify_options: Default::default(),
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

            // Backported from GnuPG 2.4.5.
            pubkey_algo_policy: Default::default(),

            // Extensions.
            autostart_parcimonie: false,

            // Streams.
            attribute_fd: Box::new(io::sink()),
            command_fd: interactive::Fd::interactive(),
            logger_fd: Mutex::new(RefCell::new(Box::new(io::stderr()))),
            status_fd: status::Fd::sink(),
        })
    }

    /// Emits the usage and terminates the process.
    pub fn wrong_args(&self, msg: fmt::Arguments) -> ! {
        safe_eprintln!("usage: gpg [options] {}", msg);
        std::process::exit(2);
    }

    /// Returns an IPC context.
    pub fn ipc(&self) -> Result<gpg_agent::gnupg::Context> {
        Ok(gpg_agent::gnupg::Context::with_homedir(&self.homedir)?)
    }

    /// Returns a connection to the GnuPG agent.
    pub async fn connect_agent(&self) -> Result<gpg_agent::Agent> {
        let mut agent = gpg_agent::Agent::connect_to(&self.homedir).await?;

        agent.send_simple("RESET").await?;

        if let Ok(tty) = std::env::var("GPG_TTY") {
            agent.send_simple(
                format!("OPTION ttyname={}", tty)).await?;
        } else {
            #[cfg(unix)]
            {
                let tty = unsafe {
                    use std::ffi::CStr;
                    let tty = libc::ttyname(0);
                    if tty.is_null() {
                        None
                    } else {
                        CStr::from_ptr(tty).to_str().ok()
                    }
                };

                if let Some(tty) = tty {
                    agent.send_simple(
                        format!("OPTION ttyname={}", tty)).await?;
                }
            }
        }
        let ttyname = unsafe { libc::ttyname(0) };
        if ! ttyname.is_null() {
            let ttyname = unsafe { std::ffi::CStr::from_ptr(ttyname) };
            agent.send_simple(format!(
                "OPTION ttyname={}",
                String::from_utf8_lossy(ttyname.to_bytes()))).await?;
        }
        if let Ok(term) = std::env::var("TERM") {
            agent.send_simple(format!("OPTION ttytype={}", term)).await?;
        }
        if let Ok(display) = std::env::var("DISPLAY") {
            agent.send_simple(format!("OPTION display={}", display)).await?;
        }
        if let Ok(xauthority) = std::env::var("XAUTHORITY") {
            agent.send_simple(format!("OPTION xauthority={}", xauthority)).await?;
        }
        if let Ok(dbus) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
            agent.send_simple(
                format!("OPTION putenv=DBUS_SESSION_BUS_ADDRESS={}",
                        dbus)).await?;
        }
        agent.send_simple("OPTION allow-pinentry-notify").await?;
        agent.send_simple("OPTION agent-awareness=2.1.0").await?;
        agent.send_simple(format!("OPTION pinentry-mode={}",
                                  self.pinentry_mode.as_str())).await?;

        Ok(agent)
    }

    /// Returns whether we're using the default home directory.
    fn homedir_is_default(&self) -> Result<bool> {
        use utils::robustly_canonicalize as rc;
        Ok(rc(&self.homedir) == rc(homedir::default()?))
    }

    /// Checks whether the permissions on the state directory are
    /// sane.
    fn check_homedir_permissions(&self) -> Result<()> {
        if self.no_perm_warn {
            // Opt-out.
            return Ok(());
        }

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
                    safe_eprintln!("gpg: WARNING: homedir '{}' is not a directory",
                              self.homedir.display());
                }

                if m.uid() != unsafe { libc::getuid() } {
                    safe_eprintln!("gpg: WARNING: unsafe ownership on homedir '{}'",
                              self.homedir.display());
                }

                if m.mode() & (libc::S_IRWXG | libc::S_IRWXO) as u32 > 0 {
                    safe_eprintln!("gpg: WARNING: unsafe permissions on homedir '{}'",
                              self.homedir.display());
                }
            },

            windows => {
                // XXX: What can we check?
            },
        }

        Ok(())
    }

    fn mut_keydb(&mut self) -> &mut keydb::KeyDB<'store> {
        &mut self.keydb
    }

    /// Returns a signer for the given key.
    pub async fn get_signer(&self,
                            vcert: &ValidCert<'_>,
                            subkey: &Key<PublicParts, UnspecifiedRole>)
                            -> Result<Box<dyn openpgp::crypto::Signer + Send + Sync>>
    {
        let mut agent = self.connect_agent().await?;
        agent.has_key(subkey).await?;

        let mut pair = agent.keypair(subkey)?.with_cert(vcert);

        // See if we have a static password to loop back to the agent.
        if let (gpg_agent::PinentryMode::Loopback, Some(p)) =
            (&self.pinentry_mode, self.static_passphrase.borrow().as_ref())
        {
            pair = pair.with_password(p.clone());
        }

        Ok(Box::new(pair))
    }

    /// Makes the agent ask for a password.
    pub async fn get_passphrase<P>(&self,
                                   agent: &mut gpg_agent::Agent,
                                   cache_id: &Option<String>,
                                   err_msg: &Option<String>,
                                   prompt: Option<String>,
                                   desc_msg: Option<String>,
                                   newsymkey: bool,
                                   repeat: usize,
                                   check: bool,
                                   qualitybar: bool,
                                   mut pinentry_launched_cb: P)
                                   -> Result<Password>
    where
        P: FnMut(&[u8]) -> Result<()>,
    {
        use gpg_agent::PinentryMode;
        use gpg_agent::assuan::Response;

        let callback = |_agent: &mut _, response| {
            if let Response::Inquire { keyword, parameters } = &response {
                match (keyword.as_str(), parameters, &self.pinentry_mode) {
                    ("PASSPHRASE", _, PinentryMode::Loopback) => {
                        // Do we have a pre-set password?
                        if let Some(p) =
                            self.static_passphrase.borrow().as_ref()
                        {
                            return Ok(Some(p.map(|decrypted| decrypted.clone())));
                        }

                        // We don't.  Prompt for a password.
                        let _ = // XXX.
                            self.status().emit(status::Status::InquireMaxLen(100));
                        let p = self.prompt_password()?;
                        Ok(Some(p.map(|decrypted| decrypted.clone())))
                    },
                    ("PINENTRY_LAUNCHED", Some(p), _) => {
                        let _ = // XXX.
                            pinentry_launched_cb(p.as_slice());
                        Ok(None)
                    },
                    // We silently ignore unknown inquiries.
                    // Alternatively, we could return an error.
                    _ => Ok(None),
                }
            } else {
                Ok(None)
            }
        };

        Ok(agent.get_passphrase(cache_id, err_msg, prompt, desc_msg,
                                newsymkey, repeat, check, qualitybar,
                                callback).await?)
    }

    /// Returns the local users used e.g. in signing operations.
    pub async fn local_users(&self, flags: KeyFlags) -> Result<Vec<String>> {
        if self.local_user.is_empty() {
            if self.def_secret_key.is_empty() {
                let mut agent = match self.connect_agent().await {
                    Ok(a) => a,
                    Err(e) => return Err(
                        e.context("There is no default key, and \
                                   connecting to the agent failed")),
                };

                // The user did not express a preference, use any
                // usable key.  GnuPG uses the first one it finds.  Do
                // the same, mostly because this search operation is
                // so expensive.
                let trust_root =
                    self.keydb().get_certd_overlay()
                    .and_then(|o| Ok(o.trust_root()?.fingerprint()))
                    .ok();
                for cert in self.keydb().certs()
                    .filter(|c| Some(c.fingerprint()) != trust_root)
                {
                    self.status().emit(
                        status::Status::KeyConsidered {
                            fingerprint: cert.fingerprint(),
                            not_selected: false,
                            all_expired_or_revoked: false,
                        })?;

                    if let Ok(vcert) = cert.with_policy(self.policy(), None) {
                        for sk in vcert.keys().key_flags(&flags).alive()
                            .revoked(false)
                        {
                            if agent.has_key(sk.key()).await? {
                                return Ok(vec![cert.fingerprint().to_string()]);
                            }
                        }
                    }

                    self.status().emit(
                        status::Status::KeyConsidered {
                            fingerprint: cert.fingerprint(),
                            not_selected: true,
                            all_expired_or_revoked: true,
                        })?;
                }

                // Heuristic failed to find a usable secret key.
                self.warn(format_args!("no default secret key: \
                                        Unusable secret key"));
                Err(anyhow::anyhow!("Unusable secret key"))
            } else {
                Ok(self.def_secret_key.clone())
            }
        } else {
            Ok(self.local_user.iter().map(|s| s.name.clone()).collect())
        }
    }

    /// Returns certs matching a given query using groups and the
    /// configured trust model.
    pub fn lookup_certs(&self, query: &Query) -> Result<Vec<(Validity, Arc<LazyCert<'store>>)>> {
        self.lookup_certs_with(
            self.trust_model_impl.with_policy(self, Some(self.now()))?.as_ref(),
            query, true)
    }

    /// Returns certs matching a given query using groups and the
    /// given trust model.
    pub fn lookup_certs_with<'a>(&self,
                                 vtm: &dyn trust::ModelViewAt<'a, 'store>,
                                 query: &Query,
                                 expand_groups: bool)
        -> Result<Vec<(Validity, Arc<LazyCert<'store>>)>>
    {
        match query {
            Query::Key(_) | Query::ExactKey(_) =>
                (), // Let the trust model do the lookup.

            // Try to map using groups if `expand_groups` is true.  We
            // don't want to lookup expanded names again, as we may
            // walk into loops.  GnuPG also doesn't do that.
            Query::Email(e) | Query::ExactUserID(e) => if expand_groups {
                if let Some(queries) = self.groups.get(e.as_str()) {
                    let mut acc = Vec::new();
                    for query in queries {
                        let q = query.parse()?;
                        acc.append(
                            &mut self.lookup_certs_with(vtm, &q, false)?);
                    }
                    return Ok(acc);
                }
            },
            // Maybe expand groups.  See comment above.
            Query::UserIDFragment(f) => if expand_groups {
                if let Some(queries) = self.groups.get(&f[..]) {
                    let mut acc = Vec::new();
                    for query in queries {
                        let q = query.parse()?;
                        acc.append(
                            &mut self.lookup_certs_with(vtm, &q, false)?);
                    }
                    return Ok(acc);
                }
            },
        }

        // Then, use the trust model to lookup the cert.
        vtm.lookup(query)
    }

    /// Like `.keydb().lookup_by_cert_or_subkey` but emits
    /// KEY_CONSIDERED lines.
    pub fn lookup_by_cert_or_subkey(&self, kh: &KeyHandle)
                                    -> Result<Vec<Arc<LazyCert<'store>>>>
    {
        self.keydb().lookup_by_cert_or_subkey(kh)
            .map(|certs| {
                for cert in &certs {
                    let fp = cert.fingerprint();
                    {
                        let mut pk_cache = self.pk_cache.lock().unwrap();
                        if pk_cache.contains(&fp) {
                            continue;
                        } else {
                            pk_cache.insert(fp);
                        }
                    }

                    let _ = self.status().emit(status::Status::KeyConsidered {
                        fingerprint: cert.fingerprint(),
                        not_selected: false,
                        all_expired_or_revoked: false,
                    });
                }
                certs
            })
    }

    /// Stores a revocation certificate.
    pub fn store_revocation(&self, cert: &Cert, rev: Signature) -> Result<()> {
        let store = self.homedir().join("openpgp-revocs.d");
        if ! store.exists() {
            std::fs::create_dir_all(&store)?;
            self.info(format_args!("directory '{}' created", store.display()));
        }

        let path = store.join(format!("{:X}.rev", cert.fingerprint()));
        Packet::from(rev).serialize(&mut fs::File::create(&path)?)?;
        self.info(format_args!("revocation certificate stored as '{}'",
                               path.display()));

        Ok(())
    }

    /// Makes an http client for keyserver and WKD requests.
    pub fn make_http_client(&self) -> keyserver::HttpClientBuilder {
        use reqwest::StatusCode;

        /// Connects to Tor's SOCKS5 proxy port and see if it feels
        /// like tor.
        async fn detect_tor() -> Result<bool> {
            let torproject = memchr::memmem::Finder::new(b"torproject");

            // Make a GET to the proxy, Tor will reply with an error.
            let r = reqwest::get("http://localhost:9050").await?;
            let status = r.status();
            let b = r.bytes().await?;

            Ok(status == StatusCode::NOT_IMPLEMENTED
               && torproject.find(&b).is_some())
        }

        // Lazily compute whether we want to use Tor.  Does not run if
        // --use-tor or --no-use-tor has been given in dirmngr.conf.
        // Only one thread will compute this.
        let use_tor = self.use_tor.get_or_init(|| {
            let transaction = || {
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(detect_tor())
            };

            // Spawn a thread so that this is safe to use from async
            // environments.
            std::thread::spawn(transaction)
                .join().unwrap_or(Ok(false))
                .unwrap_or(false)
        });

        keyserver::HttpClientBuilder::default()
	    .connect_timeout(keyserver::CONNECT_TIMEOUT)
	    .request_timeout(keyserver::REQUEST_TIMEOUT)
            .use_tor(*use_tor)
    }
}

impl<'store> common::Common<'store> for Config<'store> {
    fn argv0(&self) -> &'static str {
        "gpg"
    }

    fn log(&self, msg: fmt::Arguments) {
        let mut logger = self.logger_fd.lock().expect("not poisoned");
        let _ = writeln!(logger.get_mut(), "{}", msg);
    }

    fn warn(&self, msg: fmt::Arguments) {
        crate::with_invocation_log(
            |w| Ok(write!(w, "{}: {}", self.argv0(), msg)?));
        self.log(format_args!("{}: {}", self.argv0(), msg));
    }

    fn fail(&self) {
        self.fail.set(true);
    }

    fn override_status_code(&self, code: i32) {
        self.override_status_code.set(Some(code));
    }

    fn debug(&self) -> u32 {
        self.debug
    }

    fn homedir(&self) -> &Path {
        &self.homedir
    }

    fn keydb(&self) -> &keydb::KeyDB<'store> {
        &self.keydb
    }

    fn lookup_certs(&self, query: &Query)
        -> anyhow::Result<Vec<(Validity, Arc<LazyCert<'store>>)>>
    {
        Config::lookup_certs(self, query)
    }

    fn outfile(&self) -> Option<&String> {
        self.outfile.as_ref()
    }

    fn policy(&self) -> &GPGPolicy {
        &self.policy
    }

    fn quiet(&self) -> bool {
        self.quiet
    }

    fn verbose(&self) -> usize {
        self.verbose
    }

    fn special_filenames(&self) -> bool {
        self.special_filenames
    }

    fn status(&self) -> &status::Fd {
        &self.status_fd
    }

    fn trust_model_impl(&self) -> &dyn trust::Model {
        self.trust_model_impl.as_ref()
    }

    fn now(&self) -> std::time::SystemTime {
        self.clock.now()
    }

    fn with_fingerprint(&self) -> bool {
        self.with_fingerprint
    }
}

#[derive(Default)]
struct Flags {
    disable_signer_uid: bool,
    force_sign_key: bool,
    include_key_block: bool,
}

#[derive(Clone)]
struct URL {
    #[allow(dead_code)]
    url: String,
    #[allow(dead_code)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyserverURL {
    url: String,
}

impl KeyserverURL {
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Default for KeyserverURL {
    fn default() -> Self {
        "hkps://keys.openpgp.org".parse().unwrap()
    }
}

impl std::str::FromStr for KeyserverURL {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self {
            url: s.into(), // XXX: parsing
        })
    }
}

#[derive(Clone)]
enum RequestOrigin {
    Local,
    Remote,
    Browser,
}

impl Default for RequestOrigin {
    fn default() -> Self {
        RequestOrigin::Local
    }
}

impl std::str::FromStr for RequestOrigin {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" | "local" => Ok(RequestOrigin::Local),
            "remote" => Ok(RequestOrigin::Remote),
            "browser" => Ok(RequestOrigin::Browser),
            _ => Err(anyhow::anyhow!("Invalid request origin {:?}", s)),
        }
    }
}

#[derive(Clone)]
enum KeyIDFormat {
    None,
    Long,
    HexLong,
}

impl Default for KeyIDFormat {
    fn default() -> Self {
        KeyIDFormat::None
    }
}

impl std::str::FromStr for KeyIDFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(KeyIDFormat::None),
            "short" | "0xshort" => Err(anyhow::anyhow!(
                "short key IDs are not supported by the Sequoia Chameleon")),
            "long" => Ok(KeyIDFormat::Long),
            "0xlong" => Ok(KeyIDFormat::HexLong),
            _ => Err(anyhow::anyhow!("invalid key ID format {:?}", s)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Preferences {
    hash: Vec<HashAlgorithm>,
    symmetric: Vec<SymmetricAlgorithm>,
    compression: Vec<CompressionAlgorithm>,
    mdc: bool,
    ks_modify: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Preferences {
            hash: vec![
                HashAlgorithm::SHA512,
                HashAlgorithm::SHA384,
                HashAlgorithm::SHA256,
            ],
            symmetric: vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES192,
                SymmetricAlgorithm::AES128,
            ],
            compression: vec![
                CompressionAlgorithm::Uncompressed,
            ],
            mdc: true,
            ks_modify: false,
        }
    }
}

impl Preferences {
    fn parse(s: &str) -> Result<Option<Self>> {
        let mut p = Preferences {
            hash: vec![],
            symmetric: vec![],
            compression: vec![],
            mdc: true,
            ks_modify: false,
        };

        match s.to_lowercase().as_str() {
            "" | "default" => return Ok(None),
            // XXX: Does that make sense?
            "none" => return Ok(Some(p)),
            _ => (),
        }

        for s in s.split(&[' ', ',']) {
            if let Ok(babel::Fish(a)) = s.parse() {
                p.hash.push(a)
            } else if let Ok(babel::Fish(a)) = s.parse() {
                p.symmetric.push(a)
            } else if let Ok(babel::Fish(a)) = s.parse() {
                p.compression.push(a)
            } else if s.to_lowercase() == "mdc" {
                p.mdc = true;
            } else if s.to_lowercase() == "no-mdc" {
                p.mdc = false;
            } else if s.to_lowercase() == "ks-modify" {
                p.ks_modify = true;
            } else if s.to_lowercase() == "no-ks-modify" {
                p.ks_modify = false;
            } else {
                return Err(anyhow::anyhow!(
                    "invalid item '{}' in preference string", s));
            }
        }

        Ok(Some(p))
    }
}

fn set_cmd(cmd: &mut Option<CmdOrOpt>, new_cmd: CmdOrOpt)
           -> anyhow::Result<()> {
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
    safe_eprintln!("WARNING: {:?} is an obsolete option - it has no effect", s);
}

fn deprecated_warning(s: &str, repl1: &str, repl2: &str) {
    safe_eprintln!("WARNING: {:?} is a deprecated option, \
               please use \"{}{}\" instead",
              s, repl1, repl2);
}

enum Keyring {
    Primary(String),
    Secondary(String),
}

impl AsRef<str> for Keyring {
    fn as_ref(&self) -> &str {
        match self {
            Keyring::Primary(s) => s,
            Keyring::Secondary(s) => s,
        }
    }
}

struct Recipient {
    name: String,
    #[allow(dead_code)]
    hidden: bool,
    #[allow(dead_code)]
    config: bool,
    from_file: bool,
    #[allow(dead_code)]
    additional: bool,
}

#[derive(Clone)]
pub struct Sender {
    pub name: String,
    pub config: bool,
}

/// A session key.
pub struct SessionKey {
    cipher: SymmetricAlgorithm,
    key: openpgp::crypto::SessionKey,
}

impl SessionKey {
    /// Creates a new session key object.
    pub fn new<C, K>(cipher: C, key: K) -> Result<Self>
    where C: Into<u8>,
          K: AsRef<[u8]>,
    {
        // XXX: Maybe sanity check key lengths.
        Ok(SessionKey {
            cipher: cipher.into().into(),
            key: key.as_ref().into(),
        })
    }

    /// Returns the symmetric algorithm octet.
    pub fn cipher(&self) -> SymmetricAlgorithm {
        self.cipher
    }

    /// Returns the session key.
    pub fn key(&self) -> &openpgp::crypto::SessionKey {
        &self.key
    }
}

impl fmt::Display for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}",
               u8::from(self.cipher),
               openpgp::fmt::hex::encode(&self.key))
    }
}

impl std::str::FromStr for SessionKey {
    type Err = anyhow::Error;
    fn from_str(sk: &str) -> Result<Self> {
        // The format is:
        //
        //   <decimal-cipher-octet> ":" <hex-session-key>
        //
        // We most likely will change the first field, so we split
        // from the end of the string using `rsplit`, which puts the
        // last segment first.  This is rather unexpected.  Reverse
        // it.
        let fields = sk.rsplit(':').rev().collect::<Vec<_>>();

        if fields.len() != 2 {
            return Err(anyhow::anyhow!(
                "Expected two colon-separated fields, got {:?}",
                fields));
        }

        let algo: u8 = fields[0].parse().map_err(
            |e| anyhow::anyhow!("Failed to parse algorithm: {}", e))?;
        let sk = openpgp::fmt::hex::decode(&fields[1])?;
        Self::new(algo, sk).map_err(
            |e| anyhow::anyhow!("Bad session key: {}", e))
    }
}

fn print_additional_version(config: &Config) {
    safe_println!();
    safe_println!("Home: {}", config.homedir.display());

    safe_println!("Supported algorithms:");

    struct Writer(String, usize);
    impl Writer {
        fn new(label: &str) -> Self {
            Writer(label.to_string(), label.len())
        }
        fn emit(&mut self, msg: fmt::Arguments) {
            if let Some(", ") = msg.as_str() {
                self.0.write_fmt(msg).unwrap();
                return;
            }
            if self.0.len() > 60 {
                self.newline();
                while self.0.len() < self.1 {
                    self.0.push(' ');
                }
            }
            use std::fmt::Write;
            self.0.write_fmt(msg).unwrap();
        }
        fn newline(&mut self) {
            match self.0.pop() {
                Some(' ') => (), // Swallow.
                Some(c) => self.0.push(c), // Put back.  Unlikely.
                None => (),
            }
            safe_println!("{}", self.0);
            self.0.clear();
        }
    }

    let mut w = Writer::new("Pubkey: ");
    for (i, a) in (0..0xff).into_iter()
        .filter(|a| *a != 2 && *a != 3) // Skip single-use RSA
        .filter(|a| *a != 20) // Skip dual-use ElGamal
        .map(PublicKeyAlgorithm::from)
        .filter(|a| a.is_supported())
        .filter(|a| config.policy.public_key_algorithm(*a).is_ok())
        .enumerate()
    {
        if i > 0 {
            w.emit(format_args!(", "));
        }
        w.emit(format_args!("{}", babel::Fish(a)));
    }
    w.newline();

    let mut w = Writer::new("Cipher: ");
    for (i, a) in (0..0xff).into_iter()
        .map(SymmetricAlgorithm::from)
        .filter(|a| a.is_supported())
        .filter(|a| config.policy.symmetric_algorithm(*a).is_ok())
        .enumerate()
    {
        if i > 0 {
            w.emit(format_args!(", "));
        }
        w.emit(format_args!("{}", babel::Fish(a)));
    }
    w.newline();

    let mut w = Writer::new("Hash: ");
    for (i, a) in (0..0xff).into_iter()
        .map(HashAlgorithm::from)
        .filter(|a| *a != HashAlgorithm::MD5)
        .filter(|a| a.is_supported()).enumerate()
    {
        if i > 0 {
            w.emit(format_args!(", "));
        }
        w.emit(format_args!("{}", babel::Fish(a)));
    }
    w.newline();

    let mut w = Writer::new("Compression: ");
    for (i, a) in (0..0xff).into_iter()
        .map(CompressionAlgorithm::from)
        .filter(|a| a.is_supported()).enumerate()
    {
        if i > 0 {
            w.emit(format_args!(", "));
        }
        w.emit(format_args!("{}", babel::Fish(a)));
    }
    w.newline();
}

fn real_main() -> anyhow::Result<()> {
    tracing::parse_command_line();

    let parser = argparse::Parser::new(
        "gpg",
        crate::gnupg_interface::VERSION,
        "Sign, check, encrypt or decrypt\n\
         Default operation depends on the input data",
        &OPTIONS)
        .with_additional_version_information(print_additional_version);

    let mut opt = Config::new()?;
    let mut args = Vec::new();
    let mut command = None;
    let mut auto_key_locate_given = false;
    let mut greeting = false;
    let mut no_greeting = false;
    let mut detached_sig = false;
    let mut multifile = false;
    let mut keyrings = vec![];
    let mut debug_level = None;
    let mut logfile = None;
    let mut fpr_maybe_cmd = false;
    let mut default_keyring = false;
    let mut eyes_only = false;
    let mut s2k_digest: Option<HashAlgorithm> = None;
    let mut s2k_cipher: Option<SymmetricAlgorithm> = None;
    let mut pwfd: Option<fs::File> = None;

    // First pass: check special options.
    for rarg in parser.parse_command_line().quietly() {
        let argument =
            rarg.context("Error parsing command-line arguments")?;
        match argument {
            Argument::Option(oNoOptions, _) => opt.no_homedir_creation = true,
            Argument::Option(oHomedir, value) =>
                opt.homedir = value.as_str().unwrap().into(),
            Argument::Option(oNoPermissionWarn, _) => opt.no_perm_warn = true,
            _ => (),
        }
    }

    // Second pass: execute implicit commands.
    for rarg in parser.parse_command_line().quietly() {
        let arg =
            rarg.context("Error parsing command-line arguments")?;
        match arg {
            Argument::Option(aHelp, _) =>
                return Ok(parser.help(&opt)),
            Argument::Option(aWarranty, _) =>
                return Ok(parser.warranty()),
            Argument::Option(aDumpOptions, _) =>
                return Ok(parser.dump_options()),
            Argument::Option(aDumpOpttbl, _) =>
                return Ok(parser.dump_options_table()),
            _ => (),
        }
    }

    opt.check_homedir_permissions()?;

    // Third pass: parse config file(s) and the command line again.
    let homedir_conf = opt.homedir.join("gpg.conf");
    for (config_file, rarg) in
        parser.try_parse_file(&homedir_conf)?
        .map(|rarg| (Some(&homedir_conf), rarg))
        .chain(parser.parse_command_line()
               .map(|rarg| (None, rarg)))
    {
        let argument =
            rarg.with_context(|| {
                if let Some(f) = &config_file {
                    format!("Error parsing config file {}",
                            f.display())
                } else {
                    "Error parsing command-line arguments".into()
                }
            })?;

        let (cmd, value) = match argument {
            Argument::Option(cmd, value) => (cmd, value),
            Argument::Positional(arg) => {
                args.push(arg);
                continue;
            },
        };
      let mut handle_argument = || -> Result<bool> {
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

            aVersion
	        | aCheckKeys
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
                // Note: contrary to GnuPG we don't use the import
                // code.
                opt.import_options.show = true;
                opt.import_options.dry_run = true;
                opt.list_options.unusable_uids = true;
                opt.list_options.unusable_subkeys = true;
                opt.list_options.ietf_notations = true;
                opt.list_options.user_notations = true;
                opt.list_options.policy_urls = true;
            },

	    aDetachedSign => {
                // XXX: This is stupid.  It should be a command of its
                // own.  As is, detached signing is orthogonal to
                // encryption, so gpg --encrypt --detach-sign does
                // what it is asked to.
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
                opt.input_size_hint =
                    Some(value.as_str().unwrap().parse()
                         .context("Parsing the input hint")?);
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
	        opt.list_options.unusable_uids = true;
	        opt.list_options.unusable_subkeys = true;
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
	        opt.list_options.keyring_name = true;
	    },

	    oDebug | oDebugAll => {
                // Debugging is handled early on.  See module tracing.
            },

            oDebugLevel => {
                // XXX: This is currently ignored.
                debug_level = Some(value.as_str().unwrap().to_string());
            },

            oDebugIOLBF => {
                // XXX: This is supposed to set stdout to line buffered mode.
            },

	    oStatusFD => {
                opt.status_fd.set_stream(
                    argparse::utils::sink_from_fd(value.as_int().unwrap())?);
            },
	    oStatusFile => {
                opt.status_fd.set_stream(
                    Box::new(fs::File::create(value.as_str().unwrap())?));
            },
	    oAttributeFD => {
                opt.attribute_fd = argparse::utils::sink_from_fd(value.as_int().unwrap())?;
            },
	    oAttributeFile => {
                opt.attribute_fd =
                    Box::new(fs::File::create(value.as_str().unwrap())?);
            },
	    oLoggerFD => {
                opt.logger_fd = Mutex::new(RefCell::new(
                    argparse::utils::sink_from_fd(value.as_int().unwrap())?));
            },
            oLoggerFile => {
                // XXX: Why is this different from opt.logger_fd??
                logfile = Some(PathBuf::from(value.as_str().unwrap()));
            },

	    oWithFingerprint => {
                opt.fingerprint += 1;
                opt.with_fingerprint = true;
                opt.with_subkey_fingerprint = opt.fingerprint > 1;
            },
	    oWithSubkeyFingerprint => {
                opt.with_subkey_fingerprint = true;
            },
	    oWithICAOSpelling => {
                opt.with_icao_spelling = true;
            },
	    oFingerprint => {
                opt.fingerprint += 1;
                opt.with_fingerprint = opt.fingerprint > 0;
                opt.with_subkey_fingerprint = opt.fingerprint > 1;
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
	        obsolete_option ("secret-keyring");
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
                opt.list_options.list_sigs = false;
            },
            oQuickRandom => (),
	    oEmitVersion => {
                opt.emit_version += 1;
            },
	    oNoEmitVersion => {
                opt.emit_version = 0;
            },
	    oCompletesNeeded => {
                opt.completes_needed = Some(value.as_int().unwrap());
            },
	    oMarginalsNeeded => {
                opt.marginals_needed = Some(value.as_int().unwrap());
            },
	    oMaxCertDepth => {
                opt.max_cert_depth = Some(value.as_int().unwrap());
            },

	    oTrustDBName => {
                opt.trustdb =
                    trust::db::TrustDB::with_name(value.as_str().unwrap());
            },

	    oDefaultKey => {
                // XXX: Maybe warn about non-fingerprint queries here.
                opt.def_secret_key.push(value.as_str().unwrap().into());
                // XXX:
                // sl->flags = (pargs.r_opt << PK_LIST_SHIFT);
                // if (configname)
                //   sl->flags |= PK_LIST_CONFIG;
            },
	    oDefRecipient => {
                if let Ok(v) = value.as_str() {
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
                opt.list_options.list_sigs = true;
            },
            oWithSigList => {
                opt.list_options.list_sigs = true;
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
                opt.trust_model = Some(trust::TrustModel::Always);
            },

	    oTrustModel => {
	        opt.trust_model = Some(value.as_str().unwrap().parse()?);
	    },

	    oTOFUDefaultPolicy => {
	        opt.tofu_default_policy = value.as_str().unwrap().parse()?;
	    },
	    oTOFUDBFormat => {
	        obsolete_option ("tofu-db-format");
	    },

	    oForceOwnertrust => {
	        safe_eprintln!("Note: {} is not for normal use!",
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

	    oMinRSALength => {
                opt.de_vs_producer = compliance::DeVSProducer::new(
                    value.as_int().unwrap().try_into()?);
            },

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
	        opt.list_options.policy_urls = true;
	        opt.verify_options.policy_urls = true;
	    },
	    oNoShowPolicyURL => {
	        deprecated_warning("--no-show-policy-url",
			           "--list-options ", "no-show-policy-urls");
	        deprecated_warning("--no-show-policy-url",
			           "--verify-options ", "no-show-policy-urls");
	        opt.list_options.policy_urls = false;
	        opt.verify_options.policy_urls = false;
	    },
	    oSigKeyserverURL => {
                opt.sig_keyserver_url.push(URL::new(value.as_str().unwrap()));
            },

	    oUseEmbeddedFilename =>
                return Err(anyhow::anyhow!(
                    "This option is a security risk \
                     and is thus not supported")),
	    oNoUseEmbeddedFilename => (), // This is a NOP for us.

	    oComment => {
	        if let Ok(v) = value.as_str() {
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
	        opt.list_options.photos = true;
	        opt.verify_options.photos = true;
	    },
	    oNoShowPhotos => {
	        deprecated_warning("--no-show-photos",
			           "--list-options ","no-show-photos");
	        deprecated_warning("--no-show-photos",
			           "--verify-options ","no-show-photos");
	        opt.list_options.photos = false;
	        opt.verify_options.photos = false;
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
	    oS2KDigest => s2k_digest =
                Some(value.as_str().unwrap().parse::<babel::Fish<_>>()?.0),
	    oS2KCipher => s2k_cipher =
                Some(value.as_str().unwrap().parse::<babel::Fish<_>>()?.0),
	    oS2KCount => {
	        if let Ok(v) = value.as_int() {
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
                opt.remote_user.push(Recipient {
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
		opt.def_sig_expire = utils::parse_expiration(
                    opt.now(), value.as_str().unwrap())?;
	    },
	    oAskSigExpire => {
                opt.ask_sig_expire = true;
            },
	    oNoAskSigExpire => {
                opt.ask_sig_expire = false;
            },
	    oDefCertExpire => {
		opt.def_cert_expire = utils::parse_expiration(
                    opt.now(), value.as_str().unwrap())?;
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
                // XXX: Maybe warn about non-fingerprint queries here.
                opt.local_user.push(Sender {
                    name: value.as_str().unwrap().into(),
                    config: config_file.is_some(),
                });
	    },
	    oSender => {
                let sender = value.as_str().unwrap();
                if let Some(v) = argparse::utils::mailbox_from_userid(sender)? {
                    opt.sender_list.push(v);
                } else {
                    return Err(anyhow::anyhow!(
                        "{:?} does not contain an email address", sender));
                }
	    },
	    oCompress
                | oCompressLevel
                | oBZ2CompressLevel =>
            {
	        opt.compress_level = value.as_int().unwrap();
	    },
	    oBZ2DecompressLowmem => (),
	    oPassphrase => {
                opt.static_passphrase =
                    Some(value.as_str().unwrap().into()).into();
	    },
	    oPassphraseFD => {
                pwfd = Some(argparse::utils::source_from_fd(value.as_int().unwrap())?);
            },
	    oPassphraseFile => {
                pwfd = Some(fs::File::open(value.as_str().unwrap())?);
            },
	    oPassphraseRepeat => {
                opt.passphrase_repeat = value.as_int().unwrap();
            },

            oPinentryMode => {
	        opt.pinentry_mode = value.as_str().unwrap().parse()?;
	    },

            oRequestOrigin => {
	        opt.request_origin = value.as_str().unwrap().parse()?;
	    },

	    oCommandFD => {
                opt.command_fd =
                    argparse::utils::source_from_fd(value.as_int().unwrap())?.into();
            },
	    oCommandFile => {
                opt.command_fd =
                    fs::File::open(value.as_str().unwrap())?.into();
            },

	    oCipherAlgo => opt.def_cipher =
                Some(value.as_str().unwrap().parse::<babel::Fish<_>>()?.0),
	    oDigestAlgo => opt.def_digest =
                Some(value.as_str().unwrap().parse::<babel::Fish<_>>()?.0),
	    oCompressAlgo => opt.compress_algo =
                Some(value.as_str().unwrap().parse::<babel::Fish<_>>()?.0),
	    oCertDigestAlgo => opt.cert_digest =
                Some(value.as_str().unwrap().parse::<babel::Fish<_>>()?.0),

	    oNoSecmemWarn => (),
	    oRequireSecmem => (),
	    oNoRequireSecmem => (),
	    oNoPermissionWarn => {
                opt.no_perm_warn = true;
            },
            oDisplayCharset => (),
	    oNotDashEscaped => {
                opt.not_dash_escaped = true;
            },
	    oEscapeFrom => {
                opt.escape_from = true;
            },
	    oNoEscapeFrom => {
                opt.escape_from = false;
            },
	    oLockOnce => {
                opt.lock_once = true;
            },
	    oLockNever => {
                opt.dotlock_disable = true;
            },
	    oLockMultiple => {
	        opt.lock_once = false;
            },
	    oKeyServer => {
                let ks = value.as_str().unwrap().parse()?;
                if ! opt.keyserver.contains(&ks) {
                    opt.keyserver.push(ks);
                }
	    },
	    oKeyServerOptions => {
                let options = value.as_str().unwrap();
                if keyserver::KeyserverOptions::maybe_print_help(options)? {
                    return Ok(true);
                }
                opt.keyserver_options.parse(value.as_str().unwrap())?;
	    },

            oExportOptions => {
                let options = value.as_str().unwrap();
                if export::ExportOptions::maybe_print_help(options)? {
                    return Ok(true);
                }
                opt.export_options.parse(value.as_str().unwrap())?;
            },

            oImportOptions => {
                let options = value.as_str().unwrap();
                if import::ImportOptions::maybe_print_help(options)? {
                    return Ok(true);
                }
                opt.import_options.parse(value.as_str().unwrap())?;
            },

            oListOptions => {
                let options = value.as_str().unwrap();
                if list_keys::ListOptions::maybe_print_help(options)? {
                    return Ok(true);
                }
                opt.list_options.parse(value.as_str().unwrap())?;
            },

            oDisableCipherAlgo => {
                let a: babel::Fish<SymmetricAlgorithm> =
                    value.as_str().unwrap().parse()?;
                opt.policy.reject_symmetric_algo(a.0);
            },

            oDisablePubkeyAlgo => {
                let a: babel::Fish<PublicKeyAlgorithm> =
                    value.as_str().unwrap().parse()?;
                opt.policy.reject_public_key_algo(a.0);
            },

            oVerifyOptions => {
                let options = value.as_str().unwrap();
                if verify::VerifyOptions::maybe_print_help(options)? {
                    return Ok(true);
                }
                opt.verify_options.parse(value.as_str().unwrap())?;
            },

	    oShowSessionKey => {
                opt.show_session_key = true;
            },
            oOverrideSessionKey => {
                opt.override_session_key =
                    Some(value.as_str().unwrap().parse()?);
            },
            oOverrideSessionKeyFD => {
                let mut h = argparse::utils::source_from_fd(value.as_int().unwrap())?;
                let mut buf = Vec::new();
                h.read_to_end(&mut buf)?;
                opt.override_session_key =
                    Some(String::from_utf8(buf)?.parse()?);
            },
            oTrustedKey => {
                // XXX: We don't support KeyIDs here.
                let fp = value.as_str().unwrap().parse()?;
                if let Err(i) = opt.trusted_keys.binary_search(&fp) {
                    opt.trusted_keys.insert(i, fp);
                }
            },
	    oFastListMode => opt.list_options.fast_list = true,
	    oFixedListMode => (), // This is a NOP in GnuPG.
            oListOnly => opt.list_only = true,
	    oEnableSpecialFilenames => {
                opt.special_filenames = true;
            },
            oDefaultPreferenceList =>
                opt.def_preferences =
                Preferences::parse(value.as_str().unwrap())?.unwrap_or_default(),
            oDefaultKeyserverURL =>
                opt.def_keyserver_url = Some(value.as_str().unwrap().parse()?),
            oPersonalCipherPreferences =>
                if let Some(p) = Preferences::parse(value.as_str().unwrap())? {
                    opt.personal_cipher_prefs = Some(p.symmetric);
                },
            oPersonalDigestPreferences =>
                if let Some(p) = Preferences::parse(value.as_str().unwrap())? {
                    opt.personal_digest_prefs = Some(p.hash);
                },
            oPersonalCompressPreferences =>
                if let Some(p) = Preferences::parse(value.as_str().unwrap())? {
                    opt.personal_compress_prefs = Some(p.compression);
                },
            oWeakDigest => {
                opt.policy.weak_digest(
                    value.as_str().unwrap().parse::<babel::Fish<_>>()?.0);
            },
            oUnwrap => opt.unwrap_encryption = true,

            oGroup => {
                let g = value.as_str().unwrap().splitn(2, "=")
                    .map(|s| s.trim())
                    .collect::<Vec<_>>();
                if g.len() == 1 {
                    return Err(anyhow::anyhow!(
                        "Expected name=value pair, got: {}", g[0]));
                }
                let name = g[0].to_string();
                for value in g[1].split(" ") {
                    opt.groups.entry(name.clone()).or_default()
                        .insert(0, value.into());
                }
            },
            oUnGroup => {
                opt.groups.shift_remove(value.as_str().unwrap());
            },
            oNoGroups => {
                opt.groups.clear();
            },
            oMultifile => {
                multifile = true;
            },
            oKeyidFormat =>
                opt.keyid_format = value.as_str().unwrap().parse()?,

            oExitOnStatusWriteError =>
                opt.status_fd.exit_on_write_error(),

            oAutoKeyLocate => {
                auto_key_locate_given = true;
                for s in value.as_str().unwrap().split(',') {
                    if s == "clear" {
                        opt.auto_key_locate.clear();
                        continue;
                    }

                    let akl: AutoKeyLocate = s.parse()?;
                    if ! opt.auto_key_locate.contains(&akl) {
                        opt.auto_key_locate.push(akl);
                    }
                }
            },
            oNoAutoKeyLocate => {
                auto_key_locate_given = true;
                opt.auto_key_locate.clear();
            },

            oFakedSystemTime | oXSequoiaQuietFakedSystemTime => {
                opt.clock = value.as_str().unwrap().parse()?;
                if cmd == oFakedSystemTime {
                    // XXX: GnuPG prints this warning later.
                    use chrono::{DateTime, Utc};
                    opt.warn(format_args!(
                        "WARNING: running with faked system time: {}",
                        // 2022-09-19 10:37:42
                        DateTime::<Utc>::from(opt.now())
                            .format("%Y-%m-%d %H:%M:%S")));
                }
            },

            oForbidGenKey => opt.forbid_gen_key = true,

            // Backported from GnuPG 2.4.5.
            oAssertPubkeyAlgo =>
                opt.pubkey_algo_policy.handle_cmdline_arg(
                    value.as_str().unwrap())?,

            // Our own extensions.
            aXSequoiaParcimonie => {
                set_cmd(&mut command, aXSequoiaParcimonie)?;
            },
            oXSequoiaAutostartParcimonie => {
                opt.autostart_parcimonie = true;
            },
            aXSequoiaParcimonieDaemonize => {
                set_cmd(&mut command, aXSequoiaParcimonieDaemonize)?;
            },

            _ => (),
        }
        Ok(false)
      };

        let exit = handle_argument().with_context(|| {
            if let Some(f) = &config_file {
                if let Some(arg) = parser.argument_name(cmd) {
                    format!("Error parsing option {} in {}", arg, f.display())
                } else {
                    format!("Error parsing unknown option in {}", f.display())
                }
            } else {
                if let Some(arg) = parser.argument_name(cmd) {
                    format!("Error parsing --{}", arg)
                } else {
                    "Error parsing unknown option".into()
                }
            }
        })?;

        // We give the argument parsing code a chance to cleanly exit
        // the program.  This is used, for example, when printing
        // options such as import options.
        if exit {
            return Ok(());
        }
    }

    if command == Some(aVersion) {
        return Ok(parser.version(&opt));
    }

    if greeting && ! no_greeting {
        safe_eprintln!("gpg (Sequoia Chameleon {}) {}; \
                   Copyright (C) 2024 Sequoia PGP",
                  env!("CARGO_PKG_VERSION"),
                  crate::gnupg_interface::VERSION);
        safe_eprintln!("This is free software: \
                   you are free to change and redistribute it.");
        safe_eprintln!("There is NO WARRANTY, \
                   to the extent permitted by law.");
        safe_eprintln!();
    }

    if multifile {
        // XXX: GnuPG has a badlist of commands that don't work with
        // multifile, but in reality that list is incomplete (in fact,
        // it only supports multifile with three commands).  Let's see
        // if we can get away with a goodlist here.
        match command {
            Some(aEncr) | Some(aDecrypt) =>
                if opt.outfile().is_some() {
                    return Err(anyhow::anyhow!(
                        "--output doesn't work for this command"));
                },
            Some(aVerify) => (),
            _ => return Err(anyhow::anyhow!(
                "{:?} does not yet work with --multifile",
                command)),
        }
    }

    // If there is no command but the --fingerprint is given, default
    // to the --list-keys command.
    if command.is_none() && fpr_maybe_cmd {
        command = Some(aListKeys);
    }

    // Set the default auto key location method set, if none of the
    // options have been given.
    if ! auto_key_locate_given {
        opt.auto_key_locate = vec![
            AutoKeyLocate::Local,
            AutoKeyLocate::Wkd,
            AutoKeyLocate::KeyServer,
        ];
    }

    // XXX: More option frobbing.

    // Get the default one if no keyring has been specified.
    if keyrings.is_empty() {
        opt.keydb.add_resource(&opt.homedir, "pubring.gpg", false, true)?;

        // Use the keybox database if it is there.
        let _ = opt.keydb.add_resource(
            &opt.homedir, "gnupg-kbx-db:public-keys.d/pubring.db",
            true, false)?;
    }

    for path in keyrings {
        opt.keydb.add_resource(&opt.homedir, path, true, false)?;
    }

    if let Some(aGPGConfTest) = command {
        return Ok(());
    }

    if opt.homedir_is_default()? {
        // If we're using the default GNUPGHOME, we use the default
        // openpgp-cert-d so that certificates are shared.
        // XXX: Use CertD::default_location() once that is public.
        opt.keydb.add_certd_overlay(
            &dirs::data_dir().ok_or(anyhow::anyhow!("unsupported platform"))?
                .join("pgp.cert.d"))?;
    } else {
        // Otherwise, we create a openpgp-cert-d in the GNUPGHOME.
        opt.keydb.add_certd_overlay(&opt.homedir().join("pubring.cert.d"))?;
    }
    parcimonie::start(&opt, command);

    // If a commad is likely to access at least the number of
    // certificates divided by the number of CPUs, then we should
    // preload the certificates as we can do that in parallel.
    let preload = (matches!(command, Some(aListKeys)) && args.len() == 0)
        || (matches!(command, Some(aExport)) && args.len() == 0);
    opt.keydb.initialize(! preload)?;
    opt.trust_model_impl =
        opt.trust_model.unwrap_or(TrustModel::Auto).build(&opt)?;
    opt.trustdb.read_ownertrust(opt.trustdb.path(&opt))?;

    // Read the owner-trusts from our DB.
    // XXX: Currently, this is a plain text file.
    let overlay = opt.keydb.get_certd_overlay()?;
    let ownertrust_overlay =
        overlay.path().join("_sequoia_gpg_chameleon_ownertrust");
    if let Ok(mut f) = fs::File::open(ownertrust_overlay) {
        // Suppress info messages while importing the ownertrust from
        // our simple store.
        let quiet = opt.quiet;
        opt.quiet = true;
        opt.trustdb.import_ownertrust(&opt, &mut f)?;
        opt.quiet = quiet;
    }

    if let gpg_agent::PinentryMode::Loopback = opt.pinentry_mode {
        // In loopback mode, never ask for the password multiple
        // times.
	opt.passphrase_repeat = 0;
    }

    if let Some(mut pwfd) = pwfd {
        // Read the passphrase now.
        let mut password = Vec::new();

        // We do this very carefully, one byte at a time, to support
        // the time-honored tradition of stuffing your password in
        // front of the data stream read from stdin.
        let mut buf = [0; 1];
        loop {
            match pwfd.read_exact(&mut buf) {
                Ok(_) => if buf[0] == '\n' as u8 {
                    break;
                } else {
                    password.push(buf[0]);
                },
                Err(e) => if e.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                } else {
                    // Securely erase what we read so far.
                    let _ = Password::from(password);
                    return Err(e.into());
                },
            }
        }
        opt.static_passphrase = Some(password.into()).into();

        // Explicitly leak the File here by turning it into a file
        // descriptor to avoid closing the stream.  We may still want
        // to read data from this stream later.
        use std::os::unix::io::IntoRawFd;
        pwfd.into_raw_fd();
    }

    // Read dirmngr's configuration.  We honor some of the options
    // there, but we do the operations in this process.
    dirmngr::parse(&mut opt)?;

    if opt.keyserver.is_empty() {
        opt.keyserver.push(Default::default());
    }

    // Check for certain command whether we need to migrate a
    // secring.gpg to the gpg-agent.
    match command {
        Some(aListSecretKeys)
            | Some(aSign)
            | Some(aSignEncr)
            | Some(aSignEncrSym)
            | Some(aSignSym)
            | Some(aClearsign)
            | Some(aDecrypt)
            | Some(aSignKey)
            | Some(aLSignKey)
            | Some(aEditKey)
            | Some(aPasswd)
            | Some(aDeleteSecretKeys)
            | Some(aDeleteSecretAndPublicKeys)
            | Some(aQuickKeygen)
            | Some(aQuickAddUid)
            | Some(aQuickAddKey)
            | Some(aQuickRevUid)
            | Some(aQuickSetPrimaryUid)
            | Some(aFullKeygen)
            | Some(aKeygen)
            | Some(aImport)
            | Some(aExportSecret)
            | Some(aExportSecretSub)
            | Some(aGenRevoke)
            | Some(aDesigRevoke)
            | Some(aCardEdit)
            | Some(aChangePIN) =>
            migrate::secring(&mut opt)?,
        Some(aListKeys) if opt.with_secret =>
            migrate::secring(&mut opt)?,
        _ => (),
    }

    let result = match command {
        Some(aVerify) => if multifile {
            verify::cmd_verify_files(&opt, &args)
        } else {
            verify::cmd_verify(&opt, &args)
        },
        Some(aDecrypt) => if multifile {
            decrypt::cmd_decrypt_files(&opt, &args)
        } else {
            decrypt::cmd_decrypt(&opt, &args)
        },
        Some(aExport) => export::cmd_export(&mut opt, &args, false),
        Some(aExportSshKey) =>
            export_ssh_key::cmd_export_ssh_key(&mut opt, &args),
        Some(aImport) => import::cmd_import(&mut opt, &args),
        Some(aSign) => sign::cmd_sign(&mut opt, &args, detached_sig, false),
        Some(aClearsign) => sign::cmd_sign(&mut opt, &args, detached_sig, true),
        Some(aEncr) => if multifile {
            encrypt::cmd_encrypt_files(&mut opt, &args)
        } else {
            encrypt::cmd_encrypt(&mut opt, &args, false, false)
        },
        Some(aSym) => encrypt::cmd_encrypt(&mut opt, &args, true, false),
        Some(aSignSym) => encrypt::cmd_encrypt(&mut opt, &args, true, true),
        Some(aEncrSym) => encrypt::cmd_encrypt(&mut opt, &args, true, false),
        Some(aSignEncr) => encrypt::cmd_encrypt(&mut opt, &args, false, true),
        Some(aSignEncrSym) => encrypt::cmd_encrypt(&mut opt, &args, true, true),
        Some(aListKeys) =>
            list_keys::cmd_list_keys(&mut opt, &args, false),
        Some(aListSigs) => {
            opt.list_options.list_sigs = true;
            list_keys::cmd_list_keys(&mut opt, &args, false)
        },
        Some(aCheckKeys) => {
            opt.check_sigs = true;
            opt.list_options.list_sigs = true;
            list_keys::cmd_list_keys(&mut opt, &args, false)
        },
        Some(aListSecretKeys) =>
            list_keys::cmd_list_keys(&mut opt, &args, true),
        Some(aShowKeys) =>
            list_keys::cmd_show_keys(&mut opt, &args),
        Some(aCheckTrustDB) => Ok(()), // This is a NOP for us.
        Some(aImportOwnerTrust) =>
            commands::cmd_import_ownertrust(&mut opt, &args),
        Some(aExportOwnerTrust) =>
            commands::cmd_export_ownertrust(&opt, &args),
        Some(aListConfig) => commands::cmd_list_config(&opt, &args),
        Some(aGenRevoke) => commands::cmd_generate_revocation(&opt, &args),
        Some(aEnArmor) => commands::cmd_enarmor(&opt, &args),
        Some(aDeArmor) => commands::cmd_dearmor(&opt, &args),
        Some(aRecvKeys) => keyserver::cmd_receive_keys(&mut opt, &args),
        Some(aRefreshKeys) => keyserver::cmd_refresh_keys(&mut opt, &args),
        Some(aPrintMD) => commands::print_md(&opt, &args),
        Some(aPrintMDs) => commands::print_mds(&opt, &args),
        Some(aListPackets) => list_packets::cmd_list_packets(&opt, &args),
        Some(aKeygen) => generate_key::cmd_generate_key(&mut opt, &args, false),
        Some(aFullKeygen) => generate_key::cmd_generate_key(&mut opt, &args, true),
        Some(aQuickKeygen) =>
            generate_key::cmd_quick_generate_key(&mut opt, &args),
        Some(aQuickAddKey) => generate_key::cmd_quick_add_key(&mut opt, &args),
        Some(aQuickAddUid) => quick::cmd_quick_add_uid(&mut opt, &args),
        Some(aQuickRevUid) => quick::cmd_quick_revoke_uid(&mut opt, &args),
        None => commands::cmd_implicit(&opt, &args),

        // Our own extensions.
        Some(aXSequoiaParcimonie) =>
            parcimonie::cmd_parcimonie(&mut opt, &args),
        Some(aXSequoiaParcimonieDaemonize) =>
            parcimonie::cmd_parcimonie_daemonize(&mut opt, &args),

        Some(c) => {
            let name = parser.argument_name(c).map(|l| format!("--{}", l))
                .unwrap_or_else(|| format!("{:?}", c));
            opt.error(format_args!(
                "The command {} is not yet implemented in the Sequoia", name));
            opt.error(format_args!(
                "Chameleon.  To help us prioritize our work, please file a bug at"));
            opt.error(format_args!(
                "  https://gitlab.com/sequoia-pgp/sequoia-chameleon-gnupg/-/issues"));
            Err(anyhow::anyhow!("Command {} is not implemented.", name))
        },
    };

    // When we emit data to stdout, which is line-buffered by default,
    // some of the data may still be in the buffer.  Instead of doing
    // that in every command, we do it here once, in the hope that
    // this is more robust.
    io::stdout().flush()?;

    match result {
        Ok(()) => {
            if let Some(c) = opt.override_status_code.get() {
                std::process::exit(c);
            }
            if opt.fail.get() {
                std::process::exit(2);
            }
            Ok(())
        },
        Err(e) => {
            with_invocation_log(|w| write_error_chain_into(w, &e));
            if let Some(c) = opt.override_status_code.get() {
                std::process::exit(c);
            }
            if opt.fail.get() {
                std::process::exit(2);
            }
            if opt.verbose > 1 {
                print_error_chain(&e);
            } else {
                safe_eprintln!("gpg: {}", e);
            }
            std::process::exit(2);
        }
    }
}

fn main() {
    use std::process::exit;

    with_invocation_log(|w| {
        let a = std::env::args()
            .map(|a| format!("{:?}", a))
            .collect::<Vec<_>>();
        writeln!(w, "{}", a.join(" "))?;
        Ok(())
    });

    match real_main() {
        Ok(()) => {
            with_invocation_log(|w| Ok(writeln!(w, "success")?));
            exit(0);
        },
        Err(e) => {
            with_invocation_log(|w| write_error_chain_into(w, &e));
            print_error_chain(&e);
            exit(1);
        },
    }
}

pub fn with_invocation_log<F>(fun: F)
where
    F: FnOnce(&mut dyn std::io::Write) -> Result<()>,
{
    if cfg!(debug_assertions) {
        if let Some(p) =
            std::env::var_os("SEQUOIA_GPG_CHAMELEON_LOG_INVOCATIONS")
        {
            let mut message = Vec::new();
            let _ = write!(&mut message, "{}: ", unsafe { libc::getpid() });
            if let Ok(()) = fun(&mut message) {
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .append(true).create(true).open(p)
                {
                    let _ = f.write_all(&message);
                }
            }
        }
    }
}

/// Prints the error and causes, if any.
fn print_error_chain(err: &anyhow::Error) {
    let _ = write_error_chain_into(&mut io::stderr(), err);
}

/// Prints the error and causes, if any.
fn write_error_chain_into(sink: &mut dyn io::Write, err: &anyhow::Error)
                          -> Result<()> {
    writeln!(sink, "gpg:   error: {}", err)?;
    for cause in err.chain().skip(1) {
        writeln!(sink, "gpg: because: {}", cause)?;
    }
    Ok(())
}
