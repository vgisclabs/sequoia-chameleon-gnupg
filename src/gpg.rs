use std::{
    collections::BTreeMap,
    fmt,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use sequoia_ipc as ipc;
use openpgp::{
    cert::prelude::*,
    crypto::Password,
    packet::{
        prelude::*,
        key::{PublicParts, UnspecifiedRole},
    },
    policy::Policy,
    types::*,
};

pub mod net; // XXX
pub mod wkd; // XXX

pub mod gnupg_interface;

#[macro_use]
mod macros;
pub mod agent;
#[allow(dead_code)]
pub mod argparse;
use argparse::{Argument, Opt, flags::*};
pub mod babel;
pub mod clock;
pub mod common;
use common::{Common, Compliance, Query, Validity};
pub mod compliance;
mod interactive;
pub mod keydb;
pub mod policy;
use policy::GPGPolicy;
#[allow(dead_code)]
pub mod flags;
use flags::*;
pub mod error_codes;
pub mod status;
pub mod trust;
pub mod colons;
pub mod utils;
pub mod commands;
pub mod verify;
pub mod decrypt;
pub mod export;
pub mod import;
pub mod keyserver;
pub mod sign;
pub mod encrypt;
pub mod list_keys;
pub mod locate;
use locate::AutoKeyLocate;

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

    oNoop,

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

#[allow(dead_code)]
pub struct Config {
    // Runtime.
    clock: clock::Clock,
    fail: std::cell::Cell<bool>,
    override_status_code: std::cell::Cell<Option<i32>>,
    policy: GPGPolicy,
    trustdb: trust::db::TrustDB,
    trust_model_impl: Box<dyn trust::Model>,
    de_vs_producer: compliance::DeVSProducer,

    // Configuration.
    answer_no: bool,
    answer_yes: bool,
    armor: bool,
    ask_cert_expire: bool,
    ask_cert_level: bool,
    ask_sig_expire: bool,
    auto_key_locate: Vec<AutoKeyLocate>,
    batch: bool,
    cert_digest: HashAlgorithm,
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
    def_cipher: SymmetricAlgorithm,
    def_digest: HashAlgorithm,
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
    fingerprint: usize,
    flags: Flags,
    force_ownertrust: bool,
    groups: BTreeMap<String, Vec<String>>,
    homedir: PathBuf,
    import_options: u32,
    input_size_hint: Option<u64>,
    interactive: bool,
    keydb: keydb::KeyDB,
    keyserver: Vec<KeyserverURL>,
    keyserver_options: KeyserverOptions,
    list_only: bool,
    list_options: u32,
    list_sigs: bool,
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
    passphrase: Option<String>,
    passphrase_repeat: i64,
    photo_viewer: Option<PathBuf>,
    pinentry_mode: agent::PinentryMode,
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
    static_passprase: std::cell::Cell<Option<Password>>,
    textmode: usize,
    throw_keyids: bool,
    tofu_default_policy: trust::TofuPolicy,
    trust_model: Option<trust::TrustModel>,
    trusted_keys: Vec<openpgp::Fingerprint>,
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
    attribute_fd: Box<dyn io::Write>,
    command_fd: interactive::Fd,
    logger_fd: Box<dyn io::Write>,
    status_fd: status::Fd,
}

impl Config {
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
            fingerprint: 0,
            flags: Default::default(),
            force_ownertrust: false,
            groups: Default::default(),
            homedir: std::env::var_os("GNUPGHOME")
                .map(Into::into)
                .unwrap_or_else(|| dirs::home_dir()
                                .expect("cannot get user's home directory")
                                .join(".gnupg")),
            import_options: Default::default(),
            input_size_hint: None,
            interactive: false,
            keydb: keydb::KeyDB::for_gpg(),
            keyserver: Default::default(),
            keyserver_options: Default::default(),
            list_only: false,
            list_options: Default::default(),
            list_sigs: false,
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
            passphrase: None,
            passphrase_repeat: 0, // XXX
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
            static_passprase: Default::default(),
            textmode: 0,
            throw_keyids: false,
            tofu_default_policy: Default::default(),
            trust_model: None,
            trusted_keys: vec![],
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
            attribute_fd: Box::new(io::sink()),
            command_fd: io::stdin().into(),
            logger_fd: Box::new(io::sink()),
            status_fd: status::Fd::sink(),
        })
    }

    /// Returns an IPC context.
    pub fn ipc(&self) -> Result<ipc::gnupg::Context> {
        ipc::gnupg::Context::with_homedir(&self.homedir)
    }

    /// Returns a connection to the GnuPG agent.
    pub async fn connect_agent(&self) -> Result<ipc::gnupg::Agent> {
        use agent::send_simple;

        let ctx = self.ipc()?;
        ctx.start("gpg-agent")?;
        let mut agent = ipc::gnupg::Agent::connect(&ctx).await?;

        send_simple(&mut agent, "RESET").await?;

        if let Ok(tty) = std::env::var("GPG_TTY") {
            send_simple(&mut agent, format!(
                "OPTION ttyname={}", tty)).await?;
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
                    send_simple(&mut agent, format!(
                        "OPTION ttyname={}", tty)).await?;
                }
            }
        }
        let ttyname = unsafe { libc::ttyname(0) };
        if ! ttyname.is_null() {
            let ttyname = unsafe { std::ffi::CStr::from_ptr(ttyname) };
            send_simple(&mut agent, format!(
                "OPTION ttyname={}",
                String::from_utf8_lossy(ttyname.to_bytes()))).await?;
        }
        if let Ok(term) = std::env::var("TERM") {
            send_simple(&mut agent, format!("OPTION ttytype={}", term)).await?;
        }
        if let Ok(display) = std::env::var("DISPLAY") {
            send_simple(&mut agent, format!("OPTION display={}", display)).await?;
        }
        if let Ok(xauthority) = std::env::var("XAUTHORITY") {
            send_simple(&mut agent, format!("OPTION xauthority={}", xauthority)).await?;
        }
        if let Ok(dbus) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
            send_simple(&mut agent,
                        format!("OPTION putenv=DBUS_SESSION_BUS_ADDRESS={}",
                                dbus)).await?;
        }
        send_simple(&mut agent, "OPTION allow-pinentry-notify").await?;
        send_simple(&mut agent, "OPTION agent-awareness=2.1.0").await?;
        send_simple(&mut agent, format!("OPTION pinentry-mode={}",
                                        self.pinentry_mode.as_str())).await?;

        Ok(agent)
    }

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
                    eprintln!("gpg: WARNING: homedir '{}' is not a directory",
                              self.homedir.display());
                }

                if m.uid() != unsafe { libc::getuid() } {
                    eprintln!("gpg: WARNING: unsafe ownership on homedir '{}'",
                              self.homedir.display());
                }

                if m.mode() & (libc::S_IRWXG | libc::S_IRWXO) as u32 > 0 {
                    eprintln!("gpg: WARNING: unsafe permissions on homedir '{}'",
                              self.homedir.display());
                }
            },

            windows => {
                // XXX: What can we check?
            },
        }

        Ok(())
    }

    fn mut_keydb(&mut self) -> &mut keydb::KeyDB {
        &mut self.keydb
    }

    /// Returns a signer for the given key.
    pub async fn get_signer(&self,
                            vcert: &ValidCert<'_>,
                            subkey: &Key<PublicParts, UnspecifiedRole>)
                            -> Result<Box<dyn openpgp::crypto::Signer + Send + Sync>>
    {
        let mut agent = self.connect_agent().await?;
        agent::has_key(&mut agent, subkey).await?;

        let ctx = self.ipc()?;
        Ok(Box::new(ipc::gnupg::KeyPair::new(&ctx, subkey)?
                    .with_cert(vcert)))
    }

    /// Returns the local users used e.g. in signing operations.
    pub fn local_users(&self) -> Result<Vec<String>> {
        if self.local_user.is_empty() {
            if self.def_secret_key.is_empty() {
                Err(anyhow::anyhow!("There is no default key, use -u"))
            } else {
                Ok(self.def_secret_key.clone())
            }
        } else {
            Ok(self.local_user.iter().map(|s| s.name.clone()).collect())
        }
    }

    /// Returns certs matching a given query using groups and the
    /// configured trust model.
    pub fn lookup_certs(&self, query: &Query) -> Result<Vec<(Validity, &Cert)>> {
        self.lookup_certs_with(
            self.trust_model_impl.with_policy(self, Some(self.now()))?.as_ref(),
            query, true)
    }

    /// Returns certs matching a given query using groups and the
    /// given trust model.
    pub fn lookup_certs_with<'a: 't, 't>(&'a self,
                                         vtm: &dyn trust::ModelViewAt<'t>,
                                         query: &Query,
                                         expand_groups: bool)
                                         -> Result<Vec<(Validity, &'t Cert)>> {
        match query {
            Query::Key(_) | Query::ExactKey(_) =>
                (), // Let the trust model do the lookup.

            // Try to map using groups if `expand_groups` is true.  We
            // don't want to lookup expanded names again, as we may
            // walk into loops.  GnuPG also doesn't do that.
            Query::Email(e) => if expand_groups {
                if let Some(queries) = self.groups.get(e.as_str()) {
                    let mut acc = Vec::new();
                    for query in queries {
                        let q = query.as_str().into();
                        acc.append(
                            &mut self.lookup_certs_with(vtm, &q, false)?);
                    }
                    return Ok(acc);
                }
            },
            // Maybe expand groups.  See comment above.
            Query::UserIDFragment(f) => if expand_groups {
                let e = std::str::from_utf8(f.needle())
                    .expect("was a String before");
                if let Some(queries) = self.groups.get(e) {
                    let mut acc = Vec::new();
                    for query in queries {
                        let q = query.as_str().into();
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

    /// Makes an http client for keyserver and WKD requests.
    pub fn make_http_client(&self) -> keyserver::HttpClientBuilder {
        keyserver::HttpClientBuilder::default()
	    .connect_timeout(keyserver::CONNECT_TIMEOUT)
	    .request_timeout(keyserver::REQUEST_TIMEOUT)
    }
}

impl common::Common for Config {
    fn argv0(&self) -> &'static str {
        "gpg"
    }

    fn error(&self, msg: fmt::Arguments) {
        self.warn(msg);
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

    fn keydb(&self) -> &keydb::KeyDB {
        &self.keydb
    }

    fn lookup_certs(&self, query: &Query)
                    -> anyhow::Result<Vec<(Validity, &Cert)>> {
        Config::lookup_certs(self, query)
    }

    fn outfile(&self) -> Option<&String> {
        self.outfile.as_ref()
    }

    fn policy(&self) -> &dyn Policy {
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

    fn logger(&mut self) -> &mut dyn io::Write {
        &mut self.logger_fd
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
    use_embedded_filename: bool,
}

#[derive(Clone)]
#[allow(dead_code)]
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

#[derive(Clone)]
#[allow(dead_code)]
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

#[derive(Clone, Default)]
struct KeyserverOptions {
}

impl std::str::FromStr for KeyserverOptions {
    type Err = anyhow::Error;

    fn from_str(_s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self {
            // XXX
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
    eprintln!("WARNING: {:?} is an obsolete option - it has no effect", s);
}

fn deprecated_warning(s: &str, repl1: &str, repl2: &str) {
    eprintln!("WARNING: {:?} is a deprecated option, \
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

#[allow(dead_code)]
struct Recipient {
    name: String,
    hidden: bool,
    config: bool,
    from_file: bool,
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
    println!();
    println!("Home: {}", config.homedir.display());

    println!("Supported algorithms:");

    print!("Pubkey: ");
    for (i, a) in (0..0xff).into_iter()
        .filter(|a| *a != 2 && *a != 3) // Skip single-use RSA
        .map(PublicKeyAlgorithm::from)
        .filter(|a| a.is_supported()).enumerate()
    {
        if i > 0 {
            print!(", ");
        }
        print!("{}", babel::Fish(a));
    }
    println!();

    print!("Cipher: ");
    for (i, a) in (0..0xff).into_iter()
        .map(SymmetricAlgorithm::from)
        .filter(|a| a.is_supported()).enumerate()
    {
        if i == 7 {
            print!(",\n        ");
        } else if i > 0 {
            print!(", ");
        }
        print!("{}", babel::Fish(a));
    }
    println!();

    print!("Hash: ");
    for (i, a) in (0..0xff).into_iter()
        .map(HashAlgorithm::from)
        .filter(|a| *a != HashAlgorithm::MD5)
        .filter(|a| a.is_supported()).enumerate()
    {
        if i > 0 {
            print!(", ");
        }
        print!("{}", babel::Fish(a));
    }
    println!();

    print!("Compression: ");
    for (i, a) in (0..0xff).into_iter()
        .map(CompressionAlgorithm::from)
        .filter(|a| a.is_supported()).enumerate()
    {
        if i > 0 {
            print!(", ");
        }
        print!("{}", babel::Fish(a));
    }
    println!();
}

#[allow(dead_code, unused_variables, unused_assignments)]
fn real_main() -> anyhow::Result<()> {
    let parser = argparse::Parser::new(
        "gpg",
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
    let mut pwfd: Option<Box<dyn io::Read>> = None;

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
            Argument::Option(aVersion, _) => {
                // GnuPG emits a warning on --version.
                opt.check_homedir_permissions()?;
                return Ok(parser.version(&opt));
            },
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
      let mut handle_argument = || -> Result<()> {
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
                opt.status_fd =
                    utils::sink_from_fd(value.as_int().unwrap())?.into();
            },
	    oStatusFile => {
                opt.status_fd =
                    Box::new(fs::File::create(value.as_str().unwrap())?).into();
            },
	    oAttributeFD => {
                opt.attribute_fd = utils::sink_from_fd(value.as_int().unwrap())?;
            },
	    oAttributeFile => {
                opt.attribute_fd =
                    Box::new(fs::File::create(value.as_str().unwrap())?);
            },
	    oLoggerFD => {
                opt.logger_fd = utils::sink_from_fd(value.as_int().unwrap())?;
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
                s2k_digest = Some(argparse::utils::parse_digest(value.as_str().unwrap())?);
            },
	    oS2KCipher => {
                s2k_cipher = Some(argparse::utils::parse_cipher(value.as_str().unwrap())?);
            },
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
		opt.def_sig_expire =
                    argparse::utils::parse_expiration(value.as_str().unwrap())?;
	    },
	    oAskSigExpire => {
                opt.ask_sig_expire = true;
            },
	    oNoAskSigExpire => {
                opt.ask_sig_expire = false;
            },
	    oDefCertExpire => {
		opt.def_cert_expire =
                    argparse::utils::parse_expiration(value.as_str().unwrap())?;
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
                opt.passphrase = Some(value.as_str().unwrap().to_string());
	    },
	    oPassphraseFD => {
                pwfd = Some(utils::source_from_fd(value.as_int().unwrap())?);
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

            oRequestOrigin => {
	        opt.request_origin = value.as_str().unwrap().parse()?;
	    },

	    oCommandFD => {
                opt.command_fd =
                    utils::source_from_fd(value.as_int().unwrap())?.into();
            },
	    oCommandFile => {
                opt.command_fd =
                    fs::File::open(value.as_str().unwrap())?.into();
            },
	    oCipherAlgo => {
                opt.def_cipher =
                    argparse::utils::parse_cipher(value.as_str().unwrap())?;
            },
	    oDigestAlgo => {
                opt.def_digest =
                    argparse::utils::parse_digest(value.as_str().unwrap())?;
            },
	    oCompressAlgo => {
		opt.compress_algo = Some(
                    argparse::utils::parse_compressor(value.as_str().unwrap())?);
	    },
	    oCertDigestAlgo => {
                opt.cert_digest =
                    argparse::utils::parse_digest(value.as_str().unwrap())?;
            },

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
                opt.keyserver.push(value.as_str().unwrap().parse()?);
	    },
	    oKeyServerOptions => {
                opt.keyserver_options = value.as_str().unwrap().parse()?;
	    },

	    oShowSessionKey => {
                opt.show_session_key = true;
            },
            oOverrideSessionKey => {
                opt.override_session_key =
                    Some(value.as_str().unwrap().parse()?);
            },
            oOverrideSessionKeyFD => {
                let mut h = utils::source_from_fd(value.as_int().unwrap())?;
                let mut buf = Vec::new();
                h.read_to_end(&mut buf)?;
                opt.override_session_key =
                    Some(String::from_utf8(buf)?.parse()?);
            },
            oTrustedKey => {
                // XXX: We don't really support KeyIDs here.
                opt.trusted_keys.push(value.as_str().unwrap().parse()?);
            },
            oListOnly => opt.list_only = true,
	    oEnableSpecialFilenames => {
                opt.special_filenames = true;
            },
            oWeakDigest => {
                opt.policy.weak_digest(
                    argparse::utils::parse_digest(value.as_str().unwrap())?);
            },
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
                        .push(value.into());
                }
            },
            oUnGroup => {
                opt.groups.remove(value.as_str().unwrap());
            },
            oNoGroups => {
                opt.groups.clear();
            },
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
            oFakedSystemTime => {
                opt.clock = value.as_str().unwrap().parse()?;
                // XXX: GnuPG prints this warning later.
                use chrono::{DateTime, Utc};
                opt.warn(format_args!(
                    "WARNING: running with faked system time: {}",
                    // 2022-09-19 10:37:42
                    DateTime::<Utc>::from(opt.now())
                        .format("%Y-%m-%d %H:%M:%S")));
            },
            _ => (),
        }
        Ok(())
      };

        handle_argument().with_context(|| {
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
    }

    if greeting && ! no_greeting {
        eprintln!("Greetings from the people of earth!");
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
    }

    for path in keyrings {
        opt.keydb.add_resource(&opt.homedir, path, true, false)?;
    }

    if let Some(aGPGConfTest) = command {
        return Ok(());
    }

    opt.keydb.add_certd_overlay(&opt.homedir().join("pubring.cert.d"))?;

    // If a commad is likely to access at least the number of
    // certificates divided by the number of CPUs, then we should
    // preload the certificates as we can do that in parallel.
    let preload = (matches!(command, Some(aListKeys)) && args.len() == 0)
        || (matches!(command, Some(aExport)) && args.len() == 0);
    opt.keydb.initialize(! preload)?;
    opt.trust_model_impl =
        opt.trust_model.unwrap_or_default().build(&opt)?;
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

    if let agent::PinentryMode::Loopback = opt.pinentry_mode {
        // In loopback mode, never ask for the password multiple
        // times.
	opt.passphrase_repeat = 0;
    }

    if let Some(mut pwfd) = pwfd {
        // Read the passphrase now.
        let mut password = Vec::new();
        pwfd.read_to_end(&mut password)?;
        opt.static_passprase = Some(password.into()).into();
    }

    if opt.keyserver.is_empty() {
        opt.keyserver.push(Default::default());
    }

    let result = match command {
        Some(aVerify) => verify::cmd_verify(&opt, &args),
        Some(aDecrypt) => decrypt::cmd_decrypt(&opt, &args),
        Some(aExport) => export::cmd_export(&mut opt, &args, false),
        Some(aImport) => import::cmd_import(&mut opt, &args),
        Some(aSign) => sign::cmd_sign(&mut opt, &args, detached_sig, false),
        Some(aClearsign) => sign::cmd_sign(&mut opt, &args, detached_sig, true),
        Some(aEncr) => encrypt::cmd_encrypt(&mut opt, &args, false, false),
        Some(aSym) => encrypt::cmd_encrypt(&mut opt, &args, true, false),
        Some(aSignSym) => encrypt::cmd_encrypt(&mut opt, &args, true, true),
        Some(aEncrSym) => encrypt::cmd_encrypt(&mut opt, &args, true, false),
        Some(aSignEncr) => encrypt::cmd_encrypt(&mut opt, &args, false, true),
        Some(aSignEncrSym) => encrypt::cmd_encrypt(&mut opt, &args, true, true),
        Some(aListKeys) =>
            list_keys::cmd_list_keys(&mut opt, &args, false),
        Some(aListSecretKeys) =>
            list_keys::cmd_list_keys(&mut opt, &args, true),
        Some(aCheckTrustDB) => Ok(()), // This is a NOP for us.
        Some(aImportOwnerTrust) =>
            trust::db::cmd_import_ownertrust(&mut opt, &args),
        Some(aExportOwnerTrust) =>
            trust::db::cmd_export_ownertrust(&opt, &args),
        Some(aListConfig) => commands::cmd_list_config(&opt, &args),
        Some(aGenRevoke) => commands::cmd_generate_revocation(&opt, &args),
        Some(aEnArmor) => commands::cmd_enarmor(&opt, &args),
        Some(aDeArmor) => commands::cmd_dearmor(&opt, &args),
        Some(aRecvKeys) => keyserver::cmd_receive_keys(&mut opt, &args),
        Some(aRefreshKeys) => keyserver::cmd_refresh_keys(&mut opt, &args),
        None => commands::cmd_implicit(&opt, &args),
        Some(c) => Err(anyhow::anyhow!("Command {:?} is not implemented.", c)),
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
            if opt.verbose > 1 {
                print_error_chain(&e);
            } else {
                eprintln!("gpg: {}", e);
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
    writeln!(sink, "           {}", err)?;
    for cause in err.chain().skip(1) {
        writeln!(sink, "  because: {}", cause)?;
    }
    Ok(())
}
