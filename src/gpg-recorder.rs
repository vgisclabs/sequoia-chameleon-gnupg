//! A shim around GnuPG that records all interactions.

use std::{
    collections::hash_map::{Entry, HashMap},
    env,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time,
    os::unix::{
        ffi::OsStrExt,
        fs::PermissionsExt,
        io::{AsRawFd, FromRawFd},
    },
};

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, Command},
    time::timeout,
};

use buffered_reader::BufferedReader;

use sequoia_openpgp as openpgp;
use openpgp::{
    crypto::hash::Digest,
    fmt::hex,
    types::*,
};

pub mod homedir;

#[macro_use]
mod macros;
#[allow(dead_code)]
pub mod argparse;
use argparse::{Argument, Opt, flags::*};

trace_module!(TRACE);

const VERBOSE: bool = false;

/// Recording metadata.
///
/// Keep in sync with the definition in tests/integration.rs and make
/// only forward-compatible changes if possible.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Metadata {
    package: String,
    version: String,
    source: String,
    creation_time: time::SystemTime,
}

impl Default for Metadata {
    fn default() -> Metadata {
        Metadata {
            package: Default::default(),
            version: Default::default(),
            source: Default::default(),
            creation_time: time::SystemTime::now(),
        }.complete_from_env()
    }
}

impl Metadata {
    /// Checks whether the metadata record looks complete.
    fn is_complete(&self) -> bool {
        ! (self.package.is_empty()
           || self.version.is_empty()
           || self.source.is_empty())
    }

    /// Completes metadata from the environment.
    fn complete_from_env(mut self) -> Self {
        if self.package.is_empty() {
            self.package = env::var("SQ_RECORDER_PACKAGE").unwrap_or_default();
        }

        if self.version.is_empty() {
            self.version = env::var("SQ_RECORDER_VERSION").unwrap_or_default();
        }

        if self.source.is_empty() {
            self.source = env::var("SQ_RECORDER_SOURCE").unwrap_or_default();
        }

        self
    }
}

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

pub struct Config {
}

/// Cancels reading from our source streams once the child exits.
static KEEP_GOING: AtomicBool = AtomicBool::new(true);

/// Waits for the child and cancels the read loops.
async fn wait_and_cancel(mut c: Child) -> Result<ExitStatus> {
    let r = c.wait().await;
    KEEP_GOING.store(false, Ordering::Relaxed);
    Ok(r?)
}

/// Copies data from `source` to `sink0` and `sink1`, returning the
/// amount of data copied.
async fn tee<R, W0, W1>(mut source: R, mut sink0: W0, mut sink1: W1)
                         -> Result<usize>
where
    R: AsyncRead + Unpin + 'static,
    W0: AsyncWrite + Unpin + 'static,
    W1: AsyncWrite + Unpin + 'static,
{
    let mut buf = vec![0; 4096];
    let mut total = 0;
    loop {
        // When the child process ends, we still try to read from our
        // stdin and block the join.  To prevent that, use a time out
        // here and when it expires, we try to flush the sink.  If the
        // sink has been closed, this will fail and we break the loop.
        match timeout(time::Duration::new(0, 10), source.read(&mut buf)).await {
            Ok(read) => {
                let amount = read?;
                if amount == 0 {
                    break;
                }
                let (r0, r1) = tokio::join!(
                    sink0.write_all(&buf[..amount]),
                    sink1.write_all(&buf[..amount]),
                );
                r0?;
                r1?;
                total += amount;
            },
            Err(_timeout) => {
                if ! KEEP_GOING.load(Ordering::Relaxed) {
                    break;
                }
            },
        }
    }
    Ok(total)
}

/// Recursively copies directories.
fn copy_r(source: &Path, dest_dir: &Path, copy_toplevel_dir: bool)
          -> io::Result<()>
{
    let mut dest_name =
        source.file_name().map(|f| dest_dir.join(f))
        .unwrap_or_else(|| dest_dir.into());

    if source.is_file() || source.is_symlink() {
        fs::copy(source, &dest_name)?;
        fix_permissions(&dest_name)?;
     } else if source.is_dir() {
        if copy_toplevel_dir {
            create_dir(&dest_name)?;
        } else {
            dest_name = dest_dir.into();
        }

        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let path = entry.path();
            copy_r(&path, &dest_name, true)?
        }
    } else {
        // Ignoring non-file, non-symlink, non-directory thing, maybe
        // a socket?
    }

    Ok(())
}

/// Fixes permissions.
///
/// As we might be running with restrictive umask, fix permissions
/// after the fact.
fn fix_permissions<P: AsRef<Path>>(p: P) -> io::Result<()> {
    let p = p.as_ref();
    let metadata = fs::metadata(p)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(if metadata.is_dir() {
        0o755
    } else {
        0o644
    });
    fs::set_permissions(p, permissions)?;
    Ok(())
}

/// Creates a world-readable directory.
///
/// As we may be running with restrictive umask, fix permissions
/// during directory creation.
fn create_dir<P: AsRef<Path>>(p: P) -> io::Result<()> {
    let p = p.as_ref();
    fs::create_dir(p).and_then(|_| fix_permissions(p))
}

/// Creates a world-readable file.
///
/// As we may be running with restrictive umask, fix permissions
/// during file creation.
fn create_file<P: AsRef<Path>>(p: P) -> io::Result<fs::File> {
    let p = p.as_ref();
    fs::File::options().create(true).write(true).open(p)
        .and_then(|f| {
            fix_permissions(p)?;
            Ok(f)
        })
}

/// Writes data to a world-readable file.
///
/// As we may be running with restrictive umask, fix permissions
/// during file creation.
fn write_file<P: AsRef<Path>, D: AsRef<[u8]>>(p: P, d: D) -> io::Result<()> {
    create_file(p)?.write_all(d.as_ref())?;
    Ok(())
}

/// Opens a pipe.
fn pipe() -> Result<(tokio::fs::File, tokio::fs::File)> {
    use interprocess::unnamed_pipe::pipe;
    use std::os::unix::io::IntoRawFd;
    let (writer, reader) = pipe()?;
    unsafe {
        Ok((tokio::fs::File::from_raw_fd(writer.into_raw_fd()),
            tokio::fs::File::from_raw_fd(reader.into_raw_fd())))
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

//#[allow(dead_code, unused_variables, unused_assignments)]
async fn record() -> anyhow::Result<ExitStatus> {
    tracer!(false, "record");

    // Record and freeze the current time.
    let now = time::SystemTime::now();
    let unix_now = now.duration_since(time::UNIX_EPOCH)?.as_secs();

    // We need to parse the arguments to get GNUPGHOME and any
    // streams.
    let parser = argparse::Parser::new(
        "gpg",
        "2.2.40+dont-trust-this-number", // no one will see this anyway
        "Sign, check, encrypt or decrypt\n\
         Default operation depends on the input data",
        &OPTIONS);

    // We may inadvertently close stderr if one of the streams is
    // directed to that, and that messes up debugging of this program.
    // Save a copy.
    let stderr_backup = unsafe { libc::dup(2) };

    // State and streams.
    let mut gnupghome: Option<PathBuf> =
        env::var_os("GNUPGHOME").map(Into::into);
    let mut output: Option<PathBuf> = None;
    let mut inputs: Vec<PathBuf> = Default::default();
    let mut statusfd: Option<fs::File> = None;
    let mut loggerfd: Option<fs::File> = None;
    let mut attributefd: Option<fs::File> = None;
    let mut commandfd: Option<fs::File> = None;
    let mut command = None;

    for rarg in parser.parse_command_line().quietly() {
        let argument =
            rarg.context("Error parsing command-line arguments")?;
        match argument {
            Argument::Option(oHomedir, value) => {
                gnupghome = Some(value.as_str().unwrap().into());
            },
            Argument::Option(oOutput, value) => {
                if value.as_str().unwrap() != "-" {
                    output = Some(value.as_str().unwrap().into());
                }
            },
            Argument::Option(oStatusFD, value) => {
                statusfd = Some(argparse::utils::file_sink_from_fd(
                    value.as_int().unwrap())?);
            },
            Argument::Option(oStatusFile, value) => {
                statusfd = Some(fs::File::open(value.as_str().unwrap())?);
            },
            Argument::Option(oLoggerFD, value) => {
                loggerfd = Some(argparse::utils::file_sink_from_fd(
                    value.as_int().unwrap())?);
            },
            Argument::Option(oLoggerFile, value) => {
                loggerfd = Some(fs::File::open(value.as_str().unwrap())?);
            },
            Argument::Option(oAttributeFD, value) => {
                attributefd = Some(argparse::utils::file_sink_from_fd(
                    value.as_int().unwrap())?);
            },
            Argument::Option(oAttributeFile, value) => {
                attributefd = Some(fs::File::open(value.as_str().unwrap())?);
            }
            Argument::Option(oCommandFD, value) => {
                commandfd = Some(argparse::utils::source_from_fd(
                    value.as_int().unwrap())?);
            },
            Argument::Option(oCommandFile, value) => {
                commandfd = Some(fs::File::open(value.as_str().unwrap())?);
            },
            Argument::Positional(input) => {
                inputs.push(input.into());
            },

            Argument::Option(aCardEdit, _) |
            Argument::Option(aCardStatus, _) |
            Argument::Option(aChangePIN, _) |
            Argument::Option(aCheckKeys, _) |
            Argument::Option(aCheckTrustDB, _) |
            Argument::Option(aClearsign, _) |
            Argument::Option(aDeArmor, _) |
            Argument::Option(aDecrypt, _) |
            Argument::Option(aDecryptFiles, _) |
            Argument::Option(aDeleteKeys, _) |
            Argument::Option(aDeleteSecretAndPublicKeys, _) |
            Argument::Option(aDeleteSecretKeys, _) |
            Argument::Option(aDesigRevoke, _) |
            Argument::Option(aDetachedSign, _) |
            Argument::Option(aDumpOptions, _) |
            Argument::Option(aDumpOpttbl, _) |
            Argument::Option(aEditKey, _) |
            Argument::Option(aEnArmor, _) |
            Argument::Option(aEncr, _) |
            Argument::Option(aEncrFiles, _) |
            Argument::Option(aEncrSym, _) |
            Argument::Option(aExport, _) |
            Argument::Option(aExportOwnerTrust, _) |
            Argument::Option(aExportSecret, _) |
            Argument::Option(aExportSecretSub, _) |
            Argument::Option(aExportSshKey, _) |
            Argument::Option(aFastImport, _) |
            Argument::Option(aFetchKeys, _) |
            Argument::Option(aFixTrustDB, _) |
            Argument::Option(aFullKeygen, _) |
            Argument::Option(aGPGConfList, _) |
            Argument::Option(aGPGConfTest, _) |
            Argument::Option(aGenRandom, _) |
            Argument::Option(aGenRevoke, _) |
            Argument::Option(aHelp, _) |
            Argument::Option(aImport, _) |
            Argument::Option(aImportOwnerTrust, _) |
            Argument::Option(aKeygen, _) |
            Argument::Option(aLSignKey, _) |
            Argument::Option(aListConfig, _) |
            Argument::Option(aListGcryptConfig, _) |
            Argument::Option(aListKeys, _) |
            Argument::Option(aListPackets, _) |
            Argument::Option(aListSecretKeys, _) |
            Argument::Option(aListSigs, _) |
            Argument::Option(aListTrustDB, _) |
            Argument::Option(aListTrustPath, _) |
            Argument::Option(aLocateExtKeys, _) |
            Argument::Option(aLocateKeys, _) |
            Argument::Option(aPasswd, _) |
            Argument::Option(aPrimegen, _) |
            Argument::Option(aPrintMD, _) |
            Argument::Option(aPrintMDs, _) |
            Argument::Option(aQuickAddKey, _) |
            Argument::Option(aQuickAddUid, _) |
            Argument::Option(aQuickKeygen, _) |
            Argument::Option(aQuickLSignKey, _) |
            Argument::Option(aQuickRevSig, _) |
            Argument::Option(aQuickRevUid, _) |
            Argument::Option(aQuickSetExpire, _) |
            Argument::Option(aQuickSetPrimaryUid, _) |
            Argument::Option(aQuickSignKey, _) |
            Argument::Option(aRebuildKeydbCaches, _) |
            Argument::Option(aRecvKeys, _) |
            Argument::Option(aRefreshKeys, _) |
            Argument::Option(aSearchKeys, _) |
            Argument::Option(aSendKeys, _) |
            Argument::Option(aServer, _) |
            Argument::Option(aShowKeys, _) |
            Argument::Option(aSign, _) |
            Argument::Option(aSignEncr, _) |
            Argument::Option(aSignEncrSym, _) |
            Argument::Option(aSignKey, _) |
            Argument::Option(aSignSym, _) |
            Argument::Option(aStore, _) |
            Argument::Option(aSym, _) |
            Argument::Option(aTOFUPolicy, _) |
            Argument::Option(aUpdateTrustDB, _) |
            Argument::Option(aVerify, _) |
            Argument::Option(aVerifyFiles, _) |
            Argument::Option(aVersion, _) |
            Argument::Option(aWarranty, _) |
            Argument::Option(aXSequoiaParcimonie, _) |
            Argument::Option(aXSequoiaParcimonieDaemonize, _) => {
                let _ = set_cmd(&mut command,
                                argument.option().unwrap().0.clone());
            },
            _ => (),
        }
    }

    // Figure out whether the positional arguments we collected are
    // actually files, and whether GnuPG (and thus us) will read from
    // stdin.
    let mut read_stdin = false;
    let dash = PathBuf::from("-");
    if let Some(c) = command {
        match c {
            aDetachedSign |
            aDecrypt |
            aEncr |
            aSign |
            aEncrFiles |
            aEncrSym |
            aDecryptFiles |
            aClearsign |
            aStore |
            aFullKeygen |
            aKeygen |
            aSignEncr |
            aSignEncrSym |
            aSignSym |
            aListPackets |
            aImport |
            aFastImport |
            aVerify |
            aVerifyFiles |
            aImportOwnerTrust |
            aDeArmor |
            aEnArmor => {
                // All of the positional arguments to these commands
                // are files.
                read_stdin =
                    inputs.is_empty() || inputs.iter().any(|i| i == &dash);
            },

            aPrintMD => {
                // The first argument is not an input but the hash
                // algorithm.
                inputs.remove(0);
                read_stdin =
                    inputs.is_empty() || inputs.iter().any(|i| i == &dash);
            },

            _ => {
                // The arguments are not files.
                inputs.clear();
            },
        }
    }

    let gnupghome = gnupghome.unwrap_or_else(|| homedir::default().unwrap());

    let real_gpg: Vec<String> = vec![
        env::var("REAL_GPG_BIN").unwrap_or("/usr/bin/gpg".into()),
    ];

    let o = Command::new(&real_gpg[0])
        .arg("--version").output().await?;
    if String::from_utf8_lossy(&o.stdout[..o.stdout.len().min(256)])
        .contains("equoia")
    {
        panic!("The oracle {:?} is Sequoia-based, please provide the \
                stock gpg in REAL_GPG_BIN", real_gpg);
    }

    // First, acquire a place to store our data.
    let recorder_base: PathBuf = env::var_os("GPG_RECORDER_BASE")
        .map(Into::into).unwrap_or_else(|| "/tmp/gpg-recorder".into());
    fs::create_dir_all(&recorder_base)?;
    fix_permissions(&recorder_base)?;
    let mut n = 0;
    let recorder_dir = loop {
        let p = recorder_base.join(n.to_string());
        if create_dir(&p).is_ok() {
            break p;
        }
        n += 1;
    };

    // If this is the first sample recording, record some metadata.
    if n == 0 {
        serde_json::to_writer(create_file(recorder_base.join("metadata.json"))?,
                              &Metadata::default())?;
    }

    t!("Recording into {}", recorder_dir.display());
    let cc_stdin: tokio::fs::File =
        create_file(recorder_dir.join("stdin"))?.into();
    let cc_stdout: tokio::fs::File =
        create_file(recorder_dir.join("stdout"))?.into();
    let cc_stderr: tokio::fs::File =
        create_file(recorder_dir.join("stderr"))?.into();
    let cc_statusfd: tokio::fs::File =
        create_file(recorder_dir.join("statusfd"))?.into();
    let cc_loggerfd: tokio::fs::File =
        create_file(recorder_dir.join("loggerfd"))?.into();
    let cc_attributefd: tokio::fs::File =
        create_file(recorder_dir.join("attributefd"))?.into();
    let cc_commandfd: tokio::fs::File =
        create_file(recorder_dir.join("commandfd"))?.into();
    let cc_input_stream0: tokio::fs::File =
        create_file(recorder_dir.join("input-stream0"))?.into();
    let cc_input_stream1: tokio::fs::File =
        create_file(recorder_dir.join("input-stream1"))?.into();

    // Then, capture all of GnuPG's state.
    {
        let target = recorder_dir.join("gnupghome");
        create_dir(&target)?;
        if gnupghome.is_dir() {
            copy_r(&gnupghome, &target, false)?;
        }
    }

    // Then, frob the arguments and invoke GnuPG.
    let original_args = env::args().collect::<Vec<_>>();
    let mut args = original_args.clone();

    // Finally, copy all streams around dumping them in the process.
    let mut c = Command::new("faketime");
    c.arg(format!("@{}", unix_now));
    c.arg(&real_gpg[0]);

    // IPC.  Stdin, stdout, and stderr we handle using the std
    // library.
    c.stdin(Stdio::piped());
    c.stdout(Stdio::piped());
    c.stderr(Stdio::piped());

    // All extra streams like statusfd require special care.

    // Status-FD.
    let (statusfd_w, statusfd_r) = pipe()?;
    let statusfd_w_fd = statusfd_w.as_raw_fd();
    let statusfd_r_fd = statusfd_r.as_raw_fd();
    let statusfd = {
        let sink: Box<dyn AsyncWrite + Unpin + 'static> =
            if let Some(s) = statusfd {
                // The caller wants status-fd output.  Frob the arguments.
                if let Some(i) =
                    args.iter().position(|a| a.as_str() == "--status-fd"
                                         ||  a.as_str() == "--status-file")
                {
                    args[i] = "--status-fd".into();
                    args[i + 1] = statusfd_w_fd.to_string();
                } else if let Some(i) =
                    args.iter().position(|a| a.starts_with("--status-fd=")
                                         || a.starts_with("--status-file="))
                {
                    args[i] = format!("--status-fd={}", statusfd_w_fd);
                }

                // And copy it to the caller.
                Box::new(tokio::fs::File::from(s))
            } else {
                args.insert(1, format!("--status-fd={}", statusfd_w_fd));
                Box::new(tokio::io::sink())
            };

        tee(statusfd_r, sink, cc_statusfd)
    };

    // Logger-FD.
    let (loggerfd_w, loggerfd_r) = pipe()?;
    let loggerfd_w_fd = loggerfd_w.as_raw_fd();
    let loggerfd_r_fd = loggerfd_r.as_raw_fd();
    let loggerfd = {
        let sink: Box<dyn AsyncWrite + Unpin + 'static> =
            if let Some(s) = loggerfd {
                // The caller wants logger-fd output.  Frob the arguments.
                if let Some(i) =
                    args.iter().position(|a| a.as_str() == "--logger-fd"
                                         || a.as_str() == "--logger-file"
                                         || a.as_str() == "--log-fd"
                                         || a.as_str() == "--log-file")
                {
                    args[i] = "--logger-fd".into();
                    args[i + 1] = loggerfd_w_fd.to_string();
                } else if let Some(i) =
                    args.iter().position(|a| a.starts_with("--logger-fd=")
                                         || a.starts_with("--logger-file=")
                                         || a.starts_with("--log-fd=")
                                         || a.starts_with("--log-file="))
                {
                    args[i] = format!("--logger-fd={}", loggerfd_w_fd);
                }

                // And copy it to the caller.
                Box::new(tokio::fs::File::from(s))
            } else {
                args.insert(1, format!("--logger-fd={}", loggerfd_w_fd));
                // If logger-fd is not requested, the messages are
                // printed to stderr.
                Box::new(tokio::io::stderr())
            };

        tee(loggerfd_r, sink, cc_loggerfd)
    };

    // Attribute-FD.
    let (attributefd_w, attributefd_r) = pipe()?;
    let attributefd_w_fd = attributefd_w.as_raw_fd();
    let attributefd_r_fd = attributefd_r.as_raw_fd();
    let attributefd = {
        let sink: Box<dyn AsyncWrite + Unpin + 'static> =
            if let Some(s) = attributefd {
                // The caller wants attribute-fd output.  Frob the arguments.
                if let Some(i) =
                    args.iter().position(|a| a.as_str() == "--attribute-fd"
                                         ||  a.as_str() == "--attribute-file")
                {
                    args[i] = "--attribute-fd".into();
                    args[i + 1] = attributefd_w_fd.to_string();
                } else if let Some(i) =
                    args.iter().position(|a| a.starts_with("--attribute-fd=")
                                         || a.starts_with("--attribute-file="))
                {
                    args[i] = format!("--attribute-fd={}", attributefd_w_fd);
                }

                // And copy it to the caller.
                Box::new(tokio::fs::File::from(s))
            } else {
                args.insert(1, format!("--attribute-fd={}", attributefd_w_fd));
                Box::new(tokio::io::sink())
            };

        tee(attributefd_r, sink, cc_attributefd)
    };

    // Command-FD.
    let (commandfd_w, commandfd_r) = pipe()?;
    let commandfd_w_fd = commandfd_w.as_raw_fd();
    let commandfd_r_fd = commandfd_r.as_raw_fd();
    let commandfd = {
        let source: Box<dyn AsyncRead + Unpin + 'static> =
            if let Some(s) = commandfd {
                // The caller wants command-fd input.  Frob the arguments.
                if let Some(i) =
                    args.iter().position(|a| a.as_str() == "--command-fd"
                                         ||  a.as_str() == "--command-file")
                {
                    args[i] = "--command-fd".into();
                    args[i + 1] = commandfd_r_fd.to_string();
                } else if let Some(i) =
                    args.iter().position(|a| a.starts_with("--command-fd=")
                                         || a.starts_with("--command-file="))
                {
                    args[i] = format!("--command-fd={}", commandfd_r_fd);
                }

                // And copy it from the caller.
                Box::new(tokio::fs::File::from(s))
            } else {
                args.insert(1, format!("--command-fd={}", commandfd_r_fd));
                Box::new(tokio::io::empty())
            };

        tee(source, commandfd_w, cc_commandfd)
    };

    // Extra input stream 0.
    let (input_stream0_w, input_stream0_r) = pipe()?;
    let input_stream0_w_fd = input_stream0_w.as_raw_fd();
    let input_stream0_r_fd = input_stream0_r.as_raw_fd();
    let mut input_stream0_index = None;
    let input_stream0 = {
        let source: Box<dyn AsyncRead + Unpin + 'static> =
            if let Some(i) = inputs.iter().position(
                |i| i.as_os_str().as_bytes().starts_with("-&".as_bytes()))
        {
            input_stream0_index = Some(i);
            let s = &inputs[i];
            let fd =
                std::str::from_utf8(&s.as_os_str().as_bytes()[2..])?.parse()?;

            // The caller wants to stream input.  Frob the arguments.
            if let Some(i) = args.iter()
                .position(|a| a.as_bytes() == s.as_os_str().as_bytes())
            {
                args[i] = format!("-&{}", input_stream0_r_fd);
            }

            // Prevent matching on this again.
            inputs[i] = "<input-stream0>".into();

            // And copy it from the caller.
            Box::new(tokio::fs::File::from(
                argparse::utils::source_from_fd(fd)?))
        } else {
            Box::new(tokio::io::empty())
        };

        tee(source, input_stream0_w, cc_input_stream0)
    };

    // Extra input stream 1.
    let (input_stream1_w, input_stream1_r) = pipe()?;
    let input_stream1_w_fd = input_stream1_w.as_raw_fd();
    let input_stream1_r_fd = input_stream1_r.as_raw_fd();
    let mut input_stream1_index = None;
    let input_stream1 = {
        let source: Box<dyn AsyncRead + Unpin + 'static> =
            if let Some(i) = inputs.iter().position(
                |i| i.as_os_str().as_bytes().starts_with("-&".as_bytes()))
        {
            input_stream1_index = Some(i);
            let s = &inputs[i];
            let fd =
                std::str::from_utf8(&s.as_os_str().as_bytes()[2..])?.parse()?;

            // The caller wants to stream input.  Frob the arguments.
            if let Some(i) = args.iter()
                .position(|a| a.as_bytes() == s.as_os_str().as_bytes())
            {
                args[i] = format!("-&{}", input_stream1_r_fd);
            }

            // Prevent matching on this again.
            inputs[i] = "<input-stream1>".into();

            // And copy it from the caller.
            Box::new(tokio::fs::File::from(
                argparse::utils::source_from_fd(fd)?))
        } else {
            Box::new(tokio::io::empty())
        };

        tee(source, input_stream1_w, cc_input_stream1)
    };

    // Be nice and drop our ends of the pipes in the child process.
    unsafe {
        c.pre_exec(move || {
            drop(fs::File::from_raw_fd(statusfd_r_fd));
            drop(fs::File::from_raw_fd(loggerfd_r_fd));
            drop(fs::File::from_raw_fd(attributefd_r_fd));
            drop(fs::File::from_raw_fd(commandfd_w_fd));
            drop(fs::File::from_raw_fd(input_stream0_w_fd));
            drop(fs::File::from_raw_fd(input_stream1_w_fd));
            Ok(())
        });
    }

    args.insert(1, "--no-permission-warning".into());
    t!("spawning {} {:?}", real_gpg[0], &args[1..]);
    serde_json::to_writer(create_file(recorder_dir.join("original-args"))?,
                          &original_args)?;
    serde_json::to_writer(create_file(recorder_dir.join("given-args"))?,
                          &args)?;
    c.args(&args[1..]);
    let mut child = c.spawn()?;

    // If GnuPG doesn't read from stdin, we must also not read from
    // stdin.  Otherwise, we risk slurping up input that wasn't meant
    // for GnuPG.
    let stdin_source: Box<dyn AsyncRead + Unpin + 'static> = if read_stdin {
        Box::new(tokio::io::stdin())
    } else {
        Box::new(tokio::io::empty())
    };
    let stdin =
        tee(stdin_source, child.stdin.take().unwrap(), cc_stdin);
    let stdout =
        tee(child.stdout.take().unwrap(), tokio::io::stdout(), cc_stdout);
    let stderr =
        tee(child.stderr.take().unwrap(), tokio::io::stderr(), cc_stderr);

    t!("waiting for child process...");
    let (result, stdin, stdout, stderr,
         statusfd, loggerfd, attributefd, commandfd,
         input_stream0, input_stream1) =
        tokio::join!(wait_and_cancel(child), stdin, stdout, stderr,
                     statusfd, loggerfd, attributefd, commandfd,
                     input_stream0, input_stream1);

    // Restore stderr, it may have been inadvertently closed (see
    // above).
    unsafe {
        libc::dup2(stderr_backup, 2);
        libc::close(stderr_backup);
    };

    t!("child process returned {:?}", result);
    let (result, stdin, stdout, stderr,
         statusfd, loggerfd, attributefd, commandfd,
         input_stream0, input_stream1) =
        (result?, stdin?, stdout?, stderr?,
         statusfd?, loggerfd?, attributefd?, commandfd?,
         input_stream0?, input_stream1?);

    t!("captured {}b stdin, {}b stdout, {}b stderr",
       stdin, stdout, stderr);
    t!("{}b statusfd, {}b loggerfd, {}b attributefd, {}b commandfd",
       statusfd, loggerfd, attributefd, commandfd);
    t!("{}b input_stream0, {}b input_stream1",
       input_stream0, input_stream1);

    write_file(recorder_dir.join("original-gnupghome"),
               gnupghome.as_os_str().as_bytes())?;
    if let Some(o) = output {
        // The caller wants output to a file.  Frob the arguments.
        if let Some(i) =
            args.iter().position(|a| a.as_str() == "-o"
                                 ||  a.as_str() == "--output")
        {
            args[i] = "--output".into();
            args[i + 1] = "output".into();
        } else if let Some(i) =
            args.iter().position(|a| a.starts_with("--output="))
        {
            args[i] = "--output=output".into();
        }

        // And preserve the output file.
        let _ = fs::copy(o, recorder_dir.join("output"))
            .and_then(|_| fix_permissions(recorder_dir.join("output")));
    }

    // Fix input arguments.
    for (i, (path, arg)) in inputs.iter().rev()
        .zip(args.iter_mut().rev())
        .rev()
        .enumerate()
    {
        if *arg == "-" {
            continue;
        }

        *arg = if Some(i) == input_stream0_index {
            "input-stream0".to_string()
        } else if Some(i) == input_stream1_index {
            "input-stream1".to_string()
        } else {
            let new_name = format!("input{}", i);
            let new_path = recorder_dir.join(&new_name);
            let _ = fs::copy(path, &new_path)
                .and_then(|_| fix_permissions(&new_path));
            new_name
        };
    }

    // Strip --homedir from args.
    if let Some(i) = args.iter().position(|a| a.starts_with("--homedir=")) {
        args.remove(i);
    } else if let Some(i) = args.iter().position(|a| a.starts_with("--hom")) {
        args.remove(i + 1);
        args.remove(i);
    }

    serde_json::to_writer(create_file(recorder_dir.join("args"))?, &args)?;
    write_file(recorder_dir.join("time"), unix_now.to_string())?;
    write_file(recorder_dir.join("result"), result.to_string())?;

    // Finally, capture all of GnuPG's state after the operation.
    {
        let target = recorder_dir.join("gnupghome-after");
        create_dir(&target)?;
        if gnupghome.is_dir() {
            copy_r(&gnupghome, &target, false)?;
        }
    }

    Ok(result)
}

fn hash_file(path: &Path, digest: &mut dyn Digest) -> Result<()> {
    let f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let mut br = buffered_reader::File::new(f, path)?;
    let data = br.data_hard(len.try_into().unwrap())?;
    digest.update(data);
    Ok(())
}

fn hash_dir(dir: &Path, digest: &mut dyn Digest) -> Result<()> {
    if dir.is_dir() {
        let mut entries = fs::read_dir(dir)?
            .map(|res| res.map(|e| e.path()))
            .collect::<Result<Vec<_>, io::Error>>()?;

        entries.sort();
        for entry in entries {
            digest.update(entry.file_name().unwrap().as_bytes());
            hash_dir(&entry, digest)?;
        }
    } else {
        digest.update(dir.file_name().unwrap().as_bytes());
        hash_file(dir, digest)?;
    }

    Ok(())
}

/// Deduplicates files, replacing dupes with hard links.
fn dedup(path: &Path, content: &mut HashMap<Vec<u8>, PathBuf>) -> Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            dedup(&entry?.path(), content)?;
        }
    } else {
        let mut h = HashAlgorithm::SHA512.context()?;
        hash_file(&path, &mut h)?;
        let digest = h.into_digest()?;
        match content.entry(digest) {
            Entry::Occupied(e) => {
                let replacement = e.get();
                if VERBOSE {
                    eprintln!("Linking {} to {}", path.display(),
                              replacement.display());
                }
                fs::remove_file(&path)?;
                fs::hard_link(&replacement, &path)?;
            },
            Entry::Vacant(e) => {
                e.insert(path.into());
            },
        }
    }

    Ok(())
}

fn clean_recording() -> Result<()> {
    let usage = "Usage: gpg-recorder --clean-recording \
                 <PATH-TO-RECORDING> <OUTPUT-PATH>";
    let source: PathBuf = env::args().nth(2).expect(usage).into();
    let target: PathBuf = env::args().nth(3).expect(usage).into();
    fs::create_dir(&target).context("creating target directory")?;

    let metadata: Metadata =
        fs::File::open(source.join("metadata.json"))
        .and_then(|f| Ok(serde_json::from_reader::<_, Metadata>(f)?))
        .unwrap_or_default()
        .complete_from_env();

    let mut i = 0; // Index into source.
    let mut j = 0; // Index into target.
    let mut hashes = HashMap::<Vec<u8>, PathBuf>::default();

    loop {
        let path = source.join(i.to_string());
        i += 1;
        if ! path.exists() {
            break;
        }

        let args = path.join("args");
        let args: Vec<String> =
            fs::File::open(&args)
            .and_then(|f| Ok(serde_json::from_reader(f)?))
            .with_context(|| format!("opening {}", args.display()))?;

        if let Some(arg) = args.iter().find_map(
            |a| (a.starts_with("--vers") || a.starts_with("--list-c"))
                .then_some(a))
        {
            if VERBOSE {
                eprintln!("{}: skipping because {}", path.display(), arg);
            }
            continue;
        }

        let mut h = HashAlgorithm::SHA512.context()?;
        hash_dir(&path, &mut h)?;
        let digest = h.into_digest()?;
        if VERBOSE {
            eprintln!("{}: {}", path.display(), hex::encode(&digest));
        }

        match hashes.entry(digest) {
            Entry::Occupied(e) => {
                if VERBOSE {
                    eprintln!("Skipping {}, same as {}", path.display(),
                              e.get().display());
                }
            },
            Entry::Vacant(e) => {
                let target = target.join(j.to_string());
                j += 1;
                eprintln!("Keeping {} as {}", path.display(), target.display());
                fs::create_dir(&target)?;
                copy_r(&path, &target, false)?;
                e.insert(path);
            },
        }
    }

    let mut content = Default::default();
    dedup(&target, &mut content)?;

    let target_metadata = target.join("metadata.json");
    serde_json::to_writer_pretty(create_file(&target_metadata)?, &metadata)?;
    if ! metadata.is_complete() {
        eprintln!("Launching editor to complete the metadata...");

        loop {
            std::process::Command::new(
                env::var("EDITOR").unwrap_or_else(|_| "editor".into()))
                .arg(&target_metadata).status()?;

            if let Err(e) = fs::File::open(&target_metadata)
                .and_then(|f| Ok(serde_json::from_reader::<_, Metadata>(f)?))
            {
                eprintln!("Malformed json, please fix: {}", e);
            } else {
                break;
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    use std::process::exit;

    if env::args().nth(1).map(|s| s == "--clean-recording").unwrap_or(false) {
        return clean_recording();
    }

    with_invocation_log(|w| {
        let a = env::args()
            .map(|a| format!("{:?}", a))
            .collect::<Vec<_>>();
        writeln!(w, "{}", a.join(" "))?;
        Ok(())
    });

    let rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(record()) {
        Ok(e) => {
            with_invocation_log(|w| Ok(writeln!(w, "success")?));
            exit(e.code().unwrap_or(42));
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
            env::var_os("SEQUOIA_GPG_CHAMELEON_LOG_INVOCATIONS")
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
