use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    fs,
    io,
    path::{Path, PathBuf},
    time,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use sequoia_ipc as ipc;
use openpgp::{
    cert::prelude::*,
    crypto::Password,
    KeyHandle,
    packet::{
        prelude::*,
        key::{PublicParts, UnspecifiedRole},
        Signature,
    },
    policy::{HashAlgoSecurity, Policy, StandardPolicy},
    types::*,
};

pub mod gnupg_interface;

#[macro_use]
mod macros;
pub mod agent;
#[allow(dead_code)]
pub mod argparse;
use argparse::{Argument, Opt, flags::*};
pub mod babel;
pub mod common;
use common::{Common, Query};
mod interactive;
pub mod keydb;
#[allow(dead_code)]
pub mod flags;
use flags::*;
pub mod status;
pub mod trust;
pub mod colons;
pub mod utils;
pub mod commands;
pub mod verify;
pub mod decrypt;
pub mod import;
pub mod sign;
pub mod encrypt;
pub mod list_keys;

/// Commands and options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum CmdOrOpt {
    aNull = 0,
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

/// GnuPG's command line options.
const OPTIONS: &[Opt<CmdOrOpt>] = &[
    Opt { short_opt: o300, long_opt: "", flags: 0, description: "@Commands:\n ", },

    Opt { short_opt: aSign, long_opt: "sign", flags: (TYPE_NONE | OPT_COMMAND), description: "make a signature", },
    Opt { short_opt: aClearsign, long_opt: "clear-sign", flags: (TYPE_NONE | OPT_COMMAND), description: "make a clear text signature", },
    Opt { short_opt: aClearsign, long_opt: "clearsign", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aDetachedSign, long_opt: "detach-sign", flags: (TYPE_NONE | OPT_COMMAND), description: "make a detached signature", },
    Opt { short_opt: aEncr, long_opt: "encrypt", flags: (TYPE_NONE | OPT_COMMAND), description: "encrypt data", },
    Opt { short_opt: aEncrFiles, long_opt: "encrypt-files", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aSym, long_opt: "symmetric", flags: (TYPE_NONE | OPT_COMMAND), description: "encryption only with symmetric cipher", },
    Opt { short_opt: aStore, long_opt: "store", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aDecrypt, long_opt: "decrypt", flags: (TYPE_NONE | OPT_COMMAND), description: "decrypt data (default)", },
    Opt { short_opt: aDecryptFiles, long_opt: "decrypt-files", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aVerify, long_opt: "verify", flags: (TYPE_NONE | OPT_COMMAND), description: "verify a signature", },
    Opt { short_opt: aVerifyFiles, long_opt: "verify-files", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aListKeys, long_opt: "list-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "list keys", },
    Opt { short_opt: aListKeys, long_opt: "list-public-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aListSigs, long_opt: "list-signatures", flags: (TYPE_NONE | OPT_COMMAND), description: "list keys and signatures", },
    Opt { short_opt: aListSigs, long_opt: "list-sigs", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aCheckKeys, long_opt: "check-signatures", flags: (TYPE_NONE | OPT_COMMAND), description: "list and check key signatures", },
    Opt { short_opt: aCheckKeys, long_opt: "check-sigs", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: oFingerprint, long_opt: "fingerprint", flags: (TYPE_NONE | OPT_COMMAND), description: "list keys and fingerprints", },
    Opt { short_opt: aListSecretKeys, long_opt: "list-secret-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "list secret keys", },
    Opt { short_opt: aKeygen, long_opt: "generate-key", flags: (TYPE_NONE | OPT_COMMAND), description: "generate a new key pair", },
    Opt { short_opt: aKeygen, long_opt: "gen-key", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aQuickKeygen, long_opt: "quick-generate-key", flags: (TYPE_NONE | OPT_COMMAND), description: "quickly generate a new key pair", },
    Opt { short_opt: aQuickKeygen, long_opt: "quick-gen-key", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aQuickAddUid, long_opt: "quick-add-uid", flags: (TYPE_NONE | OPT_COMMAND), description: "quickly add a new user-id", },
    Opt { short_opt: aQuickAddUid, long_opt: "quick-adduid", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aQuickAddKey, long_opt: "quick-add-key", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aQuickAddKey, long_opt: "quick-addkey", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aQuickRevUid, long_opt: "quick-revoke-uid", flags: (TYPE_NONE | OPT_COMMAND), description: "quickly revoke a user-id", },
    Opt { short_opt: aQuickRevUid, long_opt: "quick-revuid", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aQuickSetExpire, long_opt: "quick-set-expire", flags: (TYPE_NONE | OPT_COMMAND), description: "quickly set a new expiration date", },
    Opt { short_opt: aQuickSetPrimaryUid, long_opt: "quick-set-primary-uid", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aFullKeygen, long_opt: "full-generate-key", flags: (TYPE_NONE | OPT_COMMAND), description: "full featured key pair generation", },
    Opt { short_opt: aFullKeygen, long_opt: "full-gen-key", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aGenRevoke, long_opt: "generate-revocation", flags: (TYPE_NONE | OPT_COMMAND), description: "generate a revocation certificate", },
    Opt { short_opt: aGenRevoke, long_opt: "gen-revoke", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aDeleteKeys, long_opt: "delete-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "remove keys from the public keyring", },
    Opt { short_opt: aDeleteSecretKeys, long_opt: "delete-secret-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "remove keys from the secret keyring", },
    Opt { short_opt: aQuickSignKey, long_opt: "quick-sign-key", flags: (TYPE_NONE | OPT_COMMAND), description: "quickly sign a key", },
    Opt { short_opt: aQuickLSignKey, long_opt: "quick-lsign-key", flags: (TYPE_NONE | OPT_COMMAND), description: "quickly sign a key locally", },
    Opt { short_opt: aQuickRevSig, long_opt: "quick-revoke-sig", flags: (TYPE_NONE | OPT_COMMAND), description: "quickly revoke a key signature", },
    Opt { short_opt: aSignKey, long_opt: "sign-key", flags: (TYPE_NONE | OPT_COMMAND), description: "sign a key", },
    Opt { short_opt: aLSignKey, long_opt: "lsign-key", flags: (TYPE_NONE | OPT_COMMAND), description: "sign a key locally", },
    Opt { short_opt: aEditKey, long_opt: "edit-key", flags: (TYPE_NONE | OPT_COMMAND), description: "sign or edit a key", },
    Opt { short_opt: aEditKey, long_opt: "key-edit", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aPasswd, long_opt: "change-passphrase", flags: (TYPE_NONE | OPT_COMMAND), description: "change a passphrase", },
    Opt { short_opt: aPasswd, long_opt: "passwd", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aDesigRevoke, long_opt: "generate-designated-revocation", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aDesigRevoke, long_opt: "desig-revoke", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aExport, long_opt: "export", flags: (TYPE_NONE | OPT_COMMAND), description: "export keys", },
    Opt { short_opt: aSendKeys, long_opt: "send-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "export keys to a keyserver", },
    Opt { short_opt: aRecvKeys, long_opt: "receive-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "import keys from a keyserver", },
    Opt { short_opt: aRecvKeys, long_opt: "recv-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aSearchKeys, long_opt: "search-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "search for keys on a keyserver", },
    Opt { short_opt: aRefreshKeys, long_opt: "refresh-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "update all keys from a keyserver", },
    Opt { short_opt: aLocateKeys, long_opt: "locate-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aLocateExtKeys, long_opt: "locate-external-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aFetchKeys, long_opt: "fetch-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aShowKeys, long_opt: "show-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aExportSecret, long_opt: "export-secret-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aExportSecretSub, long_opt: "export-secret-subkeys", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aExportSshKey, long_opt: "export-ssh-key", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aImport, long_opt: "import", flags: (TYPE_NONE | OPT_COMMAND), description: "import/merge keys", },
    Opt { short_opt: aFastImport, long_opt: "fast-import", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },

    Opt { short_opt: aCardStatus, long_opt: "card-status", flags: (TYPE_NONE | OPT_COMMAND), description: "print the card status", },
    Opt { short_opt: aCardEdit,   long_opt: "edit-card",   flags: (TYPE_NONE | OPT_COMMAND), description: "change data on a card", },
    Opt { short_opt: aCardEdit,   long_opt: "card-edit",   flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aChangePIN,  long_opt: "change-pin",  flags: (TYPE_NONE | OPT_COMMAND), description: "change a card's PIN", },





    Opt { short_opt: aListConfig, long_opt: "list-config", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aListGcryptConfig, long_opt: "list-gcrypt-config", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aGPGConfList, long_opt: "gpgconf-list", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aGPGConfTest, long_opt: "gpgconf-test", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aListPackets, long_opt: "list-packets", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },


    Opt { short_opt: aExportOwnerTrust, long_opt: "export-ownertrust", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aImportOwnerTrust, long_opt: "import-ownertrust", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aUpdateTrustDB, long_opt: "update-trustdb", flags: (TYPE_NONE | OPT_COMMAND), description: "update the trust database", },
    Opt { short_opt: aCheckTrustDB, long_opt: "check-trustdb", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aFixTrustDB, long_opt: "fix-trustdb", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },


    Opt { short_opt: aDeArmor, long_opt: "dearmor", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aDeArmor, long_opt: "dearmour", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aEnArmor, long_opt: "enarmor", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aEnArmor, long_opt: "enarmour", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aPrintMD, long_opt: "print-md", flags: (TYPE_NONE | OPT_COMMAND), description: "print message digests", },
    Opt { short_opt: aPrimegen, long_opt: "gen-prime", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aGenRandom, long_opt: "gen-random", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aServer, long_opt: "server", flags: (TYPE_NONE | OPT_COMMAND), description: "run in server mode", },
    Opt { short_opt: aTOFUPolicy, long_opt: "tofu-policy", flags: (TYPE_NONE | OPT_COMMAND), description: "|VALUE|set the TOFU policy for a key", },

    Opt { short_opt: o301, long_opt: "", flags: 0, description: "@\nOptions:\n ", },

    Opt { short_opt: oArmor, long_opt: "armor", flags: TYPE_NONE, description: "create ascii armored output", },
    Opt { short_opt: oArmor, long_opt: "armour", flags: TYPE_NONE, description: "@", },

    Opt { short_opt: oRecipient, long_opt: "recipient", flags: TYPE_STRING, description: "|USER-ID|encrypt for USER-ID", },
    Opt { short_opt: oHiddenRecipient, long_opt: "hidden-recipient", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oRecipientFile, long_opt: "recipient-file", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oHiddenRecipientFile, long_opt: "hidden-recipient-file", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oRecipient, long_opt: "remote-user", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oDefRecipient, long_opt: "default-recipient", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oDefRecipientSelf, long_opt: "default-recipient-self", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoDefRecipient, long_opt: "no-default-recipient", flags: TYPE_NONE, description: "@", },

    Opt { short_opt: oTempDir, long_opt: "temp-directory", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oExecPath, long_opt: "exec-path", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oEncryptTo, long_opt: "encrypt-to", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oNoEncryptTo, long_opt: "no-encrypt-to", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oHiddenEncryptTo, long_opt: "hidden-encrypt-to", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oEncryptToDefaultKey, long_opt: "encrypt-to-default-key", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oLocalUser, long_opt: "local-user", flags: TYPE_STRING, description: "|USER-ID|use USER-ID to sign or decrypt", },
    Opt { short_opt: oSender, long_opt: "sender", flags: TYPE_STRING, description: "@", },

    Opt { short_opt: oTrySecretKey, long_opt: "try-secret-key", flags: TYPE_STRING, description: "@", },

    Opt { short_opt: oCompress, long_opt: "", flags: TYPE_INT, description: "|N|set compress level to N (0 disables)", },
    Opt { short_opt: oCompressLevel, long_opt: "compress-level", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oBZ2CompressLevel, long_opt: "bzip2-compress-level", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oBZ2DecompressLowmem, long_opt: "bzip2-decompress-lowmem", flags: TYPE_NONE, description: "@", },

    Opt { short_opt: oMimemode, long_opt: "mimemode", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oTextmodeShort, long_opt: "", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oTextmode, long_opt: "textmode", flags: TYPE_NONE, description: "use canonical text mode", },
    Opt { short_opt: oNoTextmode, long_opt: "no-textmode", flags: TYPE_NONE, description: "@", },

    Opt { short_opt: oExpert, long_opt: "expert", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoExpert, long_opt: "no-expert", flags: TYPE_NONE, description: "@", },

    Opt { short_opt: oDefSigExpire, long_opt: "default-sig-expire", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oAskSigExpire, long_opt: "ask-sig-expire", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoAskSigExpire, long_opt: "no-ask-sig-expire", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oDefCertExpire, long_opt: "default-cert-expire", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oAskCertExpire, long_opt: "ask-cert-expire", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoAskCertExpire, long_opt: "no-ask-cert-expire", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oDefCertLevel, long_opt: "default-cert-level", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oMinCertLevel, long_opt: "min-cert-level", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oAskCertLevel, long_opt: "ask-cert-level", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoAskCertLevel, long_opt: "no-ask-cert-level", flags: TYPE_NONE, description: "@", },

    Opt { short_opt: oOutput, long_opt: "output", flags: TYPE_STRING, description: "|FILE|write output to FILE", },
    Opt { short_opt: oMaxOutput, long_opt: "max-output", flags: (TYPE_ULONG | OPT_PREFIX), description: "@", },
    Opt { short_opt: oInputSizeHint, long_opt: "input-size-hint", flags: TYPE_ULONG, description: "@", },

    Opt { short_opt: oVerbose, long_opt: "verbose", flags: TYPE_NONE, description: "verbose", },
    Opt { short_opt: oQuiet, long_opt: "quiet", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoTTY, long_opt: "no-tty", flags: TYPE_NONE, description: "@", },

    Opt { short_opt: oDisableSignerUID, long_opt: "disable-signer-uid", flags: TYPE_NONE, description: "@", },

    Opt { short_opt: oDryRun, long_opt: "dry-run", flags: TYPE_NONE, description: "do not make any changes", },
    Opt { short_opt: oInteractive, long_opt: "interactive", flags: TYPE_NONE, description: "prompt before overwriting", },

    Opt { short_opt: oBatch, long_opt: "batch", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oAnswerYes, long_opt: "yes", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oAnswerNo, long_opt: "no", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oKeyring, long_opt: "keyring", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oPrimaryKeyring, long_opt: "primary-keyring", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oSecretKeyring, long_opt: "secret-keyring", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oShowKeyring, long_opt: "show-keyring", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oDefaultKey, long_opt: "default-key", flags: TYPE_STRING, description: "@", },

    Opt { short_opt: oKeyServer, long_opt: "keyserver", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oKeyServerOptions, long_opt: "keyserver-options", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oKeyOrigin, long_opt: "key-origin", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oImportOptions, long_opt: "import-options", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oImportFilter, long_opt: "import-filter", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oExportOptions, long_opt: "export-options", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oExportFilter, long_opt: "export-filter", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oListOptions, long_opt: "list-options", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oVerifyOptions, long_opt: "verify-options", flags: TYPE_STRING, description: "@", },

    Opt { short_opt: oDisplayCharset, long_opt: "display-charset", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oDisplayCharset, long_opt: "charset", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oOptions, long_opt: "options", flags: (TYPE_STRING|OPT_CONFFILE), description: "@", },

    Opt { short_opt: oDebug, long_opt: "debug", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oDebugLevel, long_opt: "debug-level", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oDebugAll, long_opt: "debug-all", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oDebugIOLBF, long_opt: "debug-iolbf", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oStatusFD, long_opt: "status-fd", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oStatusFile, long_opt: "status-file", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oAttributeFD, long_opt: "attribute-fd", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oAttributeFile, long_opt: "attribute-file", flags: TYPE_STRING, description: "@", },

    Opt { short_opt: oCompletesNeeded, long_opt: "completes-needed", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oMarginalsNeeded, long_opt: "marginals-needed", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oMaxCertDepth, long_opt: "max-cert-depth", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oTrustedKey, long_opt: "trusted-key", flags: TYPE_STRING, description: "@", },

    Opt { short_opt: oLoadExtension, long_opt: "load-extension", flags: TYPE_STRING, description: "@", },

    Opt { short_opt: oCompliance, long_opt: "compliance", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oGnuPG, long_opt: "gnupg", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oGnuPG, long_opt: "no-pgp2", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oGnuPG, long_opt: "no-pgp6", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oGnuPG, long_opt: "no-pgp7", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oGnuPG, long_opt: "no-pgp8", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oRFC2440, long_opt: "rfc2440", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oRFC4880, long_opt: "rfc4880", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oRFC4880bis, long_opt: "rfc4880bis", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oOpenPGP, long_opt: "openpgp", flags: TYPE_NONE, description: "use strict OpenPGP behavior", },
    Opt { short_opt: oPGP6, long_opt: "pgp6", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oPGP7, long_opt: "pgp7", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oPGP8, long_opt: "pgp8", flags: TYPE_NONE, description: "@", },

    Opt { short_opt: oRFC2440Text, long_opt: "rfc2440-text", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoRFC2440Text, long_opt: "no-rfc2440-text", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oS2KMode, long_opt: "s2k-mode", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oS2KDigest, long_opt: "s2k-digest-algo", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oS2KCipher, long_opt: "s2k-cipher-algo", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oS2KCount, long_opt: "s2k-count", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oCipherAlgo, long_opt: "cipher-algo", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oDigestAlgo, long_opt: "digest-algo", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oCertDigestAlgo, long_opt: "cert-digest-algo", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oCompressAlgo, long_opt: "compress-algo", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oCompressAlgo, long_opt: "compression-algo", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oThrowKeyids, long_opt: "throw-keyids", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoThrowKeyids, long_opt: "no-throw-keyids", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oShowPhotos, long_opt: "show-photos", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoShowPhotos, long_opt: "no-show-photos", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oPhotoViewer, long_opt: "photo-viewer", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oSetNotation, long_opt: "set-notation", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oSigNotation, long_opt: "sig-notation", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oCertNotation, long_opt: "cert-notation", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oKnownNotation, long_opt: "known-notation", flags: TYPE_STRING, description: "@", },

    Opt { short_opt: o302, long_opt: "", flags: 0, description: "@\n(See the man page for a complete listing of all commands and options)\n", }
,

    Opt { short_opt: o303, long_opt: "", flags: 0, description: "@\nExamples:\n\n -se -r Bob [file]          sign and encrypt for user Bob\n --clear-sign [file]        make a clear text signature\n --detach-sign [file]       make a detached signature\n --list-keys [names]        show keys\n --fingerprint [names]      show fingerprints\n", }



,


    Opt { short_opt: aPrintMDs, long_opt: "print-mds", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },

    Opt { short_opt: aListTrustDB, long_opt: "list-trustdb", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },




    Opt { short_opt: aDeleteSecretAndPublicKeys, long_opt: "delete-secret-and-public-keys", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aRebuildKeydbCaches, long_opt: "rebuild-keydb-caches", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },

    Opt { short_opt: oPassphrase, long_opt: "passphrase", flags: (TYPE_STRING | OPT_OPTIONAL), description: "@", },
    Opt { short_opt: oPassphraseFD, long_opt: "passphrase-fd", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oPassphraseFile, long_opt: "passphrase-file", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oPassphraseRepeat, long_opt: "passphrase-repeat", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oPinentryMode, long_opt: "pinentry-mode", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oRequestOrigin, long_opt: "request-origin", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oCommandFD, long_opt: "command-fd", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oCommandFile, long_opt: "command-file", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oQuickRandom, long_opt: "debug-quick-random", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoVerbose, long_opt: "no-verbose", flags: TYPE_NONE, description: "@", },


    Opt { short_opt: oTrustDBName, long_opt: "trustdb-name", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oAutoCheckTrustDB, long_opt: "auto-check-trustdb", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoAutoCheckTrustDB, long_opt: "no-auto-check-trustdb", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oForceOwnertrust, long_opt: "force-ownertrust", flags: TYPE_STRING, description: "@", },


    Opt { short_opt: oNoSecmemWarn, long_opt: "no-secmem-warning", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oRequireSecmem, long_opt: "require-secmem", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoRequireSecmem, long_opt: "no-require-secmem", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoPermissionWarn, long_opt: "no-permission-warning", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoArmor, long_opt: "no-armor", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoArmor, long_opt: "no-armour", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoDefKeyring, long_opt: "no-default-keyring", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoKeyring, long_opt: "no-keyring", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoGreeting, long_opt: "no-greeting", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoOptions, long_opt: "no-options", flags: (TYPE_NONE|OPT_CONFFILE), description: "@", },
    Opt { short_opt: oHomedir, long_opt: "homedir", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oNoBatch, long_opt: "no-batch", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithColons, long_opt: "with-colons", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithTofuInfo, long_opt: "with-tofu-info", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithKeyData, long_opt: "with-key-data", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithSigList, long_opt: "with-sig-list", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithSigCheck, long_opt: "with-sig-check", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: aListKeys, long_opt: "list-key", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aListSigs, long_opt: "list-sig", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aCheckKeys, long_opt: "check-sig", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aShowKeys, long_opt: "show-key", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: oSkipVerify, long_opt: "skip-verify", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oSkipHiddenRecipients, long_opt: "skip-hidden-recipients", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoSkipHiddenRecipients, long_opt: "no-skip-hidden-recipients", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oDefCertLevel, long_opt: "default-cert-check-level", flags: TYPE_INT, description: "@", },

    Opt { short_opt: oAlwaysTrust, long_opt: "always-trust", flags: TYPE_NONE, description: "@", },

    Opt { short_opt: oTrustModel, long_opt: "trust-model", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oTOFUDefaultPolicy, long_opt: "tofu-default-policy", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oSetFilename, long_opt: "set-filename", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oForYourEyesOnly, long_opt: "for-your-eyes-only", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoForYourEyesOnly, long_opt: "no-for-your-eyes-only", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oSetPolicyURL, long_opt: "set-policy-url", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oSigPolicyURL, long_opt: "sig-policy-url", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oCertPolicyURL, long_opt: "cert-policy-url", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oShowPolicyURL, long_opt: "show-policy-url", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoShowPolicyURL, long_opt: "no-show-policy-url", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oSigKeyserverURL, long_opt: "sig-keyserver-url", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oShowNotation, long_opt: "show-notation", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoShowNotation, long_opt: "no-show-notation", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oComment, long_opt: "comment", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oDefaultComment, long_opt: "default-comment", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoComments, long_opt: "no-comments", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oEmitVersion, long_opt: "emit-version", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoEmitVersion, long_opt: "no-emit-version", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoEmitVersion, long_opt: "no-version", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNotDashEscaped, long_opt: "not-dash-escaped", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oEscapeFrom, long_opt: "escape-from-lines", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoEscapeFrom, long_opt: "no-escape-from-lines", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oLockOnce, long_opt: "lock-once", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oLockMultiple, long_opt: "lock-multiple", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oLockNever, long_opt: "lock-never", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oLoggerFD, long_opt: "logger-fd", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oLoggerFile, long_opt: "log-file", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oLoggerFile, long_opt: "logger-file", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oUseEmbeddedFilename, long_opt: "use-embedded-filename", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoUseEmbeddedFilename, long_opt: "no-use-embedded-filename", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oUtf8Strings, long_opt: "utf8-strings", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoUtf8Strings, long_opt: "no-utf8-strings", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithFingerprint, long_opt: "with-fingerprint", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithSubkeyFingerprint, long_opt: "with-subkey-fingerprint", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithSubkeyFingerprint, long_opt: "with-subkey-fingerprints", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithICAOSpelling, long_opt: "with-icao-spelling", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithKeygrip, long_opt: "with-keygrip", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithSecret, long_opt: "with-secret", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithWKDHash, long_opt: "with-wkd-hash", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oWithKeyOrigin, long_opt: "with-key-origin", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oDisableCipherAlgo, long_opt: "disable-cipher-algo", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oDisablePubkeyAlgo, long_opt: "disable-pubkey-algo", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oAllowNonSelfsignedUID, long_opt: "allow-non-selfsigned-uid", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoAllowNonSelfsignedUID, long_opt: "no-allow-non-selfsigned-uid", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oAllowFreeformUID, long_opt: "allow-freeform-uid", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoAllowFreeformUID, long_opt: "no-allow-freeform-uid", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoLiteral, long_opt: "no-literal", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oSetFilesize, long_opt: "set-filesize", flags: (TYPE_ULONG | OPT_PREFIX), description: "@", },
    Opt { short_opt: oFastListMode, long_opt: "fast-list-mode", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oFixedListMode, long_opt: "fixed-list-mode", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oLegacyListMode, long_opt: "legacy-list-mode", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oListOnly, long_opt: "list-only", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oPrintPKARecords, long_opt: "print-pka-records", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oPrintDANERecords, long_opt: "print-dane-records", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oIgnoreTimeConflict, long_opt: "ignore-time-conflict", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oIgnoreValidFrom, long_opt: "ignore-valid-from", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oIgnoreCrcError, long_opt: "ignore-crc-error", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oIgnoreMDCError, long_opt: "ignore-mdc-error", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oShowSessionKey, long_opt: "show-session-key", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oOverrideSessionKey, long_opt: "override-session-key", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oOverrideSessionKeyFD, long_opt: "override-session-key-fd", flags: TYPE_INT, description: "@", },
    Opt { short_opt: oNoRandomSeedFile, long_opt: "no-random-seed-file", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oAutoKeyRetrieve, long_opt: "auto-key-retrieve", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoAutoKeyRetrieve, long_opt: "no-auto-key-retrieve", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoSigCache, long_opt: "no-sig-cache", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oMergeOnly, long_opt: "merge-only", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oAllowSecretKeyImport, long_opt: "allow-secret-key-import", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oTryAllSecrets, long_opt: "try-all-secrets", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oEnableSpecialFilenames, long_opt: "enable-special-filenames", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoExpensiveTrustChecks, long_opt: "no-expensive-trust-checks", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oPreservePermissions, long_opt: "preserve-permissions", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oDefaultPreferenceList, long_opt: "default-preference-list", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oDefaultKeyserverURL, long_opt: "default-keyserver-url", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oPersonalCipherPreferences, long_opt: "personal-cipher-preferences", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oPersonalDigestPreferences, long_opt: "personal-digest-preferences", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oPersonalCompressPreferences, long_opt: "personal-compress-preferences", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oFakedSystemTime, long_opt: "faked-system-time", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oWeakDigest, long_opt: "weak-digest", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oUnwrap, long_opt: "unwrap", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oOnlySignTextIDs, long_opt: "only-sign-text-ids", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oForceSignKey, long_opt: "force-sign-key", flags: TYPE_NONE, description: "@", },



    Opt { short_opt: oPersonalCipherPreferences, long_opt: "personal-cipher-prefs", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oPersonalDigestPreferences, long_opt: "personal-digest-prefs", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oPersonalCompressPreferences, long_opt: "personal-compress-prefs", flags: TYPE_STRING, description: "@", },

    Opt { short_opt: oAgentProgram, long_opt: "agent-program", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oDirmngrProgram, long_opt: "dirmngr-program", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oDisableDirmngr, long_opt: "disable-dirmngr", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oDisplay, long_opt: "display", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oTTYname, long_opt: "ttyname", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oTTYtype, long_opt: "ttytype", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oLCctype, long_opt: "lc-ctype", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oLCmessages, long_opt: "lc-messages", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oXauthority, long_opt: "xauthority", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oGroup, long_opt: "group", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oUnGroup, long_opt: "ungroup", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oNoGroups, long_opt: "no-groups", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oStrict, long_opt: "strict", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoStrict, long_opt: "no-strict", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oMangleDosFilenames, long_opt: "mangle-dos-filenames", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoMangleDosFilenames, long_opt: "no-mangle-dos-filenames", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oEnableProgressFilter, long_opt: "enable-progress-filter", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oMultifile, long_opt: "multifile", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oKeyidFormat, long_opt: "keyid-format", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oExitOnStatusWriteError, long_opt: "exit-on-status-write-error", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oLimitCardInsertTries, long_opt: "limit-card-insert-tries", flags: TYPE_INT, description: "@", },

    Opt { short_opt: oAllowMultisigVerification, long_opt: "allow-multisig-verification", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oEnableLargeRSA, long_opt: "enable-large-rsa", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oDisableLargeRSA, long_opt: "disable-large-rsa", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oEnableDSA2, long_opt: "enable-dsa2", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oDisableDSA2, long_opt: "disable-dsa2", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oAllowMultipleMessages, long_opt: "allow-multiple-messages", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoAllowMultipleMessages, long_opt: "no-allow-multiple-messages", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oAllowWeakDigestAlgos, long_opt: "allow-weak-digest-algos", flags: TYPE_NONE, description: "@", },

    Opt { short_opt: oDefaultNewKeyAlgo, long_opt: "default-new-key-algo", flags: TYPE_STRING, description: "@", },





    Opt { short_opt: oLocalUser, long_opt: "sign-with", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oRecipient, long_opt: "user", flags: TYPE_STRING, description: "@", },

    Opt { short_opt: oRequireCrossCert, long_opt: "require-backsigs", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oRequireCrossCert, long_opt: "require-cross-certification", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoRequireCrossCert, long_opt: "no-require-backsigs", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoRequireCrossCert, long_opt: "no-require-cross-certification", flags: TYPE_NONE, description: "@", },


    Opt { short_opt: oAutoKeyLocate, long_opt: "auto-key-locate", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oNoAutoKeyLocate, long_opt: "no-auto-key-locate", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoAutostart, long_opt: "no-autostart", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoSymkeyCache, long_opt: "no-symkey-cache", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oIncludeKeyBlock, long_opt: "include-key-block", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoIncludeKeyBlock, long_opt: "no-include-key-block", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oAutoKeyImport, long_opt: "auto-key-import", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoAutoKeyImport, long_opt: "no-auto-key-import", flags: TYPE_NONE, description: "@", },


    Opt { short_opt: oAllowWeakKeySignatures, long_opt: "allow-weak-key-signatures", flags: TYPE_NONE, description: "@", },



    Opt { short_opt: oUseOnlyOpenPGPCard, long_opt: "use-only-openpgp-card", flags: TYPE_NONE, description: "@", },


    Opt { short_opt: oUseAgent, long_opt: "use-agent", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoUseAgent, long_opt: "no-use-agent", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oGpgAgentInfo, long_opt: "gpg-agent-info", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oReaderPort, long_opt: "reader-port", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: octapiDriver, long_opt: "ctapi-driver", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: opcscDriver, long_opt: "pcsc-driver", flags: TYPE_STRING, description: "@", },
    Opt { short_opt: oDisableCCID, long_opt: "disable-ccid", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oHonorHttpProxy, long_opt: "honor-http-proxy", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oTOFUDBFormat, long_opt: "tofu-db-format", flags: TYPE_STRING, description: "@", },

    // Special, implicit commands.
    Opt { short_opt: aHelp, long_opt: "help", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aVersion, long_opt: "version", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aWarranty, long_opt: "warranty", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aDumpOptions, long_opt: "dump-options", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
    Opt { short_opt: aDumpOpttbl, long_opt: "dump-option-table", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },


    Opt { short_opt: oNoop, long_opt: "sk-comments", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoop, long_opt: "no-sk-comments", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoop, long_opt: "compress-keys", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoop, long_opt: "compress-sigs", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoop, long_opt: "force-v3-sigs", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoop, long_opt: "no-force-v3-sigs", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoop, long_opt: "force-v4-certs", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoop, long_opt: "no-force-v4-certs", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoop, long_opt: "no-mdc-warning", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoop, long_opt: "force-mdc", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoop, long_opt: "no-force-mdc", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoop, long_opt: "disable-mdc", flags: TYPE_NONE, description: "@", },
    Opt { short_opt: oNoop, long_opt: "no-disable-mdc", flags: TYPE_NONE, description: "@", },
];

#[allow(dead_code)]
pub struct Config {
    // Runtime.
    fail: std::cell::Cell<bool>,
    policy: GPGPolicy,
    trustdb: trust::db::TrustDB,
    trust_model_impl: Box<dyn trust::model::Model>,

    // Configuration.
    answer_no: bool,
    answer_yes: bool,
    armor: bool,
    ask_cert_expire: bool,
    ask_cert_level: bool,
    ask_sig_expire: bool,
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
    groups: BTreeMap<String, Vec<KeyHandle>>,
    homedir: PathBuf,
    import_options: u32,
    input_size_hint: Option<u64>,
    interactive: bool,
    keydb: keydb::KeyDB,
    keyserver: KeyserverURL,
    keyserver_options: KeyserverOptions,
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

impl Default for Config {
    fn default() -> Self {
        Config {
            // Runtime.
            fail: Default::default(),
            policy: Default::default(),
            trustdb: Default::default(),
            trust_model_impl: common::null_model(),

            // Configuration.
            answer_no: false,
            answer_yes: false,
            armor: false,
            ask_cert_expire: false,
            ask_cert_level: false,
            ask_sig_expire: false,
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
            status_fd: Box::new(io::sink()).into(),
        }
    }
}

impl Config {
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
    pub fn lookup_certs(&self, query: &Query) -> Result<Vec<&Cert>> {
        self.lookup_certs_with(
            self.trust_model_impl.with_policy(self, None)?.as_ref(),
            query)
    }

    /// Returns certs matching a given query using groups and the
    /// given trust model.
    pub fn lookup_certs_with<'a>(&'a self,
                                 vtm: &dyn trust::model::ModelViewAt<'a>,
                                 query: &Query)
                                 -> Result<Vec<&'a Cert>> {
        // First, try to map using groups.
        match query {
            Query::Key(h) | Query::ExactKey(h) =>
                return Ok(self.keydb.get(h).into_iter().collect()),
            Query::Email(e) => {
                if let Some(handles) = self.groups.get(e.as_str()) {
                    return self.keydb.by_primaries(handles);
                }
            },
            Query::UserIDFragment(f) => {
                let e = std::str::from_utf8(f.needle())
                    .expect("was a String before");
                if let Some(handles) = self.groups.get(e) {
                    return self.keydb.by_primaries(handles);
                }
            },
        }

        // Then, use the trust model to lookup the cert.
        vtm.lookup(query)
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

    fn trust_model_impl(&self) -> &dyn trust::model::Model {
        self.trust_model_impl.as_ref()
    }
}

const POLICY: &dyn Policy = &StandardPolicy::new();

#[derive(Debug, Default)]
struct GPGPolicy {
    /// Additional weak hash algorithms.
    ///
    /// The value indicates whether a warning has been printed for
    /// this algorithm.
    weak_digests: HashSet<HashAlgorithm>,
}

impl Policy for GPGPolicy {
    fn signature(&self, sig: &Signature, sec: HashAlgoSecurity)
                 -> openpgp::Result<()>
    {
        // First, consult the standard policy.
        POLICY.signature(sig, sec)?;


        // Then, consult our set.
        if self.weak_digests.contains(&sig.hash_algo()) {
            return Err(openpgp::Error::PolicyViolation(
                sig.hash_algo().to_string(), None).into());
        }

        Ok(())
    }

    fn key(&self, ka: &ValidErasedKeyAmalgamation<'_, PublicParts>)
           -> openpgp::Result<()>
    {
        POLICY.key(ka)
    }

    fn symmetric_algorithm(&self, algo: SymmetricAlgorithm)
                           -> openpgp::Result<()>
    {
        POLICY.symmetric_algorithm(algo)
    }

    fn aead_algorithm(&self, algo: AEADAlgorithm)
                      -> openpgp::Result<()>
    {
        POLICY.aead_algorithm(algo)
    }

    fn packet(&self, packet: &Packet)
              -> openpgp::Result<()>
    {
        POLICY.packet(packet)
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
struct KeyserverURL {
    url: String,
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

#[allow(dead_code, unused_variables, unused_assignments)]
fn real_main() -> anyhow::Result<()> {
    let parser = argparse::Parser::new(
        "gpg",
        "There is no default operation",
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
    let mut command = None;
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

    // Second pass: check special options.
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
            rarg.context("Error parsing command-line arguments")?;

        let (cmd, value) = match argument {
            Argument::Option(cmd, value) => (cmd, value),
            Argument::Positional(arg) => {
                args.push(arg);
                continue;
            },
        };

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
                s2k_digest = Some(argparse::utils::parse_digest(value.as_str().unwrap())?);
            },
	    oS2KCipher => {
                s2k_cipher = Some(argparse::utils::parse_cipher(value.as_str().unwrap())?);
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
                // store the local users */
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
                opt.passphrase = value.as_str().map(Into::into);
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
                opt.keyserver = value.as_str().unwrap().parse()?;
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
	    oEnableSpecialFilenames => {
                opt.special_filenames = true;
            },
            oGroup => {
                let g = value.as_str().unwrap().splitn(2, "=")
                    .collect::<Vec<_>>();
                if g.len() == 1 {
                    return Err(anyhow::anyhow!(
                        "Expected name=value pair, got: {}", g[0]));
                }
                let name = g[0].to_string();
                let fp = g[1].parse()
                    .context("Error parsing value as fingerprint")?;
                opt.groups.entry(name).or_default().push(fp);
            },
            oUnGroup => {
                opt.groups.remove(value.as_str().unwrap());
            },
            oNoGroups => {
                opt.groups.clear();
            },

            _ => (),
        }
    }

    if greeting && ! no_greeting {
        eprintln!("Greetings from the people of earth!");
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
    opt.keydb.initialize()?;
    opt.trust_model_impl =
        opt.trust_model.unwrap_or_default().build(&opt)?;
    let _ = opt.trustdb.read_ownertrust(opt.trustdb.path(&opt));

    // Read the owner-trusts from our DB.
    // XXX: Currently, this is a plain text file.
    let overlay = opt.keydb.get_certd_overlay()?;
    let ownertrust_overlay =
        overlay.path().join("_sequoia_gpg_chameleon_ownertrust");
    if let Ok(mut f) = fs::File::open(ownertrust_overlay) {
        opt.trustdb.import_ownertrust(&mut f)?;
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

    let result = match command {
        Some(aVerify) => verify::cmd_verify(&opt, &args),
        Some(aDecrypt) => decrypt::cmd_decrypt(&opt, &args),
        Some(aImport) => import::cmd_import(&mut opt, &args),
        Some(aSign) => sign::cmd_sign(&mut opt, &args, detached_sig, false),
        Some(aClearsign) => sign::cmd_sign(&mut opt, &args, detached_sig, true),
        Some(aEncr) => encrypt::cmd_encrypt(&mut opt, &args, false),
        Some(aSignEncr) => encrypt::cmd_encrypt(&mut opt, &args, true),
        Some(aListKeys) =>
            list_keys::cmd_list_keys(&mut opt, &args, false),
        Some(aListSecretKeys) =>
            list_keys::cmd_list_keys(&mut opt, &args, true),
        Some(aImportOwnerTrust) =>
            trust::db::cmd_import_ownertrust(&mut opt, &args),
        Some(aExportOwnerTrust) =>
            trust::db::cmd_export_ownertrust(&opt, &args),
        Some(aListConfig) => commands::cmd_list_config(&opt, &args),
        Some(aGenRevoke) => commands::cmd_generate_revocation(&opt, &args),
        None => Err(anyhow::anyhow!("There is no implicit command.")),
        Some(c) => Err(anyhow::anyhow!("Command {:?} is not implemented.", c)),
    };

    match result {
        Ok(()) => {
            if opt.fail.get() {
                std::process::exit(2);
            }
            Ok(())
        },
        Err(e) => if opt.verbose > 0 {
            Err(e)
        } else {
            with_invocation_log(|w| write_error_chain_into(w, &e));
            eprintln!("Error: {}", e);
            std::process::exit(1);
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
            use std::io::Write;
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
