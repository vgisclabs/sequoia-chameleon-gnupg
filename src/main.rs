use std::{
    path::PathBuf,
};

use anyhow::{Context, Result};

#[macro_use]
mod macros;
#[allow(dead_code)]
mod argparse;
use argparse::{Opt, flags::*};

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
    let parser = argparse::Parser::new("gpg", &OPTIONS);
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

    // Second pass: check special options.
    for rarg in parser.parse_command_line() {
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
