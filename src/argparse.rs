//! A re-implementation of GnuPG's command-line parser.

use std::{
    io::{self, BufRead, BufReader},
    path::Path,
};

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

/// A command or option with long option, flags, and description.
struct Opt {
    short_opt: CmdOrOpt,
    long_opt: &'static str,
    flags: u32,
    description: &'static str,
}

// Flags for each option (ARGPARSE_OPTS).  The type code may be ORed
// with the OPT flags.

/// Does not take an argument.
const TYPE_NONE    : u32 =     0;
/// Takes an int argument.
const TYPE_INT     : u32 =     1;
/// Takes a string argument.
const TYPE_STRING  : u32 =     2;
/// Takes a long argument.
const TYPE_LONG    : u32 =     3;
/// Takes an unsigned long argument.
const TYPE_ULONG   : u32 =     4;
/// Argument is optional.
const OPT_OPTIONAL : u32 = 1<< 3;
/// Allow 0x etc. prefixed values.
const OPT_PREFIX   : u32 = 1<< 4;

/// The argument is a command.
const OPT_COMMAND  : u32 = 1<< 7;
/// The value is a conffile.
const OPT_CONFFILE : u32 = 1<< 8;

// Unused flags:

//const OPT_IGNORE   : u32 = 1<< 6; // Ignore command or option.
//const OPT_HEADER   : u32 = 1<< 9; // The value is printed as a header.
//const OPT_VERBATIM : u32 = 1<<10; // The value is printed verbatim.
//const ATTR_FORCE   : u32 = 1<<14; // Attribute force is set.
//const ATTR_IGNORE  : u32 = 1<<15; // Attribute ignore is set.

/// Returns the type bits for the given flags.
fn flags_type(flags: u32) -> u32 {
    flags & 0b111
}

use CmdOrOpt::*;

/// GnuPG's command line options.
const OPTIONS: &[Opt] = &[
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

/// Some arguments take a value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value {
    Int(i64),
    String(String),
    UInt(u64),
    None,
}

impl Value {
    // Returns the integer value, if applicable.
    pub fn as_int(&self) -> Option<i64> {
        if let Value::Int(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    // Returns the string value, if applicable.
    pub fn as_str(&self) -> Option<&str> {
        if let Value::String(v) = self {
            Some(v)
        } else {
            None
        }
    }

    // Returns the unsigned integer value, if applicable.
    pub fn as_uint(&self) -> Option<u64> {
        if let Value::UInt(v) = self {
            Some(*v)
        } else {
            None
        }
    }
}

/// Arguments can be read from the command line or a file.
pub enum Source {
    Args(std::env::Args),
    File(std::fs::File),
}

impl Source {
    /// Parses the command-line arguments.
    pub fn parse_command_line() -> impl Iterator<Item = Result<(CmdOrOpt, Value)>>
    {
        Source::Args(std::env::args()).parse()
    }

    /// Tries to parse the given file.
    ///
    /// If the file does not exist, an empty iterator is returned.
    pub fn try_parse_file<P>(path: P)
                             -> io::Result<Box<dyn Iterator<Item = Result<(CmdOrOpt, Value)>>>>
    where
        P: AsRef<Path>,
    {
        match std::fs::File::open(path) {
            Ok(f) => Ok(Box::new(Source::File(f).parse())),
            Err(e) => if e.kind() == io::ErrorKind::NotFound {
                Ok(Box::new(std::iter::empty()))
            } else {
                Err(e)
            }
        }
    }

    /// Parses the arguments.
    pub fn parse(self) -> impl Iterator<Item = Result<(CmdOrOpt, Value)>> {
        match self {
            Source::Args(mut a) => {
                a.next(); // swallow argv[0]
                Iter {
                    line: Box::new(std::iter::once(
                        Box::new(a.map(|arg| arg.to_string()))
                            as Box<dyn Iterator<Item = _>>
                    )),
                    current: None,
                    current_short: None,
                    cmdline: true,
                }
            },
            Source::File(f) =>
                Iter {
                    line: Box::new(
                        BufReader::new(f)
                            .lines()
                            .filter_map(|rl| rl.ok())
                        // Trim whitespace.
                            .map(|l| l.trim().to_string())
                        // Ignore comments.
                            .filter(|l| ! l.starts_with('#'))
                        // Ignore empty lines.
                            .filter(|l| ! l.is_empty())
                        // Split into argument and value, taking care
                        // of quoting.
                            .map(|l| -> Box<dyn Iterator<Item = String>> {
                                Box::new(l.splitn(2, |c: char| c.is_ascii_whitespace())
                                         .map(|w| if w.starts_with('"') && w.ends_with('"') {
                                             w[1..w.len()-2].into()
                                         } else {
                                             w.into()
                                         })
                                         .collect::<Vec<_>>()
                                         .into_iter())
                            })),
                    current: None,
                    current_short: None,
                    cmdline: false,
                },
        }
    }
}

struct Iter {
    line: Box<dyn Iterator<Item = Box<dyn Iterator<Item = String>>>>,
    current: Option<Box<dyn Iterator<Item = String>>>,
    current_short: Option<String>,
    cmdline: bool,
}

impl Iter {
    fn maybe_get_value(&mut self, opt: &Opt) -> Result<(CmdOrOpt, Value)> {
        let typ = flags_type(opt.flags);
        if typ == TYPE_NONE {
            return Ok((opt.short_opt, Value::None));
        }

        let value = match self.current_short.take()
            .or_else(|| self.current.as_mut().and_then(|i| i.next()))
        {
            Some(v) => v,
            None if opt.flags & OPT_OPTIONAL > 0 =>
                return Ok((opt.short_opt, Value::None)),
            None =>
                return Err(Error::Missing(opt.long_opt.into())),
        };

        // Handle OPT_PREFIX.
        let (value, radix) = if opt.flags & OPT_PREFIX > 0
            && (value.starts_with("0x") || value.starts_with("0X"))
        {
            (&value[2..], 16)
        } else {
            (&value[..], 10)
        };

        match typ {
            TYPE_NONE => unreachable!("handled above"),
            TYPE_INT | TYPE_LONG => match i64::from_str_radix(value, radix) {
                Ok(v) => Ok((opt.short_opt, Value::Int(v))),
                Err(_) => Err(Error::BadValue(opt.long_opt.into(),
                                              "integer",
                                              value.into())),
            },
            TYPE_ULONG => match u64::from_str_radix(value, radix) {
                Ok(v) => Ok((opt.short_opt, Value::UInt(v))),
                Err(_) => Err(Error::BadValue(opt.long_opt.into(),
                                              "unsigned integer",
                                              value.into())),
            },
            TYPE_STRING => Ok((opt.short_opt, Value::String(value.into()))),
            n => unreachable!("bad type {}", n),
        }
    }
}

impl Iterator for Iter {
    type Item = Result<(CmdOrOpt, Value)>;

    fn next(&mut self) -> Option<Self::Item> {
        // Handle leftover short options.
        if let Some(rest) = self.current_short.take() {
            let mut chars = rest.chars();
            let a0 = match chars.next() {
                Some(c) => c,
                None => unreachable!("current_short is not empty"),
            };

            // See if there are more short arguments after this one.
            let rest = chars.collect::<String>();
            self.current_short =
                if rest.is_empty() { None } else { Some(rest) };

            let matches = OPTIONS.iter()
                .filter(|o| o.short_opt as isize == a0 as isize)
                .collect::<Vec<_>>();

            let m = match matches.len() {
                0 => return Some(Err(Error::Unkown(a0.into()))),
                _ => matches[0],
            };

            return Some(self.maybe_get_value(m));
        }

        if self.current.is_none() {
            self.current = self.line.next();
        }

        if self.current.is_none() {
            // Exhausted top-level iterator, we're done.
            return None;
        }

        let mut current = self.current.take().unwrap();
        let arg = match current.next() {
            Some(a) => {
                self.current = Some(current);
                a
            },
            None => {
                // Exhausted iterator, see if there is a next line.
                return self.next();
            },
        };

        let (long, a) = if self.cmdline {
            if ! arg.starts_with("-") {
                return Some(Err(Error::Malformed(arg.into())));
            }

            if arg.starts_with("--") {
                // Long option.
                (true, &arg[2..])
            } else {
                // Short option.
                (false, &arg[1..])
            }
        } else {
            // Config file.  All options are long options.
            (true, &arg[..])
        };

        let m = if long {
            let matches = OPTIONS.iter().filter(|o| o.long_opt.starts_with(a))
                .collect::<Vec<_>>();

            match matches.len() {
                0 => return Some(Err(Error::Unkown(a.into()))),
                1 => matches[0],
                n => {
                    // See if there is an *exact* match.
                    let exact = OPTIONS.iter().filter(|o| o.long_opt == a)
                        .collect::<Vec<_>>();

                    // See if all matches refer to the same CmdOrOpt.
                    if matches.iter()
                        .all(|m| m.short_opt == matches[0].short_opt)
                    {
                        matches[0]
                    } else if ! exact.is_empty() {
                        exact[0]
                    } else {
                        let mut also = String::new();
                        for (i, c) in matches.iter().enumerate() {
                            match i {
                                0 => (),
                                x if x == n - 1 => also.push_str(", and "),
                                _ => also.push_str(", "),
                            }

                            also.push_str("--");
                            also.push_str(c.long_opt);
                        }
                        return Some(Err(Error::Ambiguous(a.into(), also)))
                    }
                },
            }
        } else {
            let mut chars = a.chars();
            let a0 = match chars.next() {
                Some(c) => c,
                None => return Some(Err(Error::Malformed(a.into()))),
            };

            // See if there are more short arguments after this one.
            let rest = chars.collect::<String>();
            self.current_short =
                if rest.is_empty() { None } else { Some(rest) };

            let matches = OPTIONS.iter()
                .filter(|o| o.short_opt as isize == a0 as isize)
                .collect::<Vec<_>>();

            match matches.len() {
                0 => return Some(Err(Error::Unkown(a0.into()))),
                _ => matches[0],
            }
        };

        Some(self.maybe_get_value(m))
    }
}

/// Displays version information.
pub fn version() {
    println!("gpg (GnuPG-compatible Sequoia Chameleon) {}",
             env!("CARGO_PKG_VERSION"));
    println!("sequoia-openpgp {}", sequoia_openpgp::VERSION);
    println!("Copyright (C) 2021 p≡p foundation");
    println!("License GNU GPL-3.0-or-later \
              <https://gnu.org/licenses/gpl.html>");
    println!("This is free software: \
              you are free to change and redistribute it.");
    println!("There is NO WARRANTY, \
              to the extent permitted by law.");
}

/// Displays help.
pub fn help() {
    version();
    println!();
    println!("Syntax: gpg [options] [files]");
    println!("There is no default operation");
    println!();

    for o in OPTIONS {
        if o.description == "@" {
            // Hidden from the help.
            continue;
        }

        if o.description.starts_with("@") {
            // Caption.
            println!("{}", &o.description[1..]);
        } else {
            let (meta, description) =
                if o.description.starts_with("|") {
                    let mut f = o.description.split('|');
                    f.next();
                    (Some(f.next().unwrap()), f.next().unwrap())
                } else {
                    (None, o.description)
                };

            if o.long_opt.is_empty() {
                let short_opt = if let Some(m) = meta {
                    format!("{} {}", o.short_opt as isize as u8 as char, m)
                } else {
                    format!("{}", o.short_opt as isize as u8 as char)
                };

                println!(" -{:<26} {}",
                         short_opt,
                         description);
            } else {
                let long_opt = if let Some(m) = meta {
                    format!("{} {}", o.long_opt, m)
                } else {
                    o.long_opt.to_string()
                };

                if o.short_opt as isize <= 0x7f {
                    println!(" -{}, --{:<21} {}",
                             o.short_opt as isize as u8 as char,
                             long_opt,
                             description);
                } else {
                    println!("     --{:<21} {}",
                             long_opt,
                             description);
                }
            }
        }
    }

    println!("Please report bugs to \
              <https://gitlab.com/sequoia-pgp/sequoia-chameleon-gnupg>");
}

/// Displays a message about warranty, or the lack there of.
pub fn warranty() {
    println!("\
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.");
}

/// Displays all options.
pub fn dump_options() {
    for o in OPTIONS {
        if ! o.long_opt.is_empty() {
            println!("--{}", o.long_opt);
        }
    }
}

/// Displays all options in tabular form.
pub fn dump_options_table() {
    for o in OPTIONS {
        if ! o.long_opt.is_empty() {
            println!("{}:{}:{}:{}:",
                     o.long_opt, o.short_opt as isize, o.flags, o.description);
        }
    }
}

/// Errors during argument parsing.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Malformed argument {:?}", _0)]
    Malformed(String),
    #[error("Unknown argument {:?}", _0)]
    Unkown(String),
    #[error("Ambiguous argument: {:?} matches {}", _0, _1)]
    Ambiguous(String, String),
    #[error("Missing parameter for {:?}", _0)]
    Missing(String),
    #[error("Parameter for {:?} is not a {}: {}", _0, _1, _2)]
    BadValue(String, &'static str, String),
}

/// Result specialization.
pub type Result<T> = std::result::Result<T, Error>;
