/// Error codes defined in libgpg-error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Error {
    /// Success.
    GPG_ERR_NO_ERROR = 0,
    /// General error.
    GPG_ERR_GENERAL = 1,
    /// Unknown packet.
    GPG_ERR_UNKNOWN_PACKET = 2,
    /// Unknown version in packet.
    GPG_ERR_UNKNOWN_VERSION = 3,
    /// Invalid public key algorithm.
    GPG_ERR_PUBKEY_ALGO = 4,
    /// Invalid digest algorithm.
    GPG_ERR_DIGEST_ALGO = 5,
    /// Bad public key.
    GPG_ERR_BAD_PUBKEY = 6,
    /// Bad secret key.
    GPG_ERR_BAD_SECKEY = 7,
    /// Bad signature.
    GPG_ERR_BAD_SIGNATURE = 8,
    /// No public key.
    GPG_ERR_NO_PUBKEY = 9,
    /// Checksum error.
    GPG_ERR_CHECKSUM = 10,
    /// Bad passphrase.
    GPG_ERR_BAD_PASSPHRASE = 11,
    /// Invalid cipher algorithm.
    GPG_ERR_CIPHER_ALGO = 12,
    /// Cannot open keyring.
    GPG_ERR_KEYRING_OPEN = 13,
    /// Invalid packet.
    GPG_ERR_INV_PACKET = 14,
    /// Invalid armor.
    GPG_ERR_INV_ARMOR = 15,
    /// No user ID.
    GPG_ERR_NO_USER_ID = 16,
    /// No secret key.
    GPG_ERR_NO_SECKEY = 17,
    /// Wrong secret key used.
    GPG_ERR_WRONG_SECKEY = 18,
    /// Bad session key.
    GPG_ERR_BAD_KEY = 19,
    /// Unknown compression algorithm.
    GPG_ERR_COMPR_ALGO = 20,
    /// Number is not prime.
    GPG_ERR_NO_PRIME = 21,
    /// Invalid encoding method.
    GPG_ERR_NO_ENCODING_METHOD = 22,
    /// Invalid encryption scheme.
    GPG_ERR_NO_ENCRYPTION_SCHEME = 23,
    /// Invalid signature scheme.
    GPG_ERR_NO_SIGNATURE_SCHEME = 24,
    /// Invalid attribute.
    GPG_ERR_INV_ATTR = 25,
    /// No value.
    GPG_ERR_NO_VALUE = 26,
    /// Not found.
    GPG_ERR_NOT_FOUND = 27,
    /// Value not found.
    GPG_ERR_VALUE_NOT_FOUND = 28,
    /// Syntax error.
    GPG_ERR_SYNTAX = 29,
    /// Bad MPI value.
    GPG_ERR_BAD_MPI = 30,
    /// Invalid passphrase.
    GPG_ERR_INV_PASSPHRASE = 31,
    /// Invalid signature class.
    GPG_ERR_SIG_CLASS = 32,
    /// Resources exhausted.
    GPG_ERR_RESOURCE_LIMIT = 33,
    /// Invalid keyring.
    GPG_ERR_INV_KEYRING = 34,
    /// Trust DB error.
    GPG_ERR_TRUSTDB = 35,
    /// Bad certificate.
    GPG_ERR_BAD_CERT = 36,
    /// Invalid user ID.
    GPG_ERR_INV_USER_ID = 37,
    /// Unexpected error.
    GPG_ERR_UNEXPECTED = 38,
    /// Time conflict.
    GPG_ERR_TIME_CONFLICT = 39,
    /// Keyserver error.
    GPG_ERR_KEYSERVER = 40,
    /// Wrong public key algorithm.
    GPG_ERR_WRONG_PUBKEY_ALGO = 41,
    /// Tribute to D. A..
    GPG_ERR_TRIBUTE_TO_D_A = 42,
    /// Weak encryption key.
    GPG_ERR_WEAK_KEY = 43,
    /// Invalid key length.
    GPG_ERR_INV_KEYLEN = 44,
    /// Invalid argument.
    GPG_ERR_INV_ARG = 45,
    /// Syntax error in URI.
    GPG_ERR_BAD_URI = 46,
    /// Invalid URI.
    GPG_ERR_INV_URI = 47,
    /// Network error.
    GPG_ERR_NETWORK = 48,
    /// Unknown host.
    GPG_ERR_UNKNOWN_HOST = 49,
    /// Selftest failed.
    GPG_ERR_SELFTEST_FAILED = 50,
    /// Data not encrypted.
    GPG_ERR_NOT_ENCRYPTED = 51,
    /// Data not processed.
    GPG_ERR_NOT_PROCESSED = 52,
    /// Unusable public key.
    GPG_ERR_UNUSABLE_PUBKEY = 53,
    /// Unusable secret key.
    GPG_ERR_UNUSABLE_SECKEY = 54,
    /// Invalid value.
    GPG_ERR_INV_VALUE = 55,
    /// Bad certificate chain.
    GPG_ERR_BAD_CERT_CHAIN = 56,
    /// Missing certificate.
    GPG_ERR_MISSING_CERT = 57,
    /// No data.
    GPG_ERR_NO_DATA = 58,
    /// Bug.
    GPG_ERR_BUG = 59,
    /// Not supported.
    GPG_ERR_NOT_SUPPORTED = 60,
    /// Invalid operation code.
    GPG_ERR_INV_OP = 61,
    /// Timeout.
    GPG_ERR_TIMEOUT = 62,
    /// Internal error.
    GPG_ERR_INTERNAL = 63,
    /// EOF (gcrypt).
    GPG_ERR_EOF_GCRYPT = 64,
    /// Invalid object.
    GPG_ERR_INV_OBJ = 65,
    /// Provided object is too short.
    GPG_ERR_TOO_SHORT = 66,
    /// Provided object is too large.
    GPG_ERR_TOO_LARGE = 67,
    /// Missing item in object.
    GPG_ERR_NO_OBJ = 68,
    /// Not implemented.
    GPG_ERR_NOT_IMPLEMENTED = 69,
    /// Conflicting use.
    GPG_ERR_CONFLICT = 70,
    /// Invalid cipher mode.
    GPG_ERR_INV_CIPHER_MODE = 71,
    /// Invalid flag.
    GPG_ERR_INV_FLAG = 72,
    /// Invalid handle.
    GPG_ERR_INV_HANDLE = 73,
    /// Result truncated.
    GPG_ERR_TRUNCATED = 74,
    /// Incomplete line.
    GPG_ERR_INCOMPLETE_LINE = 75,
    /// Invalid response.
    GPG_ERR_INV_RESPONSE = 76,
    /// No agent running.
    GPG_ERR_NO_AGENT = 77,
    /// Agent error.
    GPG_ERR_AGENT = 78,
    /// Invalid data.
    GPG_ERR_INV_DATA = 79,
    /// Unspecific Assuan server fault.
    GPG_ERR_ASSUAN_SERVER_FAULT = 80,
    /// General Assuan error.
    GPG_ERR_ASSUAN = 81,
    /// Invalid session key.
    GPG_ERR_INV_SESSION_KEY = 82,
    /// Invalid S-expression.
    GPG_ERR_INV_SEXP = 83,
    /// Unsupported algorithm.
    GPG_ERR_UNSUPPORTED_ALGORITHM = 84,
    /// No pinentry.
    GPG_ERR_NO_PIN_ENTRY = 85,
    /// Bad PIN.
    GPG_ERR_BAD_PIN = 87,
    /// Invalid name.
    GPG_ERR_INV_NAME = 88,
    /// Bad data.
    GPG_ERR_BAD_DATA = 89,
    /// Invalid parameter.
    GPG_ERR_INV_PARAMETER = 90,
    /// Wrong card.
    GPG_ERR_WRONG_CARD = 91,
    /// No dirmngr.
    GPG_ERR_NO_DIRMNGR = 92,
    /// Certificate revoked.
    GPG_ERR_CERT_REVOKED = 94,
    /// No CRL known.
    GPG_ERR_NO_CRL_KNOWN = 95,
    /// CRL too old.
    GPG_ERR_CRL_TOO_OLD = 96,
    /// Line too long.
    GPG_ERR_LINE_TOO_LONG = 97,
    /// Not trusted.
    GPG_ERR_NOT_TRUSTED = 98,
    /// Operation cancelled.
    GPG_ERR_CANCELED = 99,
    /// Bad CA certificate.
    GPG_ERR_BAD_CA_CERT = 100,
    /// Certificate expired.
    GPG_ERR_CERT_EXPIRED = 101,
    /// Certificate too young.
    GPG_ERR_CERT_TOO_YOUNG = 102,
    /// Unsupported certificate.
    GPG_ERR_UNSUPPORTED_CERT = 103,
    /// Unknown S-expression.
    GPG_ERR_UNKNOWN_SEXP = 104,
    /// Unsupported protection.
    GPG_ERR_UNSUPPORTED_PROTECTION = 105,
    /// Corrupted protection.
    GPG_ERR_CORRUPTED_PROTECTION = 106,
    /// Ambiguous name.
    GPG_ERR_AMBIGUOUS_NAME = 107,
    /// Card error.
    GPG_ERR_CARD = 108,
    /// Card reset required.
    GPG_ERR_CARD_RESET = 109,
    /// Card removed.
    GPG_ERR_CARD_REMOVED = 110,
    /// Invalid card.
    GPG_ERR_INV_CARD = 111,
    /// Card not present.
    GPG_ERR_CARD_NOT_PRESENT = 112,
    /// No PKCS15 application.
    GPG_ERR_NO_PKCS15_APP = 113,
    /// Not confirmed.
    GPG_ERR_NOT_CONFIRMED = 114,
    /// Configuration error.
    GPG_ERR_CONFIGURATION = 115,
    /// No policy match.
    GPG_ERR_NO_POLICY_MATCH = 116,
    /// Invalid index.
    GPG_ERR_INV_INDEX = 117,
    /// Invalid ID.
    GPG_ERR_INV_ID = 118,
    /// No SmartCard daemon.
    GPG_ERR_NO_SCDAEMON = 119,
    /// SmartCard daemon error.
    GPG_ERR_SCDAEMON = 120,
    /// Unsupported protocol.
    GPG_ERR_UNSUPPORTED_PROTOCOL = 121,
    /// Bad PIN method.
    GPG_ERR_BAD_PIN_METHOD = 122,
    /// Card not initialized.
    GPG_ERR_CARD_NOT_INITIALIZED = 123,
    /// Unsupported operation.
    GPG_ERR_UNSUPPORTED_OPERATION = 124,
    /// Wrong key usage.
    GPG_ERR_WRONG_KEY_USAGE = 125,
    /// Nothing found.
    GPG_ERR_NOTHING_FOUND = 126,
    /// Wrong blob type.
    GPG_ERR_WRONG_BLOB_TYPE = 127,
    /// Missing value.
    GPG_ERR_MISSING_VALUE = 128,
    /// Hardware problem.
    GPG_ERR_HARDWARE = 129,
    /// PIN blocked.
    GPG_ERR_PIN_BLOCKED = 130,
    /// Conditions of use not satisfied.
    GPG_ERR_USE_CONDITIONS = 131,
    /// PINs are not synced.
    GPG_ERR_PIN_NOT_SYNCED = 132,
    /// Invalid CRL.
    GPG_ERR_INV_CRL = 133,
    /// BER error.
    GPG_ERR_BAD_BER = 134,
    /// Invalid BER.
    GPG_ERR_INV_BER = 135,
    /// Element not found.
    GPG_ERR_ELEMENT_NOT_FOUND = 136,
    /// Identifier not found.
    GPG_ERR_IDENTIFIER_NOT_FOUND = 137,
    /// Invalid tag.
    GPG_ERR_INV_TAG = 138,
    /// Invalid length.
    GPG_ERR_INV_LENGTH = 139,
    /// Invalid key info.
    GPG_ERR_INV_KEYINFO = 140,
    /// Unexpected tag.
    GPG_ERR_UNEXPECTED_TAG = 141,
    /// Not DER encoded.
    GPG_ERR_NOT_DER_ENCODED = 142,
    /// No CMS object.
    GPG_ERR_NO_CMS_OBJ = 143,
    /// Invalid CMS object.
    GPG_ERR_INV_CMS_OBJ = 144,
    /// Unknown CMS object.
    GPG_ERR_UNKNOWN_CMS_OBJ = 145,
    /// Unsupported CMS object.
    GPG_ERR_UNSUPPORTED_CMS_OBJ = 146,
    /// Unsupported encoding.
    GPG_ERR_UNSUPPORTED_ENCODING = 147,
    /// Unsupported CMS version.
    GPG_ERR_UNSUPPORTED_CMS_VERSION = 148,
    /// Unknown algorithm.
    GPG_ERR_UNKNOWN_ALGORITHM = 149,
    /// Invalid crypto engine.
    GPG_ERR_INV_ENGINE = 150,
    /// Public key not trusted.
    GPG_ERR_PUBKEY_NOT_TRUSTED = 151,
    /// Decryption failed.
    GPG_ERR_DECRYPT_FAILED = 152,
    /// Key expired.
    GPG_ERR_KEY_EXPIRED = 153,
    /// Signature expired.
    GPG_ERR_SIG_EXPIRED = 154,
    /// Encoding problem.
    GPG_ERR_ENCODING_PROBLEM = 155,
    /// Invalid state.
    GPG_ERR_INV_STATE = 156,
    /// Duplicated value.
    GPG_ERR_DUP_VALUE = 157,
    /// Missing action.
    GPG_ERR_MISSING_ACTION = 158,
    /// ASN.1 module not found.
    GPG_ERR_MODULE_NOT_FOUND = 159,
    /// Invalid OID string.
    GPG_ERR_INV_OID_STRING = 160,
    /// Invalid time.
    GPG_ERR_INV_TIME = 161,
    /// Invalid CRL object.
    GPG_ERR_INV_CRL_OBJ = 162,
    /// Unsupported CRL version.
    GPG_ERR_UNSUPPORTED_CRL_VERSION = 163,
    /// Invalid certificate object.
    GPG_ERR_INV_CERT_OBJ = 164,
    /// Unknown name.
    GPG_ERR_UNKNOWN_NAME = 165,
    /// A locale function failed.
    GPG_ERR_LOCALE_PROBLEM = 166,
    /// Not locked.
    GPG_ERR_NOT_LOCKED = 167,
    /// Protocol violation.
    GPG_ERR_PROTOCOL_VIOLATION = 168,
    /// Invalid MAC.
    GPG_ERR_INV_MAC = 169,
    /// Invalid request.
    GPG_ERR_INV_REQUEST = 170,
    /// Unknown extension.
    GPG_ERR_UNKNOWN_EXTN = 171,
    /// Unknown critical extension.
    GPG_ERR_UNKNOWN_CRIT_EXTN = 172,
    /// Locked.
    GPG_ERR_LOCKED = 173,
    /// Unknown option.
    GPG_ERR_UNKNOWN_OPTION = 174,
    /// Unknown command.
    GPG_ERR_UNKNOWN_COMMAND = 175,
    /// Not operational.
    GPG_ERR_NOT_OPERATIONAL = 176,
    /// No passphrase given.
    GPG_ERR_NO_PASSPHRASE = 177,
    /// No PIN given.
    GPG_ERR_NO_PIN = 178,
    /// Not enabled.
    GPG_ERR_NOT_ENABLED = 179,
    /// No crypto engine.
    GPG_ERR_NO_ENGINE = 180,
    /// Missing key.
    GPG_ERR_MISSING_KEY = 181,
    /// Too many objects.
    GPG_ERR_TOO_MANY = 182,
    /// Limit reached.
    GPG_ERR_LIMIT_REACHED = 183,
    /// Not initialized.
    GPG_ERR_NOT_INITIALIZED = 184,
    /// Missing issuer certificate.
    GPG_ERR_MISSING_ISSUER_CERT = 185,
    /// No keyserver available.
    GPG_ERR_NO_KEYSERVER = 186,
    /// Invalid elliptic curve.
    GPG_ERR_INV_CURVE = 187,
    /// Unknown elliptic curve.
    GPG_ERR_UNKNOWN_CURVE = 188,
    /// Duplicated key.
    GPG_ERR_DUP_KEY = 189,
    /// Ambiguous result.
    GPG_ERR_AMBIGUOUS = 190,
    /// No crypto context.
    GPG_ERR_NO_CRYPT_CTX = 191,
    /// Wrong crypto context.
    GPG_ERR_WRONG_CRYPT_CTX = 192,
    /// Bad crypto context.
    GPG_ERR_BAD_CRYPT_CTX = 193,
    /// Conflict in the crypto context.
    GPG_ERR_CRYPT_CTX_CONFLICT = 194,
    /// Broken public key.
    GPG_ERR_BROKEN_PUBKEY = 195,
    /// Broken secret key.
    GPG_ERR_BROKEN_SECKEY = 196,
    /// Invalid MAC algorithm.
    GPG_ERR_MAC_ALGO = 197,
    /// Operation fully cancelled.
    GPG_ERR_FULLY_CANCELED = 198,
    /// Operation not yet finished.
    GPG_ERR_UNFINISHED = 199,
    /// Buffer too short.
    GPG_ERR_BUFFER_TOO_SHORT = 200,
    /// Invalid length specifier in S-expression.
    GPG_ERR_SEXP_INV_LEN_SPEC = 201,
    /// String too long in S-expression.
    GPG_ERR_SEXP_STRING_TOO_LONG = 202,
    /// Unmatched parentheses in S-expression.
    GPG_ERR_SEXP_UNMATCHED_PAREN = 203,
    /// S-expression not canonical.
    GPG_ERR_SEXP_NOT_CANONICAL = 204,
    /// Bad character in S-expression.
    GPG_ERR_SEXP_BAD_CHARACTER = 205,
    /// Bad quotation in S-expression.
    GPG_ERR_SEXP_BAD_QUOTATION = 206,
    /// Zero prefix in S-expression.
    GPG_ERR_SEXP_ZERO_PREFIX = 207,
    /// Nested display hints in S-expression.
    GPG_ERR_SEXP_NESTED_DH = 208,
    /// Unmatched display hints.
    GPG_ERR_SEXP_UNMATCHED_DH = 209,
    /// Unexpected reserved punctuation in S-expression.
    GPG_ERR_SEXP_UNEXPECTED_PUNC = 210,
    /// Bad hexadecimal character in S-expression.
    GPG_ERR_SEXP_BAD_HEX_CHAR = 211,
    /// Odd hexadecimal numbers in S-expression.
    GPG_ERR_SEXP_ODD_HEX_NUMBERS = 212,
    /// Bad octal character in S-expression.
    GPG_ERR_SEXP_BAD_OCT_CHAR = 213,
    /// All subkeys are expired or revoked.
    GPG_ERR_SUBKEYS_EXP_OR_REV = 217,
    /// Database is corrupted.
    GPG_ERR_DB_CORRUPTED = 218,
    /// Server indicated a failure.
    GPG_ERR_SERVER_FAILED = 219,
    /// No name.
    GPG_ERR_NO_NAME = 220,
    /// No key.
    GPG_ERR_NO_KEY = 221,
    /// Legacy key.
    GPG_ERR_LEGACY_KEY = 222,
    /// Request too short.
    GPG_ERR_REQUEST_TOO_SHORT = 223,
    /// Request too long.
    GPG_ERR_REQUEST_TOO_LONG = 224,
    /// Object is in termination state.
    GPG_ERR_OBJ_TERM_STATE = 225,
    /// No certificate chain.
    GPG_ERR_NO_CERT_CHAIN = 226,
    /// Certificate is too large.
    GPG_ERR_CERT_TOO_LARGE = 227,
    /// Invalid record.
    GPG_ERR_INV_RECORD = 228,
    /// The MAC does not verify.
    GPG_ERR_BAD_MAC = 229,
    /// Unexpected message.
    GPG_ERR_UNEXPECTED_MSG = 230,
    /// Compression or decompression failed.
    GPG_ERR_COMPR_FAILED = 231,
    /// A counter would wrap.
    GPG_ERR_WOULD_WRAP = 232,
    /// Fatal alert message received.
    GPG_ERR_FATAL_ALERT = 233,
    /// No cipher algorithm.
    GPG_ERR_NO_CIPHER = 234,
    /// Missing client certificate.
    GPG_ERR_MISSING_CLIENT_CERT = 235,
    /// Close notification received.
    GPG_ERR_CLOSE_NOTIFY = 236,
    /// Ticket expired.
    GPG_ERR_TICKET_EXPIRED = 237,
    /// Bad ticket.
    GPG_ERR_BAD_TICKET = 238,
    /// Unknown identity.
    GPG_ERR_UNKNOWN_IDENTITY = 239,
    /// Bad certificate message in handshake.
    GPG_ERR_BAD_HS_CERT = 240,
    /// Bad certificate request message in handshake.
    GPG_ERR_BAD_HS_CERT_REQ = 241,
    /// Bad certificate verify message in handshake.
    GPG_ERR_BAD_HS_CERT_VER = 242,
    /// Bad change cipher message in handshake.
    GPG_ERR_BAD_HS_CHANGE_CIPHER = 243,
    /// Bad client hello message in handshake.
    GPG_ERR_BAD_HS_CLIENT_HELLO = 244,
    /// Bad server hello message in handshake.
    GPG_ERR_BAD_HS_SERVER_HELLO = 245,
    /// Bad server hello done message in handshake.
    GPG_ERR_BAD_HS_SERVER_HELLO_DONE = 246,
    /// Bad finished message in handshake.
    GPG_ERR_BAD_HS_FINISHED = 247,
    /// Bad server key exchange message in handshake.
    GPG_ERR_BAD_HS_SERVER_KEX = 248,
    /// Bad client key exchange message in handshake.
    GPG_ERR_BAD_HS_CLIENT_KEX = 249,
    /// Bogus string.
    GPG_ERR_BOGUS_STRING = 250,
    /// Forbidden.
    GPG_ERR_FORBIDDEN = 251,
    /// Key disabled.
    GPG_ERR_KEY_DISABLED = 252,
    /// Not possible with a card based key.
    GPG_ERR_KEY_ON_CARD = 253,
    /// Invalid lock object.
    GPG_ERR_INV_LOCK_OBJ = 254,
    /// True.
    GPG_ERR_TRUE = 255,
    /// False.
    GPG_ERR_FALSE = 256,
    /// General IPC error.
    GPG_ERR_ASS_GENERAL = 257,
    /// IPC accept call failed.
    GPG_ERR_ASS_ACCEPT_FAILED = 258,
    /// IPC connect call failed.
    GPG_ERR_ASS_CONNECT_FAILED = 259,
    /// Invalid IPC response.
    GPG_ERR_ASS_INV_RESPONSE = 260,
    /// Invalid value passed to IPC.
    GPG_ERR_ASS_INV_VALUE = 261,
    /// Incomplete line passed to IPC.
    GPG_ERR_ASS_INCOMPLETE_LINE = 262,
    /// Line passed to IPC too long.
    GPG_ERR_ASS_LINE_TOO_LONG = 263,
    /// Nested IPC commands.
    GPG_ERR_ASS_NESTED_COMMANDS = 264,
    /// No data callback in IPC.
    GPG_ERR_ASS_NO_DATA_CB = 265,
    /// No inquire callback in IPC.
    GPG_ERR_ASS_NO_INQUIRE_CB = 266,
    /// Not an IPC server.
    GPG_ERR_ASS_NOT_A_SERVER = 267,
    /// Not an IPC client.
    GPG_ERR_ASS_NOT_A_CLIENT = 268,
    /// Problem starting IPC server.
    GPG_ERR_ASS_SERVER_START = 269,
    /// IPC read error.
    GPG_ERR_ASS_READ_ERROR = 270,
    /// IPC write error.
    GPG_ERR_ASS_WRITE_ERROR = 271,
    /// Too much data for IPC layer.
    GPG_ERR_ASS_TOO_MUCH_DATA = 273,
    /// Unexpected IPC command.
    GPG_ERR_ASS_UNEXPECTED_CMD = 274,
    /// Unknown IPC command.
    GPG_ERR_ASS_UNKNOWN_CMD = 275,
    /// IPC syntax error.
    GPG_ERR_ASS_SYNTAX = 276,
    /// IPC call has been cancelled.
    GPG_ERR_ASS_CANCELED = 277,
    /// No input source for IPC.
    GPG_ERR_ASS_NO_INPUT = 278,
    /// No output source for IPC.
    GPG_ERR_ASS_NO_OUTPUT = 279,
    /// IPC parameter error.
    GPG_ERR_ASS_PARAMETER = 280,
    /// Unknown IPC inquire.
    GPG_ERR_ASS_UNKNOWN_INQUIRE = 281,
    /// Crypto engine too old.
    GPG_ERR_ENGINE_TOO_OLD = 300,
    /// Screen or window too small.
    GPG_ERR_WINDOW_TOO_SMALL = 301,
    /// Screen or window too large.
    GPG_ERR_WINDOW_TOO_LARGE = 302,
    /// Required environment variable not set.
    GPG_ERR_MISSING_ENVVAR = 303,
    /// User ID already exists.
    GPG_ERR_USER_ID_EXISTS = 304,
    /// Name already exists.
    GPG_ERR_NAME_EXISTS = 305,
    /// Duplicated name.
    GPG_ERR_DUP_NAME = 306,
    /// Object is too young.
    GPG_ERR_TOO_YOUNG = 307,
    /// Object is too old.
    GPG_ERR_TOO_OLD = 308,
    /// Unknown flag.
    GPG_ERR_UNKNOWN_FLAG = 309,
    /// Invalid execution order.
    GPG_ERR_INV_ORDER = 310,
    /// Already fetched.
    GPG_ERR_ALREADY_FETCHED = 311,
    /// Try again later.
    GPG_ERR_TRY_LATER = 312,
    /// Wrong name.
    GPG_ERR_WRONG_NAME = 313,
    /// Not authenticated.
    GPG_ERR_NO_AUTH = 314,
    /// Bad authentication.
    GPG_ERR_BAD_AUTH = 315,
    /// No Keybox daemon running.
    GPG_ERR_NO_KEYBOXD = 316,
    /// Keybox daemon error.
    GPG_ERR_KEYBOXD = 317,
    /// Service is not running.
    GPG_ERR_NO_SERVICE = 318,
    /// Service error.
    GPG_ERR_SERVICE = 319,
    /// System bug detected.
    GPG_ERR_SYSTEM_BUG = 666,
    /// Unknown DNS error.
    GPG_ERR_DNS_UNKNOWN = 711,
    /// Invalid DNS section.
    GPG_ERR_DNS_SECTION = 712,
    /// Invalid textual address form.
    GPG_ERR_DNS_ADDRESS = 713,
    /// Missing DNS query packet.
    GPG_ERR_DNS_NO_QUERY = 714,
    /// Missing DNS answer packet.
    GPG_ERR_DNS_NO_ANSWER = 715,
    /// Connection closed in DNS.
    GPG_ERR_DNS_CLOSED = 716,
    /// Verification failed in DNS.
    GPG_ERR_DNS_VERIFY = 717,
    /// DNS Timeout.
    GPG_ERR_DNS_TIMEOUT = 718,
    /// General LDAP error.
    GPG_ERR_LDAP_GENERAL = 721,
    /// General LDAP attribute error.
    GPG_ERR_LDAP_ATTR_GENERAL = 722,
    /// General LDAP name error.
    GPG_ERR_LDAP_NAME_GENERAL = 723,
    /// General LDAP security error.
    GPG_ERR_LDAP_SECURITY_GENERAL = 724,
    /// General LDAP service error.
    GPG_ERR_LDAP_SERVICE_GENERAL = 725,
    /// General LDAP update error.
    GPG_ERR_LDAP_UPDATE_GENERAL = 726,
    /// Experimental LDAP error code.
    GPG_ERR_LDAP_E_GENERAL = 727,
    /// Private LDAP error code.
    GPG_ERR_LDAP_X_GENERAL = 728,
    /// Other general LDAP error.
    GPG_ERR_LDAP_OTHER_GENERAL = 729,
    /// LDAP connecting failed (X).
    GPG_ERR_LDAP_X_CONNECTING = 750,
    /// LDAP referral limit exceeded.
    GPG_ERR_LDAP_REFERRAL_LIMIT = 751,
    /// LDAP client loop.
    GPG_ERR_LDAP_CLIENT_LOOP = 752,
    /// No LDAP results returned.
    GPG_ERR_LDAP_NO_RESULTS = 754,
    /// LDAP control not found.
    GPG_ERR_LDAP_CONTROL_NOT_FOUND = 755,
    /// Not supported by LDAP.
    GPG_ERR_LDAP_NOT_SUPPORTED = 756,
    /// LDAP connect error.
    GPG_ERR_LDAP_CONNECT = 757,
    /// Out of memory in LDAP.
    GPG_ERR_LDAP_NO_MEMORY = 758,
    /// Bad parameter to an LDAP routine.
    GPG_ERR_LDAP_PARAM = 759,
    /// User cancelled LDAP operation.
    GPG_ERR_LDAP_USER_CANCELLED = 760,
    /// Bad LDAP search filter.
    GPG_ERR_LDAP_FILTER = 761,
    /// Unknown LDAP authentication method.
    GPG_ERR_LDAP_AUTH_UNKNOWN = 762,
    /// Timeout in LDAP.
    GPG_ERR_LDAP_TIMEOUT = 763,
    /// LDAP decoding error.
    GPG_ERR_LDAP_DECODING = 764,
    /// LDAP encoding error.
    GPG_ERR_LDAP_ENCODING = 765,
    /// LDAP local error.
    GPG_ERR_LDAP_LOCAL = 766,
    /// Cannot contact LDAP server.
    GPG_ERR_LDAP_SERVER_DOWN = 767,
    /// LDAP success.
    GPG_ERR_LDAP_SUCCESS = 768,
    /// LDAP operations error.
    GPG_ERR_LDAP_OPERATIONS = 769,
    /// LDAP protocol error.
    GPG_ERR_LDAP_PROTOCOL = 770,
    /// Time limit exceeded in LDAP.
    GPG_ERR_LDAP_TIMELIMIT = 771,
    /// Size limit exceeded in LDAP.
    GPG_ERR_LDAP_SIZELIMIT = 772,
    /// LDAP compare false.
    GPG_ERR_LDAP_COMPARE_FALSE = 773,
    /// LDAP compare true.
    GPG_ERR_LDAP_COMPARE_TRUE = 774,
    /// LDAP authentication method not supported.
    GPG_ERR_LDAP_UNSUPPORTED_AUTH = 775,
    /// Strong(er) LDAP authentication required.
    GPG_ERR_LDAP_STRONG_AUTH_RQRD = 776,
    /// Partial LDAP results+referral received.
    GPG_ERR_LDAP_PARTIAL_RESULTS = 777,
    /// LDAP referral.
    GPG_ERR_LDAP_REFERRAL = 778,
    /// Administrative LDAP limit exceeded.
    GPG_ERR_LDAP_ADMINLIMIT = 779,
    /// Critical LDAP extension is unavailable.
    GPG_ERR_LDAP_UNAVAIL_CRIT_EXTN = 780,
    /// Confidentiality required by LDAP.
    GPG_ERR_LDAP_CONFIDENT_RQRD = 781,
    /// LDAP SASL bind in progress.
    GPG_ERR_LDAP_SASL_BIND_INPROG = 782,
    /// No such LDAP attribute.
    GPG_ERR_LDAP_NO_SUCH_ATTRIBUTE = 784,
    /// Undefined LDAP attribute type.
    GPG_ERR_LDAP_UNDEFINED_TYPE = 785,
    /// Inappropriate matching in LDAP.
    GPG_ERR_LDAP_BAD_MATCHING = 786,
    /// Constraint violation in LDAP.
    GPG_ERR_LDAP_CONST_VIOLATION = 787,
    /// LDAP type or value exists.
    GPG_ERR_LDAP_TYPE_VALUE_EXISTS = 788,
    /// Invalid syntax in LDAP.
    GPG_ERR_LDAP_INV_SYNTAX = 789,
    /// No such LDAP object.
    GPG_ERR_LDAP_NO_SUCH_OBJ = 800,
    /// LDAP alias problem.
    GPG_ERR_LDAP_ALIAS_PROBLEM = 801,
    /// Invalid DN syntax in LDAP.
    GPG_ERR_LDAP_INV_DN_SYNTAX = 802,
    /// LDAP entry is a leaf.
    GPG_ERR_LDAP_IS_LEAF = 803,
    /// LDAP alias dereferencing problem.
    GPG_ERR_LDAP_ALIAS_DEREF = 804,
    /// LDAP proxy authorization failure (X).
    GPG_ERR_LDAP_X_PROXY_AUTH_FAIL = 815,
    /// Inappropriate LDAP authentication.
    GPG_ERR_LDAP_BAD_AUTH = 816,
    /// Invalid LDAP credentials.
    GPG_ERR_LDAP_INV_CREDENTIALS = 817,
    /// Insufficient access for LDAP.
    GPG_ERR_LDAP_INSUFFICIENT_ACC = 818,
    /// LDAP server is busy.
    GPG_ERR_LDAP_BUSY = 819,
    /// LDAP server is unavailable.
    GPG_ERR_LDAP_UNAVAILABLE = 820,
    /// LDAP server is unwilling to perform.
    GPG_ERR_LDAP_UNWILL_TO_PERFORM = 821,
    /// Loop detected by LDAP.
    GPG_ERR_LDAP_LOOP_DETECT = 822,
    /// LDAP naming violation.
    GPG_ERR_LDAP_NAMING_VIOLATION = 832,
    /// LDAP object class violation.
    GPG_ERR_LDAP_OBJ_CLS_VIOLATION = 833,
    /// LDAP operation not allowed on non-leaf.
    GPG_ERR_LDAP_NOT_ALLOW_NONLEAF = 834,
    /// LDAP operation not allowed on RDN.
    GPG_ERR_LDAP_NOT_ALLOW_ON_RDN = 835,
    /// Already exists (LDAP).
    GPG_ERR_LDAP_ALREADY_EXISTS = 836,
    /// Cannot modify LDAP object class.
    GPG_ERR_LDAP_NO_OBJ_CLASS_MODS = 837,
    /// LDAP results too large.
    GPG_ERR_LDAP_RESULTS_TOO_LARGE = 838,
    /// LDAP operation affects multiple DSAs.
    GPG_ERR_LDAP_AFFECTS_MULT_DSAS = 839,
    /// Virtual LDAP list view error.
    GPG_ERR_LDAP_VLV = 844,
    /// Other LDAP error.
    GPG_ERR_LDAP_OTHER = 848,
    /// Resources exhausted in LCUP.
    GPG_ERR_LDAP_CUP_RESOURCE_LIMIT = 881,
    /// Security violation in LCUP.
    GPG_ERR_LDAP_CUP_SEC_VIOLATION = 882,
    /// Invalid data in LCUP.
    GPG_ERR_LDAP_CUP_INV_DATA = 883,
    /// Unsupported scheme in LCUP.
    GPG_ERR_LDAP_CUP_UNSUP_SCHEME = 884,
    /// Reload required in LCUP.
    GPG_ERR_LDAP_CUP_RELOAD = 885,
    /// LDAP cancelled.
    GPG_ERR_LDAP_CANCELLED = 886,
    /// No LDAP operation to cancel.
    GPG_ERR_LDAP_NO_SUCH_OPERATION = 887,
    /// Too late to cancel LDAP.
    GPG_ERR_LDAP_TOO_LATE = 888,
    /// Cannot cancel LDAP.
    GPG_ERR_LDAP_CANNOT_CANCEL = 889,
    /// LDAP assertion failed.
    GPG_ERR_LDAP_ASSERTION_FAILED = 890,
    /// Proxied authorization denied by LDAP.
    GPG_ERR_LDAP_PROX_AUTH_DENIED = 891,
    /// User defined error code 1.
    GPG_ERR_USER_1 = 1024,
    /// User defined error code 2.
    GPG_ERR_USER_2 = 1025,
    /// User defined error code 3.
    GPG_ERR_USER_3 = 1026,
    /// User defined error code 4.
    GPG_ERR_USER_4 = 1027,
    /// User defined error code 5.
    GPG_ERR_USER_5 = 1028,
    /// User defined error code 6.
    GPG_ERR_USER_6 = 1029,
    /// User defined error code 7.
    GPG_ERR_USER_7 = 1030,
    /// User defined error code 8.
    GPG_ERR_USER_8 = 1031,
    /// User defined error code 9.
    GPG_ERR_USER_9 = 1032,
    /// User defined error code 10.
    GPG_ERR_USER_10 = 1033,
    /// User defined error code 11.
    GPG_ERR_USER_11 = 1034,
    /// User defined error code 12.
    GPG_ERR_USER_12 = 1035,
    /// User defined error code 13.
    GPG_ERR_USER_13 = 1036,
    /// User defined error code 14.
    GPG_ERR_USER_14 = 1037,
    /// User defined error code 15.
    GPG_ERR_USER_15 = 1038,
    /// User defined error code 16.
    GPG_ERR_USER_16 = 1039,
    /// SQL success.
    GPG_ERR_SQL_OK = 1500,
    /// SQL error.
    GPG_ERR_SQL_ERROR = 1501,
    /// Internal logic error in SQL library.
    GPG_ERR_SQL_INTERNAL = 1502,
    /// Access permission denied (SQL).
    GPG_ERR_SQL_PERM = 1503,
    /// SQL abort was requested.
    GPG_ERR_SQL_ABORT = 1504,
    /// SQL database file is locked.
    GPG_ERR_SQL_BUSY = 1505,
    /// An SQL table in the database is locked.
    GPG_ERR_SQL_LOCKED = 1506,
    /// SQL library ran out of core.
    GPG_ERR_SQL_NOMEM = 1507,
    /// Attempt to write a readonly SQL database.
    GPG_ERR_SQL_READONLY = 1508,
    /// SQL operation terminated by interrupt.
    GPG_ERR_SQL_INTERRUPT = 1509,
    /// I/O error during SQL operation.
    GPG_ERR_SQL_IOERR = 1510,
    /// SQL database disk image is malformed.
    GPG_ERR_SQL_CORRUPT = 1511,
    /// Unknown opcode in SQL file control.
    GPG_ERR_SQL_NOTFOUND = 1512,
    /// Insertion failed because SQL database is full.
    GPG_ERR_SQL_FULL = 1513,
    /// Unable to open the SQL database file.
    GPG_ERR_SQL_CANTOPEN = 1514,
    /// SQL database lock protocol error.
    GPG_ERR_SQL_PROTOCOL = 1515,
    /// (internal SQL code: empty).
    GPG_ERR_SQL_EMPTY = 1516,
    /// SQL database schema changed.
    GPG_ERR_SQL_SCHEMA = 1517,
    /// String or blob exceeds size limit (SQL).
    GPG_ERR_SQL_TOOBIG = 1518,
    /// SQL abort due to constraint violation.
    GPG_ERR_SQL_CONSTRAINT = 1519,
    /// Data type mismatch (SQL).
    GPG_ERR_SQL_MISMATCH = 1520,
    /// SQL library used incorrectly.
    GPG_ERR_SQL_MISUSE = 1521,
    /// SQL library uses unsupported OS features.
    GPG_ERR_SQL_NOLFS = 1522,
    /// Authorization denied (SQL).
    GPG_ERR_SQL_AUTH = 1523,
    /// (unused SQL code: format).
    GPG_ERR_SQL_FORMAT = 1524,
    /// SQL bind parameter out of range.
    GPG_ERR_SQL_RANGE = 1525,
    /// File opened that is not an SQL database file.
    GPG_ERR_SQL_NOTADB = 1526,
    /// Notifications from SQL logger.
    GPG_ERR_SQL_NOTICE = 1527,
    /// Warnings from SQL logger.
    GPG_ERR_SQL_WARNING = 1528,
    /// SQL has another row ready.
    GPG_ERR_SQL_ROW = 1600,
    /// SQL has finished executing.
    GPG_ERR_SQL_DONE = 1601,
    /// System error w/o errno.
    GPG_ERR_MISSING_ERRNO = 16381,
    /// Unknown system error.
    GPG_ERR_UNKNOWN_ERRNO = 16382,
    /// End of file.
    GPG_ERR_EOF = 16383,
    /// Sometimes, GnuPG returns -1.
    GPG_ERR_MINUS_ONE = 4294967295,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            GPG_ERR_NO_ERROR => f.write_str("Success"),
            GPG_ERR_GENERAL => f.write_str("General error"),
            GPG_ERR_UNKNOWN_PACKET => f.write_str("Unknown packet"),
            GPG_ERR_UNKNOWN_VERSION => f.write_str("Unknown version in packet"),
            GPG_ERR_PUBKEY_ALGO => f.write_str("Invalid public key algorithm"),
            GPG_ERR_DIGEST_ALGO => f.write_str("Invalid digest algorithm"),
            GPG_ERR_BAD_PUBKEY => f.write_str("Bad public key"),
            GPG_ERR_BAD_SECKEY => f.write_str("Bad secret key"),
            GPG_ERR_BAD_SIGNATURE => f.write_str("Bad signature"),
            GPG_ERR_NO_PUBKEY => f.write_str("No public key"),
            GPG_ERR_CHECKSUM => f.write_str("Checksum error"),
            GPG_ERR_BAD_PASSPHRASE => f.write_str("Bad passphrase"),
            GPG_ERR_CIPHER_ALGO => f.write_str("Invalid cipher algorithm"),
            GPG_ERR_KEYRING_OPEN => f.write_str("Cannot open keyring"),
            GPG_ERR_INV_PACKET => f.write_str("Invalid packet"),
            GPG_ERR_INV_ARMOR => f.write_str("Invalid armor"),
            GPG_ERR_NO_USER_ID => f.write_str("No user ID"),
            GPG_ERR_NO_SECKEY => f.write_str("No secret key"),
            GPG_ERR_WRONG_SECKEY => f.write_str("Wrong secret key used"),
            GPG_ERR_BAD_KEY => f.write_str("Bad session key"),
            GPG_ERR_COMPR_ALGO => f.write_str("Unknown compression algorithm"),
            GPG_ERR_NO_PRIME => f.write_str("Number is not prime"),
            GPG_ERR_NO_ENCODING_METHOD => f.write_str("Invalid encoding method"),
            GPG_ERR_NO_ENCRYPTION_SCHEME => f.write_str("Invalid encryption scheme"),
            GPG_ERR_NO_SIGNATURE_SCHEME => f.write_str("Invalid signature scheme"),
            GPG_ERR_INV_ATTR => f.write_str("Invalid attribute"),
            GPG_ERR_NO_VALUE => f.write_str("No value"),
            GPG_ERR_NOT_FOUND => f.write_str("Not found"),
            GPG_ERR_VALUE_NOT_FOUND => f.write_str("Value not found"),
            GPG_ERR_SYNTAX => f.write_str("Syntax error"),
            GPG_ERR_BAD_MPI => f.write_str("Bad MPI value"),
            GPG_ERR_INV_PASSPHRASE => f.write_str("Invalid passphrase"),
            GPG_ERR_SIG_CLASS => f.write_str("Invalid signature class"),
            GPG_ERR_RESOURCE_LIMIT => f.write_str("Resources exhausted"),
            GPG_ERR_INV_KEYRING => f.write_str("Invalid keyring"),
            GPG_ERR_TRUSTDB => f.write_str("Trust DB error"),
            GPG_ERR_BAD_CERT => f.write_str("Bad certificate"),
            GPG_ERR_INV_USER_ID => f.write_str("Invalid user ID"),
            GPG_ERR_UNEXPECTED => f.write_str("Unexpected error"),
            GPG_ERR_TIME_CONFLICT => f.write_str("Time conflict"),
            GPG_ERR_KEYSERVER => f.write_str("Keyserver error"),
            GPG_ERR_WRONG_PUBKEY_ALGO => f.write_str("Wrong public key algorithm"),
            GPG_ERR_TRIBUTE_TO_D_A => f.write_str("Tribute to D. A."),
            GPG_ERR_WEAK_KEY => f.write_str("Weak encryption key"),
            GPG_ERR_INV_KEYLEN => f.write_str("Invalid key length"),
            GPG_ERR_INV_ARG => f.write_str("Invalid argument"),
            GPG_ERR_BAD_URI => f.write_str("Syntax error in URI"),
            GPG_ERR_INV_URI => f.write_str("Invalid URI"),
            GPG_ERR_NETWORK => f.write_str("Network error"),
            GPG_ERR_UNKNOWN_HOST => f.write_str("Unknown host"),
            GPG_ERR_SELFTEST_FAILED => f.write_str("Selftest failed"),
            GPG_ERR_NOT_ENCRYPTED => f.write_str("Data not encrypted"),
            GPG_ERR_NOT_PROCESSED => f.write_str("Data not processed"),
            GPG_ERR_UNUSABLE_PUBKEY => f.write_str("Unusable public key"),
            GPG_ERR_UNUSABLE_SECKEY => f.write_str("Unusable secret key"),
            GPG_ERR_INV_VALUE => f.write_str("Invalid value"),
            GPG_ERR_BAD_CERT_CHAIN => f.write_str("Bad certificate chain"),
            GPG_ERR_MISSING_CERT => f.write_str("Missing certificate"),
            GPG_ERR_NO_DATA => f.write_str("No data"),
            GPG_ERR_BUG => f.write_str("Bug"),
            GPG_ERR_NOT_SUPPORTED => f.write_str("Not supported"),
            GPG_ERR_INV_OP => f.write_str("Invalid operation code"),
            GPG_ERR_TIMEOUT => f.write_str("Timeout"),
            GPG_ERR_INTERNAL => f.write_str("Internal error"),
            GPG_ERR_EOF_GCRYPT => f.write_str("EOF (gcrypt)"),
            GPG_ERR_INV_OBJ => f.write_str("Invalid object"),
            GPG_ERR_TOO_SHORT => f.write_str("Provided object is too short"),
            GPG_ERR_TOO_LARGE => f.write_str("Provided object is too large"),
            GPG_ERR_NO_OBJ => f.write_str("Missing item in object"),
            GPG_ERR_NOT_IMPLEMENTED => f.write_str("Not implemented"),
            GPG_ERR_CONFLICT => f.write_str("Conflicting use"),
            GPG_ERR_INV_CIPHER_MODE => f.write_str("Invalid cipher mode"),
            GPG_ERR_INV_FLAG => f.write_str("Invalid flag"),
            GPG_ERR_INV_HANDLE => f.write_str("Invalid handle"),
            GPG_ERR_TRUNCATED => f.write_str("Result truncated"),
            GPG_ERR_INCOMPLETE_LINE => f.write_str("Incomplete line"),
            GPG_ERR_INV_RESPONSE => f.write_str("Invalid response"),
            GPG_ERR_NO_AGENT => f.write_str("No agent running"),
            GPG_ERR_AGENT => f.write_str("Agent error"),
            GPG_ERR_INV_DATA => f.write_str("Invalid data"),
            GPG_ERR_ASSUAN_SERVER_FAULT => f.write_str("Unspecific Assuan server fault"),
            GPG_ERR_ASSUAN => f.write_str("General Assuan error"),
            GPG_ERR_INV_SESSION_KEY => f.write_str("Invalid session key"),
            GPG_ERR_INV_SEXP => f.write_str("Invalid S-expression"),
            GPG_ERR_UNSUPPORTED_ALGORITHM => f.write_str("Unsupported algorithm"),
            GPG_ERR_NO_PIN_ENTRY => f.write_str("No pinentry"),
            GPG_ERR_BAD_PIN => f.write_str("Bad PIN"),
            GPG_ERR_INV_NAME => f.write_str("Invalid name"),
            GPG_ERR_BAD_DATA => f.write_str("Bad data"),
            GPG_ERR_INV_PARAMETER => f.write_str("Invalid parameter"),
            GPG_ERR_WRONG_CARD => f.write_str("Wrong card"),
            GPG_ERR_NO_DIRMNGR => f.write_str("No dirmngr"),
            GPG_ERR_CERT_REVOKED => f.write_str("Certificate revoked"),
            GPG_ERR_NO_CRL_KNOWN => f.write_str("No CRL known"),
            GPG_ERR_CRL_TOO_OLD => f.write_str("CRL too old"),
            GPG_ERR_LINE_TOO_LONG => f.write_str("Line too long"),
            GPG_ERR_NOT_TRUSTED => f.write_str("Not trusted"),
            GPG_ERR_CANCELED => f.write_str("Operation cancelled"),
            GPG_ERR_BAD_CA_CERT => f.write_str("Bad CA certificate"),
            GPG_ERR_CERT_EXPIRED => f.write_str("Certificate expired"),
            GPG_ERR_CERT_TOO_YOUNG => f.write_str("Certificate too young"),
            GPG_ERR_UNSUPPORTED_CERT => f.write_str("Unsupported certificate"),
            GPG_ERR_UNKNOWN_SEXP => f.write_str("Unknown S-expression"),
            GPG_ERR_UNSUPPORTED_PROTECTION => f.write_str("Unsupported protection"),
            GPG_ERR_CORRUPTED_PROTECTION => f.write_str("Corrupted protection"),
            GPG_ERR_AMBIGUOUS_NAME => f.write_str("Ambiguous name"),
            GPG_ERR_CARD => f.write_str("Card error"),
            GPG_ERR_CARD_RESET => f.write_str("Card reset required"),
            GPG_ERR_CARD_REMOVED => f.write_str("Card removed"),
            GPG_ERR_INV_CARD => f.write_str("Invalid card"),
            GPG_ERR_CARD_NOT_PRESENT => f.write_str("Card not present"),
            GPG_ERR_NO_PKCS15_APP => f.write_str("No PKCS15 application"),
            GPG_ERR_NOT_CONFIRMED => f.write_str("Not confirmed"),
            GPG_ERR_CONFIGURATION => f.write_str("Configuration error"),
            GPG_ERR_NO_POLICY_MATCH => f.write_str("No policy match"),
            GPG_ERR_INV_INDEX => f.write_str("Invalid index"),
            GPG_ERR_INV_ID => f.write_str("Invalid ID"),
            GPG_ERR_NO_SCDAEMON => f.write_str("No SmartCard daemon"),
            GPG_ERR_SCDAEMON => f.write_str("SmartCard daemon error"),
            GPG_ERR_UNSUPPORTED_PROTOCOL => f.write_str("Unsupported protocol"),
            GPG_ERR_BAD_PIN_METHOD => f.write_str("Bad PIN method"),
            GPG_ERR_CARD_NOT_INITIALIZED => f.write_str("Card not initialized"),
            GPG_ERR_UNSUPPORTED_OPERATION => f.write_str("Unsupported operation"),
            GPG_ERR_WRONG_KEY_USAGE => f.write_str("Wrong key usage"),
            GPG_ERR_NOTHING_FOUND => f.write_str("Nothing found"),
            GPG_ERR_WRONG_BLOB_TYPE => f.write_str("Wrong blob type"),
            GPG_ERR_MISSING_VALUE => f.write_str("Missing value"),
            GPG_ERR_HARDWARE => f.write_str("Hardware problem"),
            GPG_ERR_PIN_BLOCKED => f.write_str("PIN blocked"),
            GPG_ERR_USE_CONDITIONS => f.write_str("Conditions of use not satisfied"),
            GPG_ERR_PIN_NOT_SYNCED => f.write_str("PINs are not synced"),
            GPG_ERR_INV_CRL => f.write_str("Invalid CRL"),
            GPG_ERR_BAD_BER => f.write_str("BER error"),
            GPG_ERR_INV_BER => f.write_str("Invalid BER"),
            GPG_ERR_ELEMENT_NOT_FOUND => f.write_str("Element not found"),
            GPG_ERR_IDENTIFIER_NOT_FOUND => f.write_str("Identifier not found"),
            GPG_ERR_INV_TAG => f.write_str("Invalid tag"),
            GPG_ERR_INV_LENGTH => f.write_str("Invalid length"),
            GPG_ERR_INV_KEYINFO => f.write_str("Invalid key info"),
            GPG_ERR_UNEXPECTED_TAG => f.write_str("Unexpected tag"),
            GPG_ERR_NOT_DER_ENCODED => f.write_str("Not DER encoded"),
            GPG_ERR_NO_CMS_OBJ => f.write_str("No CMS object"),
            GPG_ERR_INV_CMS_OBJ => f.write_str("Invalid CMS object"),
            GPG_ERR_UNKNOWN_CMS_OBJ => f.write_str("Unknown CMS object"),
            GPG_ERR_UNSUPPORTED_CMS_OBJ => f.write_str("Unsupported CMS object"),
            GPG_ERR_UNSUPPORTED_ENCODING => f.write_str("Unsupported encoding"),
            GPG_ERR_UNSUPPORTED_CMS_VERSION => f.write_str("Unsupported CMS version"),
            GPG_ERR_UNKNOWN_ALGORITHM => f.write_str("Unknown algorithm"),
            GPG_ERR_INV_ENGINE => f.write_str("Invalid crypto engine"),
            GPG_ERR_PUBKEY_NOT_TRUSTED => f.write_str("Public key not trusted"),
            GPG_ERR_DECRYPT_FAILED => f.write_str("Decryption failed"),
            GPG_ERR_KEY_EXPIRED => f.write_str("Key expired"),
            GPG_ERR_SIG_EXPIRED => f.write_str("Signature expired"),
            GPG_ERR_ENCODING_PROBLEM => f.write_str("Encoding problem"),
            GPG_ERR_INV_STATE => f.write_str("Invalid state"),
            GPG_ERR_DUP_VALUE => f.write_str("Duplicated value"),
            GPG_ERR_MISSING_ACTION => f.write_str("Missing action"),
            GPG_ERR_MODULE_NOT_FOUND => f.write_str("ASN.1 module not found"),
            GPG_ERR_INV_OID_STRING => f.write_str("Invalid OID string"),
            GPG_ERR_INV_TIME => f.write_str("Invalid time"),
            GPG_ERR_INV_CRL_OBJ => f.write_str("Invalid CRL object"),
            GPG_ERR_UNSUPPORTED_CRL_VERSION => f.write_str("Unsupported CRL version"),
            GPG_ERR_INV_CERT_OBJ => f.write_str("Invalid certificate object"),
            GPG_ERR_UNKNOWN_NAME => f.write_str("Unknown name"),
            GPG_ERR_LOCALE_PROBLEM => f.write_str("A locale function failed"),
            GPG_ERR_NOT_LOCKED => f.write_str("Not locked"),
            GPG_ERR_PROTOCOL_VIOLATION => f.write_str("Protocol violation"),
            GPG_ERR_INV_MAC => f.write_str("Invalid MAC"),
            GPG_ERR_INV_REQUEST => f.write_str("Invalid request"),
            GPG_ERR_UNKNOWN_EXTN => f.write_str("Unknown extension"),
            GPG_ERR_UNKNOWN_CRIT_EXTN => f.write_str("Unknown critical extension"),
            GPG_ERR_LOCKED => f.write_str("Locked"),
            GPG_ERR_UNKNOWN_OPTION => f.write_str("Unknown option"),
            GPG_ERR_UNKNOWN_COMMAND => f.write_str("Unknown command"),
            GPG_ERR_NOT_OPERATIONAL => f.write_str("Not operational"),
            GPG_ERR_NO_PASSPHRASE => f.write_str("No passphrase given"),
            GPG_ERR_NO_PIN => f.write_str("No PIN given"),
            GPG_ERR_NOT_ENABLED => f.write_str("Not enabled"),
            GPG_ERR_NO_ENGINE => f.write_str("No crypto engine"),
            GPG_ERR_MISSING_KEY => f.write_str("Missing key"),
            GPG_ERR_TOO_MANY => f.write_str("Too many objects"),
            GPG_ERR_LIMIT_REACHED => f.write_str("Limit reached"),
            GPG_ERR_NOT_INITIALIZED => f.write_str("Not initialized"),
            GPG_ERR_MISSING_ISSUER_CERT => f.write_str("Missing issuer certificate"),
            GPG_ERR_NO_KEYSERVER => f.write_str("No keyserver available"),
            GPG_ERR_INV_CURVE => f.write_str("Invalid elliptic curve"),
            GPG_ERR_UNKNOWN_CURVE => f.write_str("Unknown elliptic curve"),
            GPG_ERR_DUP_KEY => f.write_str("Duplicated key"),
            GPG_ERR_AMBIGUOUS => f.write_str("Ambiguous result"),
            GPG_ERR_NO_CRYPT_CTX => f.write_str("No crypto context"),
            GPG_ERR_WRONG_CRYPT_CTX => f.write_str("Wrong crypto context"),
            GPG_ERR_BAD_CRYPT_CTX => f.write_str("Bad crypto context"),
            GPG_ERR_CRYPT_CTX_CONFLICT => f.write_str("Conflict in the crypto context"),
            GPG_ERR_BROKEN_PUBKEY => f.write_str("Broken public key"),
            GPG_ERR_BROKEN_SECKEY => f.write_str("Broken secret key"),
            GPG_ERR_MAC_ALGO => f.write_str("Invalid MAC algorithm"),
            GPG_ERR_FULLY_CANCELED => f.write_str("Operation fully cancelled"),
            GPG_ERR_UNFINISHED => f.write_str("Operation not yet finished"),
            GPG_ERR_BUFFER_TOO_SHORT => f.write_str("Buffer too short"),
            GPG_ERR_SEXP_INV_LEN_SPEC => f.write_str("Invalid length specifier in S-expression"),
            GPG_ERR_SEXP_STRING_TOO_LONG => f.write_str("String too long in S-expression"),
            GPG_ERR_SEXP_UNMATCHED_PAREN => f.write_str("Unmatched parentheses in S-expression"),
            GPG_ERR_SEXP_NOT_CANONICAL => f.write_str("S-expression not canonical"),
            GPG_ERR_SEXP_BAD_CHARACTER => f.write_str("Bad character in S-expression"),
            GPG_ERR_SEXP_BAD_QUOTATION => f.write_str("Bad quotation in S-expression"),
            GPG_ERR_SEXP_ZERO_PREFIX => f.write_str("Zero prefix in S-expression"),
            GPG_ERR_SEXP_NESTED_DH => f.write_str("Nested display hints in S-expression"),
            GPG_ERR_SEXP_UNMATCHED_DH => f.write_str("Unmatched display hints"),
            GPG_ERR_SEXP_UNEXPECTED_PUNC => f.write_str("Unexpected reserved punctuation in S-expression"),
            GPG_ERR_SEXP_BAD_HEX_CHAR => f.write_str("Bad hexadecimal character in S-expression"),
            GPG_ERR_SEXP_ODD_HEX_NUMBERS => f.write_str("Odd hexadecimal numbers in S-expression"),
            GPG_ERR_SEXP_BAD_OCT_CHAR => f.write_str("Bad octal character in S-expression"),
            GPG_ERR_SUBKEYS_EXP_OR_REV => f.write_str("All subkeys are expired or revoked"),
            GPG_ERR_DB_CORRUPTED => f.write_str("Database is corrupted"),
            GPG_ERR_SERVER_FAILED => f.write_str("Server indicated a failure"),
            GPG_ERR_NO_NAME => f.write_str("No name"),
            GPG_ERR_NO_KEY => f.write_str("No key"),
            GPG_ERR_LEGACY_KEY => f.write_str("Legacy key"),
            GPG_ERR_REQUEST_TOO_SHORT => f.write_str("Request too short"),
            GPG_ERR_REQUEST_TOO_LONG => f.write_str("Request too long"),
            GPG_ERR_OBJ_TERM_STATE => f.write_str("Object is in termination state"),
            GPG_ERR_NO_CERT_CHAIN => f.write_str("No certificate chain"),
            GPG_ERR_CERT_TOO_LARGE => f.write_str("Certificate is too large"),
            GPG_ERR_INV_RECORD => f.write_str("Invalid record"),
            GPG_ERR_BAD_MAC => f.write_str("The MAC does not verify"),
            GPG_ERR_UNEXPECTED_MSG => f.write_str("Unexpected message"),
            GPG_ERR_COMPR_FAILED => f.write_str("Compression or decompression failed"),
            GPG_ERR_WOULD_WRAP => f.write_str("A counter would wrap"),
            GPG_ERR_FATAL_ALERT => f.write_str("Fatal alert message received"),
            GPG_ERR_NO_CIPHER => f.write_str("No cipher algorithm"),
            GPG_ERR_MISSING_CLIENT_CERT => f.write_str("Missing client certificate"),
            GPG_ERR_CLOSE_NOTIFY => f.write_str("Close notification received"),
            GPG_ERR_TICKET_EXPIRED => f.write_str("Ticket expired"),
            GPG_ERR_BAD_TICKET => f.write_str("Bad ticket"),
            GPG_ERR_UNKNOWN_IDENTITY => f.write_str("Unknown identity"),
            GPG_ERR_BAD_HS_CERT => f.write_str("Bad certificate message in handshake"),
            GPG_ERR_BAD_HS_CERT_REQ => f.write_str("Bad certificate request message in handshake"),
            GPG_ERR_BAD_HS_CERT_VER => f.write_str("Bad certificate verify message in handshake"),
            GPG_ERR_BAD_HS_CHANGE_CIPHER => f.write_str("Bad change cipher message in handshake"),
            GPG_ERR_BAD_HS_CLIENT_HELLO => f.write_str("Bad client hello message in handshake"),
            GPG_ERR_BAD_HS_SERVER_HELLO => f.write_str("Bad server hello message in handshake"),
            GPG_ERR_BAD_HS_SERVER_HELLO_DONE => f.write_str("Bad server hello done message in handshake"),
            GPG_ERR_BAD_HS_FINISHED => f.write_str("Bad finished message in handshake"),
            GPG_ERR_BAD_HS_SERVER_KEX => f.write_str("Bad server key exchange message in handshake"),
            GPG_ERR_BAD_HS_CLIENT_KEX => f.write_str("Bad client key exchange message in handshake"),
            GPG_ERR_BOGUS_STRING => f.write_str("Bogus string"),
            GPG_ERR_FORBIDDEN => f.write_str("Forbidden"),
            GPG_ERR_KEY_DISABLED => f.write_str("Key disabled"),
            GPG_ERR_KEY_ON_CARD => f.write_str("Not possible with a card based key"),
            GPG_ERR_INV_LOCK_OBJ => f.write_str("Invalid lock object"),
            GPG_ERR_TRUE => f.write_str("True"),
            GPG_ERR_FALSE => f.write_str("False"),
            GPG_ERR_ASS_GENERAL => f.write_str("General IPC error"),
            GPG_ERR_ASS_ACCEPT_FAILED => f.write_str("IPC accept call failed"),
            GPG_ERR_ASS_CONNECT_FAILED => f.write_str("IPC connect call failed"),
            GPG_ERR_ASS_INV_RESPONSE => f.write_str("Invalid IPC response"),
            GPG_ERR_ASS_INV_VALUE => f.write_str("Invalid value passed to IPC"),
            GPG_ERR_ASS_INCOMPLETE_LINE => f.write_str("Incomplete line passed to IPC"),
            GPG_ERR_ASS_LINE_TOO_LONG => f.write_str("Line passed to IPC too long"),
            GPG_ERR_ASS_NESTED_COMMANDS => f.write_str("Nested IPC commands"),
            GPG_ERR_ASS_NO_DATA_CB => f.write_str("No data callback in IPC"),
            GPG_ERR_ASS_NO_INQUIRE_CB => f.write_str("No inquire callback in IPC"),
            GPG_ERR_ASS_NOT_A_SERVER => f.write_str("Not an IPC server"),
            GPG_ERR_ASS_NOT_A_CLIENT => f.write_str("Not an IPC client"),
            GPG_ERR_ASS_SERVER_START => f.write_str("Problem starting IPC server"),
            GPG_ERR_ASS_READ_ERROR => f.write_str("IPC read error"),
            GPG_ERR_ASS_WRITE_ERROR => f.write_str("IPC write error"),
            GPG_ERR_ASS_TOO_MUCH_DATA => f.write_str("Too much data for IPC layer"),
            GPG_ERR_ASS_UNEXPECTED_CMD => f.write_str("Unexpected IPC command"),
            GPG_ERR_ASS_UNKNOWN_CMD => f.write_str("Unknown IPC command"),
            GPG_ERR_ASS_SYNTAX => f.write_str("IPC syntax error"),
            GPG_ERR_ASS_CANCELED => f.write_str("IPC call has been cancelled"),
            GPG_ERR_ASS_NO_INPUT => f.write_str("No input source for IPC"),
            GPG_ERR_ASS_NO_OUTPUT => f.write_str("No output source for IPC"),
            GPG_ERR_ASS_PARAMETER => f.write_str("IPC parameter error"),
            GPG_ERR_ASS_UNKNOWN_INQUIRE => f.write_str("Unknown IPC inquire"),
            GPG_ERR_ENGINE_TOO_OLD => f.write_str("Crypto engine too old"),
            GPG_ERR_WINDOW_TOO_SMALL => f.write_str("Screen or window too small"),
            GPG_ERR_WINDOW_TOO_LARGE => f.write_str("Screen or window too large"),
            GPG_ERR_MISSING_ENVVAR => f.write_str("Required environment variable not set"),
            GPG_ERR_USER_ID_EXISTS => f.write_str("User ID already exists"),
            GPG_ERR_NAME_EXISTS => f.write_str("Name already exists"),
            GPG_ERR_DUP_NAME => f.write_str("Duplicated name"),
            GPG_ERR_TOO_YOUNG => f.write_str("Object is too young"),
            GPG_ERR_TOO_OLD => f.write_str("Object is too old"),
            GPG_ERR_UNKNOWN_FLAG => f.write_str("Unknown flag"),
            GPG_ERR_INV_ORDER => f.write_str("Invalid execution order"),
            GPG_ERR_ALREADY_FETCHED => f.write_str("Already fetched"),
            GPG_ERR_TRY_LATER => f.write_str("Try again later"),
            GPG_ERR_WRONG_NAME => f.write_str("Wrong name"),
            GPG_ERR_NO_AUTH => f.write_str("Not authenticated"),
            GPG_ERR_BAD_AUTH => f.write_str("Bad authentication"),
            GPG_ERR_NO_KEYBOXD => f.write_str("No Keybox daemon running"),
            GPG_ERR_KEYBOXD => f.write_str("Keybox daemon error"),
            GPG_ERR_NO_SERVICE => f.write_str("Service is not running"),
            GPG_ERR_SERVICE => f.write_str("Service error"),
            GPG_ERR_SYSTEM_BUG => f.write_str("System bug detected"),
            GPG_ERR_DNS_UNKNOWN => f.write_str("Unknown DNS error"),
            GPG_ERR_DNS_SECTION => f.write_str("Invalid DNS section"),
            GPG_ERR_DNS_ADDRESS => f.write_str("Invalid textual address form"),
            GPG_ERR_DNS_NO_QUERY => f.write_str("Missing DNS query packet"),
            GPG_ERR_DNS_NO_ANSWER => f.write_str("Missing DNS answer packet"),
            GPG_ERR_DNS_CLOSED => f.write_str("Connection closed in DNS"),
            GPG_ERR_DNS_VERIFY => f.write_str("Verification failed in DNS"),
            GPG_ERR_DNS_TIMEOUT => f.write_str("DNS Timeout"),
            GPG_ERR_LDAP_GENERAL => f.write_str("General LDAP error"),
            GPG_ERR_LDAP_ATTR_GENERAL => f.write_str("General LDAP attribute error"),
            GPG_ERR_LDAP_NAME_GENERAL => f.write_str("General LDAP name error"),
            GPG_ERR_LDAP_SECURITY_GENERAL => f.write_str("General LDAP security error"),
            GPG_ERR_LDAP_SERVICE_GENERAL => f.write_str("General LDAP service error"),
            GPG_ERR_LDAP_UPDATE_GENERAL => f.write_str("General LDAP update error"),
            GPG_ERR_LDAP_E_GENERAL => f.write_str("Experimental LDAP error code"),
            GPG_ERR_LDAP_X_GENERAL => f.write_str("Private LDAP error code"),
            GPG_ERR_LDAP_OTHER_GENERAL => f.write_str("Other general LDAP error"),
            GPG_ERR_LDAP_X_CONNECTING => f.write_str("LDAP connecting failed (X)"),
            GPG_ERR_LDAP_REFERRAL_LIMIT => f.write_str("LDAP referral limit exceeded"),
            GPG_ERR_LDAP_CLIENT_LOOP => f.write_str("LDAP client loop"),
            GPG_ERR_LDAP_NO_RESULTS => f.write_str("No LDAP results returned"),
            GPG_ERR_LDAP_CONTROL_NOT_FOUND => f.write_str("LDAP control not found"),
            GPG_ERR_LDAP_NOT_SUPPORTED => f.write_str("Not supported by LDAP"),
            GPG_ERR_LDAP_CONNECT => f.write_str("LDAP connect error"),
            GPG_ERR_LDAP_NO_MEMORY => f.write_str("Out of memory in LDAP"),
            GPG_ERR_LDAP_PARAM => f.write_str("Bad parameter to an LDAP routine"),
            GPG_ERR_LDAP_USER_CANCELLED => f.write_str("User cancelled LDAP operation"),
            GPG_ERR_LDAP_FILTER => f.write_str("Bad LDAP search filter"),
            GPG_ERR_LDAP_AUTH_UNKNOWN => f.write_str("Unknown LDAP authentication method"),
            GPG_ERR_LDAP_TIMEOUT => f.write_str("Timeout in LDAP"),
            GPG_ERR_LDAP_DECODING => f.write_str("LDAP decoding error"),
            GPG_ERR_LDAP_ENCODING => f.write_str("LDAP encoding error"),
            GPG_ERR_LDAP_LOCAL => f.write_str("LDAP local error"),
            GPG_ERR_LDAP_SERVER_DOWN => f.write_str("Cannot contact LDAP server"),
            GPG_ERR_LDAP_SUCCESS => f.write_str("LDAP success"),
            GPG_ERR_LDAP_OPERATIONS => f.write_str("LDAP operations error"),
            GPG_ERR_LDAP_PROTOCOL => f.write_str("LDAP protocol error"),
            GPG_ERR_LDAP_TIMELIMIT => f.write_str("Time limit exceeded in LDAP"),
            GPG_ERR_LDAP_SIZELIMIT => f.write_str("Size limit exceeded in LDAP"),
            GPG_ERR_LDAP_COMPARE_FALSE => f.write_str("LDAP compare false"),
            GPG_ERR_LDAP_COMPARE_TRUE => f.write_str("LDAP compare true"),
            GPG_ERR_LDAP_UNSUPPORTED_AUTH => f.write_str("LDAP authentication method not supported"),
            GPG_ERR_LDAP_STRONG_AUTH_RQRD => f.write_str("Strong(er) LDAP authentication required"),
            GPG_ERR_LDAP_PARTIAL_RESULTS => f.write_str("Partial LDAP results+referral received"),
            GPG_ERR_LDAP_REFERRAL => f.write_str("LDAP referral"),
            GPG_ERR_LDAP_ADMINLIMIT => f.write_str("Administrative LDAP limit exceeded"),
            GPG_ERR_LDAP_UNAVAIL_CRIT_EXTN => f.write_str("Critical LDAP extension is unavailable"),
            GPG_ERR_LDAP_CONFIDENT_RQRD => f.write_str("Confidentiality required by LDAP"),
            GPG_ERR_LDAP_SASL_BIND_INPROG => f.write_str("LDAP SASL bind in progress"),
            GPG_ERR_LDAP_NO_SUCH_ATTRIBUTE => f.write_str("No such LDAP attribute"),
            GPG_ERR_LDAP_UNDEFINED_TYPE => f.write_str("Undefined LDAP attribute type"),
            GPG_ERR_LDAP_BAD_MATCHING => f.write_str("Inappropriate matching in LDAP"),
            GPG_ERR_LDAP_CONST_VIOLATION => f.write_str("Constraint violation in LDAP"),
            GPG_ERR_LDAP_TYPE_VALUE_EXISTS => f.write_str("LDAP type or value exists"),
            GPG_ERR_LDAP_INV_SYNTAX => f.write_str("Invalid syntax in LDAP"),
            GPG_ERR_LDAP_NO_SUCH_OBJ => f.write_str("No such LDAP object"),
            GPG_ERR_LDAP_ALIAS_PROBLEM => f.write_str("LDAP alias problem"),
            GPG_ERR_LDAP_INV_DN_SYNTAX => f.write_str("Invalid DN syntax in LDAP"),
            GPG_ERR_LDAP_IS_LEAF => f.write_str("LDAP entry is a leaf"),
            GPG_ERR_LDAP_ALIAS_DEREF => f.write_str("LDAP alias dereferencing problem"),
            GPG_ERR_LDAP_X_PROXY_AUTH_FAIL => f.write_str("LDAP proxy authorization failure (X)"),
            GPG_ERR_LDAP_BAD_AUTH => f.write_str("Inappropriate LDAP authentication"),
            GPG_ERR_LDAP_INV_CREDENTIALS => f.write_str("Invalid LDAP credentials"),
            GPG_ERR_LDAP_INSUFFICIENT_ACC => f.write_str("Insufficient access for LDAP"),
            GPG_ERR_LDAP_BUSY => f.write_str("LDAP server is busy"),
            GPG_ERR_LDAP_UNAVAILABLE => f.write_str("LDAP server is unavailable"),
            GPG_ERR_LDAP_UNWILL_TO_PERFORM => f.write_str("LDAP server is unwilling to perform"),
            GPG_ERR_LDAP_LOOP_DETECT => f.write_str("Loop detected by LDAP"),
            GPG_ERR_LDAP_NAMING_VIOLATION => f.write_str("LDAP naming violation"),
            GPG_ERR_LDAP_OBJ_CLS_VIOLATION => f.write_str("LDAP object class violation"),
            GPG_ERR_LDAP_NOT_ALLOW_NONLEAF => f.write_str("LDAP operation not allowed on non-leaf"),
            GPG_ERR_LDAP_NOT_ALLOW_ON_RDN => f.write_str("LDAP operation not allowed on RDN"),
            GPG_ERR_LDAP_ALREADY_EXISTS => f.write_str("Already exists (LDAP)"),
            GPG_ERR_LDAP_NO_OBJ_CLASS_MODS => f.write_str("Cannot modify LDAP object class"),
            GPG_ERR_LDAP_RESULTS_TOO_LARGE => f.write_str("LDAP results too large"),
            GPG_ERR_LDAP_AFFECTS_MULT_DSAS => f.write_str("LDAP operation affects multiple DSAs"),
            GPG_ERR_LDAP_VLV => f.write_str("Virtual LDAP list view error"),
            GPG_ERR_LDAP_OTHER => f.write_str("Other LDAP error"),
            GPG_ERR_LDAP_CUP_RESOURCE_LIMIT => f.write_str("Resources exhausted in LCUP"),
            GPG_ERR_LDAP_CUP_SEC_VIOLATION => f.write_str("Security violation in LCUP"),
            GPG_ERR_LDAP_CUP_INV_DATA => f.write_str("Invalid data in LCUP"),
            GPG_ERR_LDAP_CUP_UNSUP_SCHEME => f.write_str("Unsupported scheme in LCUP"),
            GPG_ERR_LDAP_CUP_RELOAD => f.write_str("Reload required in LCUP"),
            GPG_ERR_LDAP_CANCELLED => f.write_str("LDAP cancelled"),
            GPG_ERR_LDAP_NO_SUCH_OPERATION => f.write_str("No LDAP operation to cancel"),
            GPG_ERR_LDAP_TOO_LATE => f.write_str("Too late to cancel LDAP"),
            GPG_ERR_LDAP_CANNOT_CANCEL => f.write_str("Cannot cancel LDAP"),
            GPG_ERR_LDAP_ASSERTION_FAILED => f.write_str("LDAP assertion failed"),
            GPG_ERR_LDAP_PROX_AUTH_DENIED => f.write_str("Proxied authorization denied by LDAP"),
            GPG_ERR_USER_1 => f.write_str("User defined error code 1"),
            GPG_ERR_USER_2 => f.write_str("User defined error code 2"),
            GPG_ERR_USER_3 => f.write_str("User defined error code 3"),
            GPG_ERR_USER_4 => f.write_str("User defined error code 4"),
            GPG_ERR_USER_5 => f.write_str("User defined error code 5"),
            GPG_ERR_USER_6 => f.write_str("User defined error code 6"),
            GPG_ERR_USER_7 => f.write_str("User defined error code 7"),
            GPG_ERR_USER_8 => f.write_str("User defined error code 8"),
            GPG_ERR_USER_9 => f.write_str("User defined error code 9"),
            GPG_ERR_USER_10 => f.write_str("User defined error code 10"),
            GPG_ERR_USER_11 => f.write_str("User defined error code 11"),
            GPG_ERR_USER_12 => f.write_str("User defined error code 12"),
            GPG_ERR_USER_13 => f.write_str("User defined error code 13"),
            GPG_ERR_USER_14 => f.write_str("User defined error code 14"),
            GPG_ERR_USER_15 => f.write_str("User defined error code 15"),
            GPG_ERR_USER_16 => f.write_str("User defined error code 16"),
            GPG_ERR_SQL_OK => f.write_str("SQL success"),
            GPG_ERR_SQL_ERROR => f.write_str("SQL error"),
            GPG_ERR_SQL_INTERNAL => f.write_str("Internal logic error in SQL library"),
            GPG_ERR_SQL_PERM => f.write_str("Access permission denied (SQL)"),
            GPG_ERR_SQL_ABORT => f.write_str("SQL abort was requested"),
            GPG_ERR_SQL_BUSY => f.write_str("SQL database file is locked"),
            GPG_ERR_SQL_LOCKED => f.write_str("An SQL table in the database is locked"),
            GPG_ERR_SQL_NOMEM => f.write_str("SQL library ran out of core"),
            GPG_ERR_SQL_READONLY => f.write_str("Attempt to write a readonly SQL database"),
            GPG_ERR_SQL_INTERRUPT => f.write_str("SQL operation terminated by interrupt"),
            GPG_ERR_SQL_IOERR => f.write_str("I/O error during SQL operation"),
            GPG_ERR_SQL_CORRUPT => f.write_str("SQL database disk image is malformed"),
            GPG_ERR_SQL_NOTFOUND => f.write_str("Unknown opcode in SQL file control"),
            GPG_ERR_SQL_FULL => f.write_str("Insertion failed because SQL database is full"),
            GPG_ERR_SQL_CANTOPEN => f.write_str("Unable to open the SQL database file"),
            GPG_ERR_SQL_PROTOCOL => f.write_str("SQL database lock protocol error"),
            GPG_ERR_SQL_EMPTY => f.write_str("(internal SQL code: empty)"),
            GPG_ERR_SQL_SCHEMA => f.write_str("SQL database schema changed"),
            GPG_ERR_SQL_TOOBIG => f.write_str("String or blob exceeds size limit (SQL)"),
            GPG_ERR_SQL_CONSTRAINT => f.write_str("SQL abort due to constraint violation"),
            GPG_ERR_SQL_MISMATCH => f.write_str("Data type mismatch (SQL)"),
            GPG_ERR_SQL_MISUSE => f.write_str("SQL library used incorrectly"),
            GPG_ERR_SQL_NOLFS => f.write_str("SQL library uses unsupported OS features"),
            GPG_ERR_SQL_AUTH => f.write_str("Authorization denied (SQL)"),
            GPG_ERR_SQL_FORMAT => f.write_str("(unused SQL code: format)"),
            GPG_ERR_SQL_RANGE => f.write_str("SQL bind parameter out of range"),
            GPG_ERR_SQL_NOTADB => f.write_str("File opened that is not an SQL database file"),
            GPG_ERR_SQL_NOTICE => f.write_str("Notifications from SQL logger"),
            GPG_ERR_SQL_WARNING => f.write_str("Warnings from SQL logger"),
            GPG_ERR_SQL_ROW => f.write_str("SQL has another row ready"),
            GPG_ERR_SQL_DONE => f.write_str("SQL has finished executing"),
            GPG_ERR_MISSING_ERRNO => f.write_str("System error w/o errno"),
            GPG_ERR_UNKNOWN_ERRNO => f.write_str("Unknown system error"),
            GPG_ERR_EOF => f.write_str("End of file"),
            GPG_ERR_MINUS_ONE => f.write_str("Minus one"),
        }
    }
}

impl  std::error::Error for Error {}
