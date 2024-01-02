//! Flags changing the behavior.

/* Tests for the debugging flags.  */
pub const DBG_PACKET_VALUE: u32 = 1	/* debug packet reading/writing */;
pub const DBG_MPI_VALUE	: u32 = 2	/* debug mpi details */;
pub const DBG_CRYPTO_VALUE: u32 = 4	/* debug crypto handling */;
				/* (may reveal sensitive data) */
pub const DBG_FILTER_VALUE: u32 = 8	/* debug internal filter handling */;
pub const DBG_IOBUF_VALUE: u32 = 16	/* debug iobuf stuff */;
pub const DBG_MEMORY_VALUE: u32 = 32	/* debug memory allocation stuff */;
pub const DBG_CACHE_VALUE: u32 = 64	/* debug the caching */;
pub const DBG_MEMSTAT_VALUE: u32 = 128	/* show memory statistics */;
pub const DBG_TRUST_VALUE: u32 = 256	/* debug the trustdb */;
pub const DBG_HASHING_VALUE: u32 = 512	/* debug hashing operations */;
pub const DBG_IPC_VALUE: u32 = 1024  /* debug assuan communication */;
pub const DBG_CLOCK_VALUE: u32 = 4096;
pub const DBG_LOOKUP_VALUE: u32 = 8192	/* debug the key lookup */;
pub const DBG_EXTPROG_VALUE: u32 = 16384 /* debug external program calls */;

/* Various option flags.  Note that there should be no common string
   names between the IMPORT_ and EXPORT_ flags as they can be mixed in
   the keyserver-options option. */

pub const VERIFY_SHOW_PHOTOS: u32 = 1 << 0;
pub const VERIFY_SHOW_POLICY_URLS: u32 = 1 << 1;
pub const VERIFY_SHOW_STD_NOTATIONS: u32 = 1 << 2;
pub const VERIFY_SHOW_USER_NOTATIONS: u32 = 1 << 3;
pub const VERIFY_SHOW_NOTATIONS: u32 = VERIFY_SHOW_STD_NOTATIONS | VERIFY_SHOW_USER_NOTATIONS;
pub const VERIFY_SHOW_KEYSERVER_URLS: u32 = 1 << 4;
pub const VERIFY_SHOW_UID_VALIDITY: u32 = 1 << 5;
pub const VERIFY_SHOW_UNUSABLE_UIDS: u32 = 1 << 6;
pub const VERIFY_PKA_LOOKUPS: u32 = 1 << 7;
pub const VERIFY_PKA_TRUST_INCREASE: u32 = 1 << 8;
pub const VERIFY_SHOW_PRIMARY_UID_ONLY: u32 = 1 << 9;

pub const KEYSERVER_HTTP_PROXY: u32 = 1 << 0;
pub const KEYSERVER_TIMEOUT: u32 = 1 << 1;
pub const KEYSERVER_ADD_FAKE_V3: u32 = 1 << 2;
pub const KEYSERVER_AUTO_KEY_RETRIEVE: u32 = 1 << 3;
pub const KEYSERVER_HONOR_KEYSERVER_URL: u32 = 1 << 4;
pub const KEYSERVER_HONOR_PKA_RECORD: u32 = 1 << 5;
