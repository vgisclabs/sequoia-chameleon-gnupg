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
