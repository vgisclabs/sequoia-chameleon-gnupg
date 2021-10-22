//! Translates GnuPG-speak from and to Sequoia-speak.

use std::{
    fmt,
    time,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    types::*,
};

/// Translates values to and from human-readable forms.
pub struct Fish<T>(pub T);

impl fmt::Display for Fish<std::time::SystemTime> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const TIMEFMT: &str = "%c %Z";
        const CTIMEFMT: &[u8] = b"%c %Z\x00";

        /// Fallback using chrono.
        fn fallback(f: &mut fmt::Formatter<'_>, t: time::SystemTime)
                    -> fmt::Result {
            write!(f, "{}",
                   chrono::DateTime::<chrono::Utc>::from(t)
                   .format(TIMEFMT))
        }

        // Actually use a chrono dependency for WASM since there's no strftime
        // (except for WASI).
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
            fallback(f, self.0)
        }
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))] {
            extern "C" {
                fn strftime(
                    s: *mut libc::c_char,
                    max: libc::size_t,
                    format: *const libc::c_char,
                    tm: *const libc::tm,
                ) -> usize;
            }

            let t = match self.0.duration_since(std::time::UNIX_EPOCH) {
                Ok(t) => t.as_secs() as libc::time_t,
                Err(_) => return fallback(f, self.0),
            };

            // This must be large enough for any locale.
            let mut s = [0u8; 64];

            let len = unsafe {
                let mut tm: libc::tm = std::mem::zeroed();

                #[cfg(unix)]
                libc::gmtime_r(&t, &mut tm);
                #[cfg(windows)]
                libc::gmtime_s(&mut tm, &t);

                strftime(s.as_mut_ptr() as *mut libc::c_char,
                         s.len(),
                         CTIMEFMT.as_ptr() as *const libc::c_char,
                         &tm)
            };

            write!(f, "{}",
                   std::ffi::CStr::from_bytes_with_nul(&s[..len + 1])
                   .expect("strftime nul terminates string")
                   .to_string_lossy())
        }
    }
}

impl fmt::Display for Fish<PublicKeyAlgorithm> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match self.0 {
            RSAEncryptSign => f.write_str("RSA"),
            RSAEncrypt => f.write_str("RSA"),
            RSASign => f.write_str("RSA"),
            ElGamalEncrypt => f.write_str("ELG"),
            DSA => f.write_str("DSA"),
            ECDSA => f.write_str("ECDSA"),
            ElGamalEncryptSign => f.write_str("ELG"),
            ECDH => f.write_str("ECDH"),
            EdDSA => f.write_str("EDDSA"),
            Private(u) => write!(f, "Private({})", u),
            Unknown(u) => write!(f, "Unknown({})", u),
            catchall => write!(f, "{:?}", catchall),
        }
    }
}
