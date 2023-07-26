//! Miscellaneous utilities.

use std::{
    fs,
    io,
    path::{Path, PathBuf},
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    policy::Policy,
};

pub use crate::{
    argparse::utils::{
        sink_from_fd,
        source_from_fd,
        special_filename_fd,
    },
};
use crate::{
    common::{self, Query},
};

/// Opens a (special) file.
#[allow(dead_code)]
pub fn open(control: &dyn common::Common, name: &str)
            -> Result<Box<dyn io::Read + Send + Sync>>
{
    if name == "-" {
        Ok(Box::new(io::stdin()))
    } else if control.special_filenames()
        && special_filename_fd(name).is_some()
    {
        let fd = special_filename_fd(name).expect("checked above");
        Ok(Box::new(source_from_fd(fd)?))
    } else {
        Ok(Box::new(fs::File::open(name)?))
    }
}

/// Opens multiple (special) files, joining them into one stream.
#[allow(dead_code)]
pub fn open_multiple(control: &dyn common::Common, names: &[String])
                     -> Box<dyn io::Read + Send + Sync>
{
    Box::new(MultiReader {
        special_filenames: control.special_filenames(),
        names: names.iter().rev().cloned().map(Into::into).collect(),
        current: None,
    })
}

struct MultiReader {
    special_filenames: bool,
    names: Vec<String>,
    current: Option<Box<dyn io::Read + Send + Sync>>,
}

impl io::Read for MultiReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // First, try the currently opened file.
        if let Some(mut current) = self.current.take() {
            let bytes_read = current.read(buf)?;
            if bytes_read > 0 {
                self.current = Some(current);
                return Ok(bytes_read);
            } else {
                // Try the next file.
                return self.read(buf);
            }
        }

        // Second, try to open the next file.
        if let Some(name) = self.names.pop() { // names are reversed.
            self.current = Some(
                if name == "-" {
                    Box::new(io::stdin())
                } else if self.special_filenames
                    && special_filename_fd(&name).is_some()
                {
                    let fd = special_filename_fd(&name).expect("checked above");
                    source_from_fd(fd)
                        .map(|f| Box::new(f))
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
                } else {
                    Box::new(fs::File::open(name)?)
                }
            );

            self.read(buf)
        } else {
            // Final EOF.
            Ok(0)
        }
    }
}

/// Opens a (special) file for writing.
#[allow(dead_code)]
pub fn create(control: &dyn common::Common, name: &str)
              -> Result<Box<dyn io::Write + Send + Sync>>
{
    if name == "-" {
        Ok(Box::new(io::stdout()))
    } else if control.special_filenames()
        && special_filename_fd(name).is_some()
    {
        let fd = special_filename_fd(name).expect("checked above");
        sink_from_fd(fd)
    } else {
        Ok(Box::new(fs::File::create(name)?))
    }
}

/// Best-effort heuristic to compute the primary User ID of a given cert.
pub fn best_effort_primary_uid(policy: &dyn Policy, cert: &Cert) -> String {
    // Try to be more helpful by including a User ID in the
    // listing.  We'd like it to be the primary one.  Use
    // decreasingly strict policies.
    let mut primary_uid = None;

    // First, apply our policy.
    if let Ok(vcert) = cert.with_policy(policy, None) {
        if let Ok(primary) = vcert.primary_userid() {
            primary_uid = Some(primary.value().to_vec());
        }
    }

    // Second, apply the null policy.
    if primary_uid.is_none() {
        let null = openpgp::policy::NullPolicy::new();
        if let Ok(vcert) = cert.with_policy(&null, None) {
            if let Ok(primary) = vcert.primary_userid() {
                primary_uid = Some(primary.value().to_vec());
            }
        }
    }

    // As a last resort, pick the first user id.
    if primary_uid.is_none() {
        if let Some(primary) = cert.userids().next() {
            primary_uid = Some(primary.value().to_vec());
        } else {
            // Special case, there is no user id.
            primary_uid = Some(b"(NO USER ID)"[..].into());
        }
    }

    String::from_utf8_lossy(&primary_uid.expect("set at this point")).into()
}

/// Returns the cert's User ID matching the query.
///
/// This falls back to a best-effort heuristic to compute the primary
/// User ID if the query matches a key.
pub fn best_effort_uid_for_query(policy: &dyn Policy,
                                 cert: &Cert,
                                 query: &Query)
                                 -> String
{
    match query {
        Query::Key(_) | Query::ExactKey(_) => (),
        Query::Email(_) | Query::UserIDFragment(_) =>
            for uidb in cert.userids() {
                if query.matches_userid(uidb.userid()) {
                    return String::from_utf8_lossy(uidb.userid().value()).into();
                }
            },
    }

    best_effort_primary_uid(policy, cert)
}

/// Returns a line with the same length of `t` (up to 80 characters).
pub fn undeline_for(t: &str) -> &[u8] {
    const U: [u8; 80] = ['-' as u8; 80];
    let l = U.len().min(t.len());
    &U[..l]
}

/// Robustly canonicalizes the given path.
///
/// This function works even in cases where std::fs::canonicalize does
/// not, notably when a component doesn't yet exist.
pub fn robustly_canonicalize<P: AsRef<Path>>(path: P) -> PathBuf {
    if let Ok(p) = path.as_ref().canonicalize() {
        return p;
    }

    let mut p = path.as_ref().to_path_buf();
    let mut tail = if let Some(t) = p.file_name() {
        PathBuf::from(t)
    } else {
        return p; // Somewhat odd corner case.
    };

    // Walk up, trying to canonicalize the parents.
    while p.pop() {
        if let Ok(p) = p.canonicalize() {
            return p.join(tail);
        }
        tail = p.file_name().map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from(".")) // Technically a failure.
            .join(tail);
    }

    p.join(tail)
}

/// Strips known extensions from filename.
///
/// Returns an error if we didn't recognize the file extension.
pub fn make_outfile_name<S: AsRef<str>>(name: S) -> Result<String> {
    let s = name.as_ref();
    if s.ends_with(".gpg") {
        Ok(s[..s.len() - 4].into())
    } else if s.ends_with(".gpg") {
        Ok(s[..s.len() - 4].into())
    } else if s.ends_with(".pgp") {
        Ok(s[..s.len() - 4].into())
    } else if s.ends_with(".sig") {
        Ok(s[..s.len() - 4].into())
    } else if s.ends_with(".asc") {
        Ok(s[..s.len() - 4].into())
    } else if s.ends_with(".sign") {
        Ok(s[..s.len() - 5].into())
    } else {
        Err(anyhow::anyhow!("{}: unknown suffix", s))
    }
}

/// Converts S2K::Iterated's `hash_bytes` into coded count
/// representation.
///
/// # Errors
///
/// Fails with `Error::InvalidArgument` if `hash_bytes` cannot be
/// encoded. See also [`S2K::nearest_hash_count()`].
///
// Notes: Copied from S2K::encode_count.
#[allow(dead_code)]
pub fn s2k_encode_iteration_count(hash_bytes: u32) -> Result<u8> {
    use openpgp::Error;
    // eeee.mmmm -> (16 + mmmm) * 2^(6 + e)

    let msb = 32 - hash_bytes.leading_zeros();
    let (mantissa_mask, tail_mask) = match msb {
        0..=10 => {
            return Err(Error::InvalidArgument(
                format!("S2K: cannot encode iteration count of {}",
                        hash_bytes)).into());
        }
        11..=32 => {
            let m = 0b11_1100_0000 << (msb - 11);
            let t = 1 << (msb - 11);

            (m, t - 1)
        }
        _ => unreachable!()
    };
    let exp = if msb < 11 { 0 } else { msb - 11 };
    let mantissa = (hash_bytes & mantissa_mask) >> (msb - 5);

    if tail_mask & hash_bytes != 0 {
        return Err(Error::InvalidArgument(
            format!("S2K: cannot encode iteration count of {}",
                    hash_bytes)).into());
    }

    Ok(mantissa as u8 | (exp as u8) << 4)
}

/// Sanitizes an ASCII string for display purposes.
pub fn sanitize_ascii_str(s: &[u8], escape: &[u8]) -> String {
    let mut o = String::with_capacity(s.len());

    for c in s.iter().cloned() {
        if c < 0x20 || c == 0x7f || escape.contains(&c) || c == b'\\' {
            o.push('\\');
            match c {
                b'\n' => o.push('n'),
                b'\r' => o.push('r'),
                0x0c => o.push('f'),
                0x0b => o.push('v'),
                0x08 => o.push('b'),
                b'\x00' => o.push('0'),
                _ => o.push_str(&format!("x{:02x}", c)),
            }
        } else {
            o.push(c as char);
        }
    }

    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robustly_canonicalize() {
        use super::robustly_canonicalize as rc;
        let current_dir = std::env::current_dir().unwrap();

        assert_eq!(rc(""), Path::new(""));
        assert_eq!(rc("/"), Path::new("/"));
        assert_eq!(rc("."), current_dir);
        assert_eq!(rc("./"), current_dir);
        assert_eq!(rc("/dev"), Path::new("/dev"));
        assert_eq!(rc("/dev/null"), Path::new("/dev/null"));
        assert_eq!(rc("/dev/i/dont/exist"), Path::new("/dev/i/dont/exist"));
        assert_eq!(rc("/i/dont/exist"), Path::new("/i/dont/exist"));
        assert_eq!(rc("i/dont/exist"), current_dir.join("i/dont/exist"));
    }
}
