//! Miscellaneous utilities.

use std::{
    convert::TryInto,
    fs,
    io,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    policy::Policy,
};

use crate::{
    common,
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
        source_from_fd(fd)
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


/// Returns the file descriptor if the given name is a special
/// filename.
pub fn special_filename_fd(name: &str) -> Option<i64> {
    if name.starts_with("-&") {
        name[2..].parse().ok()
    } else {
       None
    }
}

/// Creates an io::Write from the given file descriptor.
pub fn sink_from_fd(fd: i64) -> Result<Box<dyn io::Write + Send + Sync>> {
    platform! {
        unix => {
            use std::os::unix::io::FromRawFd;
            let fd = fd.try_into().context(
                format!("Not a valid file descriptor: {}", fd))?;
            Ok(Box::new(unsafe {
                fs::File::from_raw_fd(fd)
            }))
        },
        windows => {
            unimplemented!()
        },
    }
}

/// Creates an io::Read from the given file descriptor.
pub fn source_from_fd(fd: i64) -> Result<Box<dyn io::Read + Send + Sync>> {
    platform! {
        unix => {
            use std::os::unix::io::FromRawFd;
            let fd = fd.try_into().context(
                format!("Not a valid file descriptor: {}", fd))?;
            Ok(Box::new(unsafe {
                fs::File::from_raw_fd(fd)
            }))
        },
        windows => {
            unimplemented!()
        },
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

/// Returns a line with the same length of `t` (up to 80 characters).
pub fn undeline_for(t: &str) -> &[u8] {
    const U: [u8; 80] = ['-' as u8; 80];
    let l = U.len().min(t.len());
    &U[..l]
}
