//! Miscellaneous utilities.

use std::{
    convert::TryInto,
    fs,
    io,
};

use anyhow::{Context, Result};

use crate::{
    control,
};

/// Opens a (special) file.
pub fn open(control: &dyn control::Common, name: &str)
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
pub fn open_multiple(control: &dyn control::Common, names: &[String])
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
pub fn create(control: &dyn control::Common, name: &str)
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
fn special_filename_fd(name: &str) -> Option<i64> {
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

