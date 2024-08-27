use std::{
    fs,
    io,
};

use anyhow::{Context, Result};

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
    file_sink_from_fd(fd).map(|f| -> Box<dyn io::Write + Send + Sync> {
        Box::new(f)
    })
}

/// Creates a fs::File from the given file descriptor.
pub fn file_sink_from_fd(fd: i64) -> Result<fs::File> {
    platform! {
        unix => {
            use std::os::unix::io::FromRawFd;
            let fd = fd.try_into().context(
                format!("Not a valid file descriptor: {}", fd))?;
            Ok(unsafe {
                fs::File::from_raw_fd(fd)
            })
        },
        windows => {
            unimplemented!()
        },
    }
}

/// Creates an io::Read from the given file descriptor.
pub fn source_from_fd(fd: i64) -> Result<fs::File> {
    platform! {
        unix => {
            use std::os::unix::io::FromRawFd;
            let fd = fd.try_into().context(
                format!("Not a valid file descriptor: {}", fd))?;
            Ok(unsafe {
                fs::File::from_raw_fd(fd)
            })
        },
        windows => {
            unimplemented!()
        },
    }
}

#[cfg(test)]
mod tests {
}
