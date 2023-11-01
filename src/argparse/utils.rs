use std::{
    fs,
    io,
    time,
};

use anyhow::{Context, Result};
use sequoia_openpgp as openpgp;
use openpgp::{
    types::*,
};


pub fn parse_digest(s: &str) -> Result<HashAlgorithm> {
    let sl = s.to_lowercase();
    if sl.starts_with('h') {
        if let Ok(a) = sl[1..].parse::<u8>() {
            return Ok(a.into());
        }
    }

    match sl.as_str() {
        "md5" => Ok(HashAlgorithm::MD5),
        "sha1" => Ok(HashAlgorithm::SHA1),
        "ripemd160" => Ok(HashAlgorithm::RipeMD),
        "sha256" => Ok(HashAlgorithm::SHA256),
        "sha384" => Ok(HashAlgorithm::SHA384),
        "sha512" => Ok(HashAlgorithm::SHA512),
        "sha224" => Ok(HashAlgorithm::SHA224),
        _ => Err(anyhow::anyhow!("Unknown hash algorithm {:?}", s)),
    }
}

pub fn parse_cipher(s: &str) -> Result<SymmetricAlgorithm> {
    let sl = s.to_lowercase();
    if sl.starts_with('s') {
        if let Ok(a) = sl[1..].parse::<u8>() {
            return Ok(a.into());
        }
    }

    match sl.as_str() {
        "idea" => Ok(SymmetricAlgorithm::IDEA),
        "3des" => Ok(SymmetricAlgorithm::TripleDES),
        "cast5" => Ok(SymmetricAlgorithm::CAST5),
        "blowfish" => Ok(SymmetricAlgorithm::Blowfish),
        "aes" => Ok(SymmetricAlgorithm::AES128),
        "aes192" => Ok(SymmetricAlgorithm::AES192),
        "aes256" => Ok(SymmetricAlgorithm::AES256),
        "twofish" => Ok(SymmetricAlgorithm::Twofish),
        "twofish128" => Ok(SymmetricAlgorithm::Twofish),
        "camellia128" => Ok(SymmetricAlgorithm::Camellia128),
        "camellia192" => Ok(SymmetricAlgorithm::Camellia192),
        "camellia256" => Ok(SymmetricAlgorithm::Camellia256),
        _ => Err(anyhow::anyhow!("Unknown cipher algorithm {:?}", s)),
    }
}

pub fn parse_compressor(s: &str) -> Result<CompressionAlgorithm> {
    let sl = s.to_lowercase();
    if sl.starts_with('z') {
        if let Ok(a) = sl[1..].parse::<u8>() {
            return Ok(a.into());
        }
    }

    match sl.as_str() {
        "none" | "uncompressed" => Ok(CompressionAlgorithm::Uncompressed),
        "zip" => Ok(CompressionAlgorithm::Zip),
        "zlib" => Ok(CompressionAlgorithm::Zlib),
        "bzip2" => Ok(CompressionAlgorithm::BZip2),
        _ => Err(anyhow::anyhow!("Unknown compression algorithm {:?}", s)),
    }
}

pub fn parse_expiration(s: &str) -> Result<Option<time::Duration>> {
    let now = chrono::Utc::now();

    match s {
        "" | "none" | "never" | "-" | "0" => Ok(None),
        s if s.starts_with("seconds=") => {
            match s[8..].parse::<u64>() {
                Ok(v) => Ok(Some(time::Duration::new(v, 0))),
                Err(e) => Err(anyhow::Error::from(e)
                              .context("Invalid number of seconds")),
            }
        },
        _ => {
            // ISO date.
            if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
            {
                // At noon, or, as GnuPG would say, 86400/2.
                let dt = d.and_time(chrono::NaiveTime::from_hms_opt(12, 0, 0)
                                    .expect("this to be a valid time"));
                let dtu = chrono::DateTime::from_utc(dt, chrono::Utc);
                if dtu > now {
                    let duration = dtu - now;
                    return Ok(Some(duration.to_std().expect("non-negative")));
                }
            }

            // ISO time.  The only supported format is
            // "yyyymmddThhmmss[Z]" delimited by white space, nul, a
            // colon or a comma.
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(
                &s[..15.min(s.len())], "%Y%m%dT%H%M%S")
            {
                let dtu = chrono::DateTime::from_utc(dt, chrono::Utc);
                if dtu > now {
                    let duration = dtu - now;
                    return Ok(Some(duration.to_std().expect("non-negative")));
                }
            }

            // Days, in the format [0-9]+[dDwWmMyY]?.
            if s.chars().rev().skip(1).all(|c| c.is_ascii_digit())
                && s.chars().last().map(|c| c.is_ascii_digit()
                                        || c == 'd' || c == 'D'
                                        || c == 'w' || c == 'W'
                                        || c == 'm' || c == 'M'
                                        || c == 'y' || c == 'Y')
                .unwrap_or(false)
            {
                let last_is_digit =
                    s.chars().last().map(|c| c.is_ascii_digit())
                    .unwrap_or(false);
                if last_is_digit {
                    return Ok(Some(time::Duration::new(s.parse()?, 0)));
                } else {
                    let days = match s.chars().last().unwrap()
                        .to_ascii_lowercase()
                    {
                        'd' => 1,
                        'w' => 7,
                        'm' => 30,
                        'y' => 365,
                        _ => unreachable!("checked above"),
                    };
                    return Ok(Some(time::Duration::new(
                        s[..s.len()-1].parse::<u64>()? * days * 24 * 60 * 60, 0)));
                }
            }

            Err(anyhow::anyhow!("Invalid expiration date: {:?}", s))
        }
    }
}

pub fn mailbox_from_userid(s: &str) -> Result<Option<String>> {
    openpgp::packet::UserID::from(s).email2()
        .map(|o| o.map(ToString::to_string))
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
    #[test]
    fn parse_expiration() {
        use std::time::Duration;
        use super::parse_expiration as pe;
        assert_eq!(pe("").unwrap(), None);
        assert_eq!(pe("0").unwrap(), None);
        assert_eq!(pe("none").unwrap(), None);
        assert_eq!(pe("never").unwrap(), None);
        assert_eq!(pe("-").unwrap(), None);
        assert_eq!(pe("1").unwrap().unwrap(),
                   Duration::new(1, 0));
        assert_eq!(pe("1d").unwrap().unwrap(),
                   Duration::new(1 * 24 * 60 * 60 , 0));
        assert_eq!(pe("1D").unwrap().unwrap(),
                   Duration::new(1 * 24 * 60 * 60, 0));
        assert_eq!(pe("1w").unwrap().unwrap(),
                   Duration::new(7 * 24 * 60 * 60 , 0));
        assert_eq!(pe("1W").unwrap().unwrap(),
                   Duration::new(7 * 24 * 60 * 60, 0));
        assert_eq!(pe("1m").unwrap().unwrap(),
                   Duration::new(30 * 24 * 60 * 60 , 0));
        assert_eq!(pe("1M").unwrap().unwrap(),
                   Duration::new(30 * 24 * 60 * 60, 0));
        assert_eq!(pe("1y").unwrap().unwrap(),
                   Duration::new(365 * 24 * 60 * 60 , 0));
        assert_eq!(pe("1Y").unwrap().unwrap(),
                   Duration::new(365 * 24 * 60 * 60, 0));
    }
}
