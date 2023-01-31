use std::{
    time,
};

use anyhow::Result;
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
        "twofish128" => Ok(SymmetricAlgorithm::Twofish),
        "camellia128" => Ok(SymmetricAlgorithm::Camellia128),
        "camellia192" => Ok(SymmetricAlgorithm::Camellia192),
        "camellia256" => Ok(SymmetricAlgorithm::Camellia256),
        _ => Err(anyhow::anyhow!("Unknown hash algorithm {:?}", s)),
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
        _ => Err(anyhow::anyhow!("Unknown hash algorithm {:?}", s)),
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
                &s[..15], "%Y%m%dT%H%M%S")
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
                    let multiplier = match s.chars().last().unwrap()
                        .to_ascii_lowercase()
                    {
                        'd' => 1,
                        'w' => 7,
                        'm' => 30,
                        'y' => 365,
                        _ => unreachable!("checked above"),
                    };
                    return Ok(Some(time::Duration::new(
                        s[..s.len()-1].parse::<u64>()? * multiplier, 0)));
                }
            }

            Err(anyhow::anyhow!("Invalid expiration date: {:?}", s))
        }
    }
}

pub fn mailbox_from_userid(s: &str) -> Result<Option<String>> {
    openpgp::packet::UserID::from(s).email()
}
