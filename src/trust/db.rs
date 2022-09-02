/// TrustDB implementation.
///
/// See doc/DETAILS, section "Layout of the TrustDB".

use std::{
    path::{Path, PathBuf},
    time::*,
};

use anyhow::Result;

use buffered_reader::{
    BufferedReader,
    File,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
};

use crate::{
    Config,
    control::Common,
    trust::TrustModel,
};

/// The mask covers the type.
pub const TRUST_MASK: u32 = 15;

/// Not yet calculated/assigned (o).
pub const TRUST_UNKNOWN: u32 = 0;

/// Calculation may be invalid (e).
pub const TRUST_EXPIRED: u32 = 1;

/// Not enough information for calculation (q).
pub const TRUST_UNDEFINED: u32 = 2;

/// Never trust this pubkey (n).
pub const TRUST_NEVER: u32 = 3;

/// Marginally trusted (m).
pub const TRUST_MARGINAL: u32 = 4;

/// Fully trusted (f).
pub const TRUST_FULLY: u32 = 5;

/// Ultimately trusted (u).
pub const TRUST_ULTIMATE: u32 = 6;

// Trust values not covered by the mask.

/// Revoked (r).
pub const TRUST_FLAG_REVOKED: u32 = 32;

/// Revoked but for subkeys (r).
pub const TRUST_FLAG_SUB_REVOKED: u32 = 64;

/// Key/uid disabled (d).
pub const TRUST_FLAG_DISABLED: u32 = 128;

/// Heck-trustdb is pending (a).
pub const TRUST_FLAG_PENDING_CHECK: u32 = 256;

/// The trust value is based on the TOFU information.
pub const TRUST_FLAG_TOFU_BASED: u32 = 512;



pub struct TrustDB {
    path: PathBuf,
}

impl Default for TrustDB {
    fn default() -> Self {
        Self::with_name("trustdb.gpg")
    }
}

impl TrustDB {
    pub fn with_name(name: impl AsRef<Path>) -> Self {
        TrustDB {
            path: name.as_ref().into(), // XXX
        }
    }

    pub fn version(&self, config: &Config) -> Version {
        let v = self.read_version(config).ok();
        Version {
            version: 2,
            marginals_needed: config.marginals_needed
                .map(|v| v.try_into().unwrap_or(0xff))
                .or_else(|| v.as_ref().map(|v| v.marginals_needed))
                .unwrap_or(crate::trust::DEFAULT_MARGINALS_NEEDED),
            completes_needed: config.completes_needed
                .map(|v| v.try_into().unwrap_or(0xff))
                .or_else(|| v.as_ref().map(|v| v.completes_needed))
                .unwrap_or(crate::trust::DEFAULT_COMPLETES_NEEDED),
            max_cert_depth: config.max_cert_depth
                .map(|v| v.try_into().unwrap_or(0xff))
                .or_else(|| v.as_ref().map(|v| v.max_cert_depth))
                .unwrap_or(crate::trust::DEFAULT_MAX_CERT_DEPTH),
            model: config.trust_model
                .or_else(|| v.as_ref().map(|v| v.model))
                .unwrap_or_default(),
            min_cert_level: v.as_ref().map(|v| v.min_cert_level)
                .unwrap_or_default(),
            creation_time: v.as_ref().map(|v| v.creation_time)
                .unwrap_or_else(std::time::SystemTime::now),
            expiration_time: v.as_ref().and_then(|v| v.expiration_time.clone()),
            first_free: v.as_ref().map(|v| v.first_free)
                .unwrap_or(0.into()),
            hash_table: v.as_ref().map(|v| v.hash_table)
                .unwrap_or(0.into()),
        }
    }

    fn read_version(&self, config: &Config) -> Result<Version> {
        let mut reader = File::open(config.make_filename(&self.path))?;
        let version_record = Record::from_buffered_reader(&mut reader)?;
        if let Record::Version(v) = version_record {
            Ok(v)
        } else {
            Err(anyhow::anyhow!(
                "First record in TrustDB {:?} is not a version record",
                config.make_filename(&self.path)))
        }
    }

    pub fn ultimately_trusted_keys(&self, config: &Config)
                                   -> Result<Vec<Fingerprint>>
    {
        let mut reader = File::open(config.make_filename(&self.path))?;
        let mut utks = Vec::new();
        while let Ok(record) = Record::from_buffered_reader(&mut reader) {
            match record {
                Record::Trust { fingerprint, ownertrust, .. } => {
                    if ownertrust as u32 & TRUST_MASK == TRUST_ULTIMATE {
                        utks.push(fingerprint);
                    }
                }
                _ => (),
            }
        }
        Ok(utks)
    }
}

/// Index into the TrustDB.
///
/// The TrustDB consists of fixed-size records that can reference each
/// other using their position in the database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Index(u32);

impl From<u32> for Index {
    fn from(v: u32) -> Self {
        Index(v)
    }
}

/// A TrustDB record.
pub enum Record {
    Version(Version),

    Trust {
        fingerprint: Fingerprint,
        ownertrust: u8,
        depth: u8,
        min_ownertrust: u8,
        flags: u8,
        valid_list: Index,
    },

    Unknown {
        data: [u8; 40],
    },
}

pub struct Version {
    pub version: u8,
    pub marginals_needed: u8,
    pub completes_needed: u8,
    pub max_cert_depth: u8,
    pub model: TrustModel,
    pub min_cert_level: u8,
    pub creation_time: SystemTime,
    pub expiration_time: Option<SystemTime>,
    pub first_free: Index,
    pub hash_table: Index,
}

impl Record {
    pub fn from_buffered_reader(r: &mut dyn BufferedReader<()>)
                                -> Result<Self>
    {
        let b = &r.data_consume_hard(40)?[..40];
        let typ = b[0];

        let read_be_u32 = |v: &[u8]| -> u32 {
            debug_assert_eq!(v.len(), 4);
            let mut bytes = [0; 4];
            bytes.copy_from_slice(v);
            u32::from_be_bytes(bytes)
        };
        let read_time = |v: &[u8]| -> SystemTime {
            UNIX_EPOCH + Duration::new(read_be_u32(v).into(), 0)
        };
        let read_maybe_time = |v: &[u8]| -> Option<SystemTime> {
            let t = read_time(v);
            if t == UNIX_EPOCH { None } else { Some(t) }
        };

        match typ {
            1 => Ok(Record::Version(Version {
                version:          b[4],
                marginals_needed: b[5],
                completes_needed: b[6],
                max_cert_depth:   b[7],
                model:            b[8].into(),
                min_cert_level:   b[9],
                creation_time:    read_time(&b[12..16]),
                expiration_time:  read_maybe_time(&b[16..20]),
                first_free:       read_be_u32(&b[28..32]).into(),
                hash_table:       read_be_u32(&b[36..40]).into(),
            })),

            12 => Ok(Record::Trust {
                fingerprint: Fingerprint::from_bytes(&b[2..22]),
                ownertrust:     b[22],
                depth:          b[23],
                min_ownertrust: b[24],
                flags:          b[25],
                valid_list:     read_be_u32(&b[26..30]).into(),
            }),

            _ => {
                let mut data = [0u8; 40];
                data.copy_from_slice(b);
                Ok(Record::Unknown {
                    data,
                })
            },
        }
    }
}
