/// TrustDB implementation.
///
/// See doc/DETAILS, section "Layout of the TrustDB".

use std::{
    collections::BTreeMap,
    io::{self, BufRead},
    path::{Path, PathBuf},
    sync::Mutex,
    time::*,
};

use anyhow::{Context, Result};

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
    common::Common,
    trust::{TrustModel, OwnerTrust, OwnerTrustLevel},
};

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

/// Dispatches the --import-ownertrust command.
pub fn cmd_import_ownertrust(config: &mut crate::Config, args: &[String])
                             -> Result<()>
{
    if args.len() > 1 {
        return Err(anyhow::anyhow!("Expected only one argument, got more"));
    }

    let filename = args.get(0).cloned().unwrap_or_else(|| "-".into());
    let mut source = crate::utils::open(config, &filename)?;
    config.trustdb.import_ownertrust(&mut source)?;

    // Write the owner-trusts to our DB.
    // XXX: Currently, this is a plain text file.
    let overlay = config.keydb.get_certd_overlay()?;
    if ! overlay.path().exists() {
        // Importing ownertrust should work before the overlay has
        // been created.
        std::fs::create_dir(overlay.path())?;
    }
    let ownertrust_overlay =
        overlay.path().join("_sequoia_gpg_chameleon_ownertrust");
    config.trustdb.export_ownertrust(
        &mut std::fs::File::create(ownertrust_overlay)?)?;

    Ok(())
}

/// Dispatches the --export-ownertrust command.
pub fn cmd_export_ownertrust(config: &crate::Config, args: &[String])
                             -> Result<()>
{
    if args.len() > 0 {
        return Err(anyhow::anyhow!("Expected no arguments, got some"));
    }

    config.trustdb.export_ownertrust(&mut std::io::stdout())?;
    Ok(())
}

pub struct TrustDB {
    path: PathBuf,
    ownertrust: Mutex<BTreeMap<Fingerprint, OwnerTrust>>,
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
            ownertrust: Default::default(),
        }
    }

    pub fn path(&self, config: &Config) -> PathBuf {
        config.make_filename(&self.path)
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
                .unwrap_or_else(|| config.now()),
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
        if let Some(Record::Version(v)) = version_record {
            Ok(v)
        } else {
            Err(anyhow::anyhow!(
                "First record in TrustDB {:?} is not a version record",
                config.make_filename(&self.path)))
        }
    }

    pub fn read_ownertrust(&self, path: PathBuf) -> Result<()> {
        let mut reader = match File::open(path) {
            Ok(r) => r,
            Err(e) =>
                return if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e.into())
                },
        };

        while let Some(record) = Record::from_buffered_reader(&mut reader)? {
            match record {
                Record::Trust { fingerprint, ownertrust, .. } =>
                    self.set_ownertrust(fingerprint.clone(), ownertrust),
                _ => (),
            }
        }

        Ok(())
    }

    pub fn import_ownertrust(&self, source: &mut dyn io::Read)
                             -> Result<()> {
        for (i, line) in io::BufReader::new(source).lines().enumerate() {
            let l = line?;
            if l.is_empty() || l.starts_with("_") {
                continue;
            }
            let f = l.split(':').collect::<Vec<&str>>();
            if f.len() < 2 {
                return Err(anyhow::anyhow!(
                    "Malformed ownertrust line {}: too few fields", i));
            }
            let fp = f[0].parse()
                .with_context(|| format!("Malformed ownertrust line {}: {}",
                                         i, l))?;
            let ownertrust = f[1].parse::<u8>()
                .map_err(Into::into)
                .and_then(|v| v.try_into())
                .with_context(|| format!("Malformed ownertrust line {}: {}",
                                         i, l))?;

            self.set_ownertrust(fp, ownertrust);
        }

        Ok(())
    }

    pub fn export_ownertrust(&self, sink: &mut dyn io::Write)
                             -> Result<()> {
        for (fp, ownertrust) in self.ownertrust.lock().unwrap().iter() {
            // Skip unknown ownertrust values, like GnuPG.
            if ownertrust.level() == OwnerTrustLevel::Unknown {
                continue;
            }

            writeln!(sink, "{:X}:{}:", fp, u8::from(*ownertrust))?;
        }

        Ok(())
    }

    pub fn get_ownertrust(&self, fp: &Fingerprint) -> Option<OwnerTrust> {
        self.ownertrust.lock().unwrap().get(fp).cloned()
    }

    pub fn set_ownertrust(&self, fp: Fingerprint, ownertrust: OwnerTrust) {
        self.ownertrust.lock().unwrap().insert(fp, ownertrust);
    }

    pub fn ultimately_trusted_keys(&self) -> Vec<Fingerprint> {
        self.ownertrust.lock().unwrap().iter()
            .filter_map(|(fp, ot)| if ot.level() == OwnerTrustLevel::Ultimate {
                Some(fp.clone())
            } else {
                None
            })
            .collect()
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
#[derive(Debug)]
pub enum Record {
    Version(Version),

    Trust {
        fingerprint: Fingerprint,
        ownertrust: OwnerTrust,
        depth: u8,
        min_ownertrust: u8,
        flags: u8,
        valid_list: Index,
    },

    Unknown {
        typ: u8,
        data: [u8; 40],
    },
}

#[derive(Debug)]
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
                                -> Result<Option<Self>>
    {
        let b = match r.data_consume_hard(40) {
            Ok(v) => &v[..40],
            Err(e) =>
                return if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    Ok(None)
                } else {
                    Err(e.into())
                },
        };
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
            1 => Ok(Some(Record::Version(Version {
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
            }))),

            12 => Ok(Some(Record::Trust {
                fingerprint: Fingerprint::from_bytes(&b[2..22]),
                ownertrust:     b[22].try_into()?,
                depth:          b[23],
                min_ownertrust: b[24],
                flags:          b[25],
                valid_list:     read_be_u32(&b[26..30]).into(),
            })),

            _ => {
                let mut data = [0u8; 40];
                data.copy_from_slice(b);
                Ok(Some(Record::Unknown {
                    typ,
                    data,
                }))
            },
        }
    }
}
