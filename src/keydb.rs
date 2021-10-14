//! Manages keyrings and keyboxes.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use home_dir::HomeDirExt;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
};

pub struct KeyDB {
    for_gpgv: bool,
    resources: Vec<Resource>,
}

struct Resource {
    kind: Kind,
    path: PathBuf,
    create: bool,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Kind {
    Keybox,
    Keyring,
}

impl Kind {
    /// Guesses the kind by probing for magic bytes.
    fn guess<P>(path: P) -> Result<Option<Self>>
    where
        P: AsRef<Path>,
    {
        let mut magic = [0; 4];
        let mut f = fs::File::open(path)?;
        f.read_exact(&mut magic)?;

        if magic == [0x13, 0x57, 0x9a, 0xce]
            || magic == [0xce, 0x9a, 0x57, 0x13]
        {
            return Ok(None);
        } else {
            let mut verbuf = [0; 4];
            f.read_exact(&mut verbuf)?;
            f.read_exact(&mut magic)?;
            if verbuf[0] == 1 && &magic[..] == b"KBXf" {
                if verbuf[3] & 0x02 == 0x02 {
                    return Ok(Some(Kind::Keybox));
                } else {
                    return Ok(None);
                }
            }
        }

        Ok(Some(Kind::Keyring))
    }
}

impl KeyDB {
    /// Creates a KeyDB for gpg.
    pub fn for_gpg() -> Self {
        Self {
            for_gpgv: false,
            resources: Vec::default(),
        }
    }

    /// Creates a KeyDB for gpgv.
    pub fn for_gpgv() -> Self {
        Self {
            for_gpgv: true,
            resources: Vec::default(),
        }
    }

    pub fn add_resource<U>(&mut self,
                           home_dir: &Path,
                           url: U,
                           read_only: bool,
                           default: bool)
                           -> Result<()>
    where
        U: AsRef<str>,
    {
        let mut url = url.as_ref();
        let mut kind = None;
        let create = ! read_only && self.resources.is_empty();

        if url.starts_with("gnupg-ring:") {
            kind = Some(Kind::Keyring);
            url = &url[11..];
        } else if url.starts_with("gnupg-kbx:") {
            kind = Some(Kind::Keybox);
            url = &url[10..];
        }

        // Expand tildes.
        let path = PathBuf::from(url).expand_home()?;

        // Make absolute.
        let mut path = home_dir.join(path);

        if kind.is_none() {
            if path.exists() {
                if let Some(Kind::Keyring) = Kind::guess(&path)? {
                    kind = Some(Kind::Keyring);

                    // Now let us check whether in addition to the
                    // "pubring.gpg" a "pubring.kbx with openpgp keys
                    // exists.  This is so that GPG 2.1 will use an
                    // existing "pubring.kbx" by default iff that file has
                    // been created or used by 2.1.  This check is needed
                    // because after creation or use of the kbx file with
                    // 2.1 an older version of gpg may have created a new
                    // pubring.gpg for its own use.
                    if default {
                        // Check if there is also a Keybox file with the
                        // same stem.
                        let path_kbx = path.with_extension("kbx");
                        if path_kbx.exists()
                            && Kind::guess(&path_kbx)? == Some(Kind::Keybox)
                        {
                            // Prefer the keybox.
                            path = path_kbx;
                            kind = Some(Kind::Keybox);
                        }
                    }
                }
            } else if self.for_gpgv && default
                && path.extension().map(|e| e.to_string_lossy() == "gpg")
                .unwrap_or(false)
            {
                // Not found but gpgv's default "trustedkeys.kbx" file
                // has been requested.  We did not found it so now
                // check whether a "trustedkeys.gpg" file exists and
                // use that instead.

                // Check if there is also a Keyring file with the
                // same stem.
                let path_gpg = path.with_extension("gpg");
                if path_gpg.exists() {
                    if let Some(k) = Kind::guess(&path_gpg)? {
                        // Prefer that.
                        path = path_gpg;
                        kind = Some(k);
                    }
                }
            } else if default && create
                && path.extension().map(|e| e.to_string_lossy() == "gpg")
                .unwrap_or(false)
            {
                // The file does not exist, the default resource has
                // been requested, the file shall be created, and the
                // file has a ".gpg" suffix.  Change the suffix to
                // ".kbx".  This way we achieve that we open an
                // existing ".gpg" keyring, but create a new keybox
                // file with an ".kbx" suffix.
                path = path.with_extension("kbx");
            } else {
                // No file yet: create keybox.
                kind = Some(Kind::Keybox);
            }
        }

        match kind {
            None =>
                Err(anyhow!("Unknown type of key resource {:?}", path)),
            Some(kind) => {
                if ! create && ! path.exists() {
                    return
                        Err(anyhow!("Key resource {:?} does not exist", path));
                }

                self.resources.push(
                    Resource {
                        path,
                        kind,
                        create,
                    }
                );
                Ok(())
            },
        }
    }
}
