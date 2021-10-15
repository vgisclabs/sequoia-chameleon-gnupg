//! Manages keyrings and keyboxes.

use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    rc::Rc,
};

use anyhow::{anyhow, Context, Result};
use home_dir::HomeDirExt;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Fingerprint,
    KeyHandle,
    KeyID,
    parse::Parse,
};

pub struct KeyDB {
    for_gpgv: bool,
    resources: Vec<Resource>,
    initialized: bool,
    by_fp: HashMap<Fingerprint, Rc<Cert>>,
    by_id: HashMap<KeyID, Rc<Cert>>,
    by_subkey_fp: HashMap<Fingerprint, Rc<Cert>>,
    by_subkey_id: HashMap<KeyID, Rc<Cert>>,
}

#[derive(Clone)]
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
            initialized: false,
            by_fp: Default::default(),
            by_id: Default::default(),
            by_subkey_fp: Default::default(),
            by_subkey_id: Default::default(),
        }
    }

    /// Creates a KeyDB for gpgv.
    pub fn for_gpgv() -> Self {
        let mut db = Self::for_gpg();
        db.for_gpgv = true;
        db
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

    /// Looks up a cert by key handle.
    pub fn get(&self, handle: &KeyHandle) -> Option<&Cert> {
        self.by_subkey(handle)
           .or_else(|| self.by_primary(handle))
    }

    /// Looks up a cert by primary key handle.
    pub fn by_primary(&self, handle: &KeyHandle) -> Option<&Cert> {
        match handle {
            KeyHandle::Fingerprint(fp) =>
                self.by_fp.get(fp).map(AsRef::as_ref),
            KeyHandle::KeyID(id) =>
                self.by_id.get(id).map(AsRef::as_ref),
        }
    }

    /// Looks up a cert by subkey key handle.
    pub fn by_subkey(&self, handle: &KeyHandle) -> Option<&Cert> {
        match handle {
            KeyHandle::Fingerprint(fp) =>
                self.by_subkey_fp.get(fp).map(AsRef::as_ref),
            KeyHandle::KeyID(id) =>
                self.by_subkey_id.get(id).map(AsRef::as_ref),
        }
    }

    /// Initializes the store, if not already done.
    pub fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }
        self.initialized = true;

        for resource in &self.resources.clone() {
            if resource.create && ! resource.path.exists() {
                continue;
            }

            match resource.kind {
                Kind::Keyring => {
                    use openpgp::cert::CertParser;
                    for cert in CertParser::from_file(&resource.path)? {
                        let cert = cert.context(
                            format!("While parsing {:?}", resource.path))?;
                        self.insert(cert);
                    }
                },
                Kind::Keybox => {
                    use sequoia_ipc::keybox::*;
                    for record in Keybox::from_file(&resource.path)? {
                        let record = record.context(
                            format!("While parsing {:?}", resource.path))?;
                        if let KeyboxRecord::OpenPGP(r) = record {
                            self.insert(
                                r.cert().context(format!(
                                    "While parsing {:?}", resource.path))?);
                        }
                    }
                },
            }
        }

        Ok(())
    }

    /// Inserts the given cert into the database.
    fn insert(&mut self, cert: Cert) {
        let rccert = Rc::new(cert);

        let fp = rccert.fingerprint();
        let keyid = KeyID::from(&fp);
        self.by_fp.insert(fp, rccert.clone());
        self.by_id.insert(keyid, rccert.clone());

        for subkey in rccert.keys().subkeys() {
            let fp = subkey.fingerprint();
            let keyid = KeyID::from(&fp);
            self.by_subkey_fp.insert(fp, rccert.clone());
            self.by_subkey_id.insert(keyid, rccert.clone());
        }
    }
}
