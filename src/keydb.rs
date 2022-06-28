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
    serialize::SerializeInto,
};

/// Controls tracing.
const TRACE: bool = false;

#[allow(dead_code)]
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
    writable: bool,
    create: bool,
}

impl Resource {
    fn insert(&self, cert: &Cert) -> Result<()> {
        if ! self.writable {
            return Err(Error::ReadOnly.into());
        }

        if ! self.create && ! self.path.exists() {
            return Err(Error::ReadOnly.into());
        }

        if self.kind != Kind::CertD {
            return Err(Error::ReadOnly.into());
        }

        let certd = pgp_cert_d::CertD::with_base_dir(&self.path)?;
        certd.insert(cert.to_vec()?.into(), |new, old| {
            if let Some(old) = old {
                Ok(Cert::from_bytes(&old)?
                   .merge_public(Cert::from_bytes(&new)?)?
                   .to_vec()?.into())
            } else {
                Ok(new)
            }
        })?;

        Ok(())
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
#[allow(dead_code)]
pub enum Kind {
    Keybox,
    KeyboxX509,
    Keyring,
    CertD,
}

impl Kind {
    /// Guesses the kind by probing for magic bytes.
    #[allow(dead_code)]
    fn guess<P>(path: P) -> Result<Option<Self>>
    where
        P: AsRef<Path>,
    {
        tracer!(TRACE, "Kind::guess");
        t!("Guessing kind of {:?}", path.as_ref());

        if path.as_ref().is_dir() {
            // XXX: Is there a more robust way to detect cert-ds?
            return Ok(Some(Kind::CertD));
        }

        let mut magic = [0; 4];
        let mut f = fs::File::open(path)?;
        f.read_exact(&mut magic)?;

        if magic == [0x13, 0x57, 0x9a, 0xce]
            || magic == [0xce, 0x9a, 0x57, 0x13]
        {
            t!("-> No longer supported.");
            return Ok(None);
        } else {
            let mut verbuf = [0; 4];
            f.read_exact(&mut verbuf)?;
            f.read_exact(&mut magic)?;
            if verbuf[0] == 1 && &magic[..] == b"KBXf" {
                if verbuf[3] & 0x02 == 0x02 {
                    t!("-> Keybox also used for OpenPGP.");
                    return Ok(Some(Kind::Keybox));
                } else {
                    t!("-> Keybox used only for X509.");
                    return Ok(Some(Kind::KeyboxX509));
                }
            }
        }

        t!("-> Keyring.");
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
    #[allow(dead_code)]
    pub fn for_gpgv() -> Self {
        let mut db = Self::for_gpg();
        db.for_gpgv = true;
        db
    }

    #[allow(dead_code)]
    pub fn add_resource<U>(&mut self,
                           home_dir: &Path,
                           url: U,
                           read_only: bool,
                           default: bool)
                           -> Result<()>
    where
        U: AsRef<str>,
    {
        tracer!(TRACE, "KeyDB::add_resource");
        t!("home_dir {:?}, url {:?}, read_only {:?}, default {:?}",
           home_dir, url.as_ref(), read_only, default);

        let mut url = url.as_ref();
        let mut kind = None;
        let create = ! read_only && self.resources.is_empty();

        if url.starts_with("gnupg-ring:") {
            kind = Some(Kind::Keyring);
            url = &url[11..];
        } else if url.starts_with("gnupg-kbx:") {
            kind = Some(Kind::Keybox);
            url = &url[10..];
        } else if url.starts_with("pgp-cert-d:") {
            kind = Some(Kind::CertD);
            url = &url[11..];
        }

        // Expand tildes.
        let mut path = PathBuf::from(url).expand_home()?;

        // If the path contains just a single component, it is
        // relative to the home directory.
        if path.components().count() == 1 {
            path = home_dir.join(path);
        }
        t!("abolute path: {:?}", path);

        if kind.is_none() {
            t!("Kind is unknown, using heuristic");
            if path.exists() {
                kind = Kind::guess(&path)?;
                if let Some(Kind::Keyring) = kind {
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
                kind = Some(Kind::Keybox);
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
                        writable: ! read_only,
                        create,
                    }
                );
                Ok(())
            },
        }
    }

    /// Looks up a cert by key handle.
    #[allow(dead_code)]
    pub fn get(&self, handle: &KeyHandle) -> Option<&Cert> {
        tracer!(TRACE, "KeyDB::get");
        t!("{}", handle);
        self.by_subkey(handle)
           .or_else(|| self.by_primary(handle))
    }

    /// Looks up a cert by primary key handle.
    #[allow(dead_code)]
    pub fn by_primary(&self, handle: &KeyHandle) -> Option<&Cert> {
        tracer!(TRACE, "KeyDB::by_primary");
        t!("{}", handle);
        match handle {
            KeyHandle::Fingerprint(fp) =>
                self.by_fp.get(fp).map(AsRef::as_ref),
            KeyHandle::KeyID(id) =>
                self.by_id.get(id).map(AsRef::as_ref),
        }
    }

    /// Looks up a cert by subkey key handle.
    pub fn by_subkey(&self, handle: &KeyHandle) -> Option<&Cert> {
        tracer!(TRACE, "KeyDB::by_subkey");
        t!("{}", handle);
        match handle {
            KeyHandle::Fingerprint(fp) =>
                self.by_subkey_fp.get(fp).map(AsRef::as_ref),
            KeyHandle::KeyID(id) =>
                self.by_subkey_id.get(id).map(AsRef::as_ref),
        }
    }

    /// Adds a writable pgp-cert-d overlay to the resources, if not
    /// already in place.
    pub fn add_certd_overlay(&mut self) -> Result<()> {
        tracer!(TRACE, "KeyDB::add_certd_overlay");
        if let Some(topmost) = self.resources.last().cloned() {
            if topmost.writable && topmost.kind == Kind::CertD {
                t!("Writable CertD already configured.");
                return Ok(());
            }

            self.resources.push(Resource {
                path: topmost.path.with_extension("d"),
                kind: Kind::CertD,
                writable: true,
                create: true,
            });
        } else {
            return Err(Error::NoWritableResource.into()); // XXX not quite the right error
        }

        Ok(())
    }

    /// Initializes the store, if not already done.
    #[allow(dead_code)]
    pub fn initialize(&mut self) -> Result<()> {
        tracer!(TRACE, "KeyDB::initialize");
        if self.initialized {
            return Ok(());
        }
        self.initialized = true;
        t!("initializing");

        for resource in &self.resources.clone() {
            if resource.create && ! resource.path.exists() {
                continue;
            }

            match resource.kind {
                Kind::Keyring => {
                    use sequoia_openpgp_mt::keyring;
                    t!("loading keyring {:?}", resource.path);
                    for cert in keyring::parse(fs::File::open(&resource.path)?)?
                    {
                        let cert = cert.context(
                            format!("While parsing {:?}", resource.path))?;
                        self.index(cert);
                    }
                },
                Kind::Keybox => {
                    use sequoia_ipc::keybox::*;
                    t!("loading keybox {:?}", resource.path);
                    for record in Keybox::from_file(&resource.path)? {
                        let record = record.context(
                            format!("While parsing {:?}", resource.path))?;
                        if let KeyboxRecord::OpenPGP(r) = record {
                            self.index(
                                r.cert().context(format!(
                                    "While parsing {:?}", resource.path))?);
                        }
                    }
                },
                Kind::KeyboxX509 => {
                    t!("ignoring keybox {:?} only used fox X509",
                       resource.path);
                },
                Kind::CertD => {
                    t!("loading cert-d {:?}", resource.path);
                    let certd =
                        pgp_cert_d::CertD::with_base_dir(&resource.path)?;
                    for (_, _, cert) in certd.iter()? {
                        let cert = Cert::from_bytes(&cert)
                            .context(format!(
                                "While parsing {:?}", resource.path))?;
                        self.index(cert);
                    }
                },
            }
        }

        Ok(())
    }

    /// Inserts the given cert into the in-memory database.
    fn index(&mut self, cert: Cert) {
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

    /// Inserts the given cert into the database.
    ///
    /// The cert is written to the first writable resource, and the
    /// in-memory database is updated.
    pub fn insert(&mut self, cert: Cert) -> Result<()> {
        fn do_insert(db: &KeyDB, cert: &Cert) -> Result<()> {
            if let Some(r) = db.resources.iter().rev().find(|r| r.writable) {
                r.insert(cert)
            } else {
                Err(anyhow::Error::from(Error::NoWritableResource)
                    .context("Inserting cert into database failed"))
            }
        }

        if let Err(e) = do_insert(self, &cert) {
            Err(e)
        } else {
            self.index(cert);
            Ok(())
        }
    }
}

/// KeyDB-related errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("No writable key database resource configured")]
    NoWritableResource,
    #[error("Impossible to update read-only resource")]
    ReadOnly,
}
