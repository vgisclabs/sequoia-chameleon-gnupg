//! Manages keyrings and keyboxes.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use home_dir::HomeDirExt;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    crypto::hash::Digest,
    Fingerprint,
    KeyHandle,
    KeyID,
    packet::UserID,
    parse::Parse,
    serialize::SerializeInto,
    types::HashAlgorithm,
};

use crate::{
    common::Query,
};

/// Controls tracing.
const TRACE: bool = false;

#[allow(dead_code)]
pub struct KeyDB {
    for_gpgv: bool,
    resources: Vec<Resource>,
    overlay: Option<Overlay>,

    initialized: bool,
    by_fp: BTreeMap<Fingerprint, Rc<Cert>>,
    by_id: BTreeMap<KeyID, Rc<Cert>>,
    by_subkey_fp: BTreeMap<Fingerprint, Rc<Cert>>,
    by_subkey_id: BTreeMap<KeyID, Rc<Cert>>,
    by_userid: BTreeMap<UserID, BTreeSet<Fingerprint>>,
    by_email: BTreeMap<String, BTreeSet<Fingerprint>>,
}

#[derive(Clone)]
struct Resource {
    kind: Kind,
    path: PathBuf,
    create: bool,
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

        let mut f = fs::File::open(path)?;

        // If the file is empty, GnuPG always returns keyring.
        if f.metadata()?.len() == 0 {
            return Ok(Some(Kind::Keyring));
        }

        let mut magic = [0; 4];
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
            overlay: None,
            by_fp: Default::default(),
            by_id: Default::default(),
            by_subkey_fp: Default::default(),
            by_subkey_id: Default::default(),
            by_userid: Default::default(),
            by_email: Default::default(),
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

    /// Looks up certs by primary key handles.
    pub fn by_primaries<'k, I>(&self, handles: I) -> Result<Vec<&Cert>>
    where
        I: IntoIterator<Item = &'k KeyHandle>,
    {
        tracer!(TRACE, "KeyDB::by_primaries");
        let mut acc = Vec::new();
        for handle in handles {
            t!("{}", handle);
            if let Some(cert) = match handle {
                KeyHandle::Fingerprint(fp) =>
                    self.by_fp.get(fp).map(AsRef::as_ref),
                KeyHandle::KeyID(id) =>
                    self.by_id.get(id).map(AsRef::as_ref),
            } {
                acc.push(cert);
            } else {
                return Err(anyhow::anyhow!("Cert {} not found", handle));
            }
        }
        Ok(acc)
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

    /// Looks up cert candidates matching the given query.
    ///
    /// Note: The returned certs have to be validated using a trust
    /// model!
    pub fn lookup_candidates(&self, query: &Query) -> Result<Vec<&Cert>> {
        tracer!(TRACE, "KeyDB::lookup_candidates");
        t!("{}", query);
        match query {
            Query::Key(h) | Query::ExactKey(h) =>
                Ok(self.get(h).into_iter().collect()),
            Query::Email(e) =>
                Ok(self.by_email.get(e)
                   .map(|fps| fps.iter().filter_map(
                       |fp| self.by_fp.get(fp).map(AsRef::as_ref)).collect())
                   .unwrap_or_default()),
            Query::UserIDFragment(f) =>
                Ok(self.by_userid.iter()
                   .filter(|(k, _)| f.find(k.value()).is_some())
                   .flat_map(|(_, fps)| fps.iter().filter_map(
                       |fp| self.by_fp.get(fp).map(AsRef::as_ref)))
                   .collect()),
        }
    }

    /// Adds a writable pgp-cert-d overlay to the resources, if not
    /// already in place.
    pub fn add_certd_overlay(&mut self, path: &Path) -> Result<()> {
        tracer!(TRACE, "KeyDB::add_certd_overlay");
        if self.overlay.is_some() {
            t!("CertD overlay already configured.");
            return Ok(());
        }

        self.overlay = Some(Overlay::new(path)?);
        Ok(())
    }

    /// Gets the writable pgp-cert-d overlay.
    pub fn get_certd_overlay(&self) -> Result<&Overlay> {
        self.overlay.as_ref().ok_or_else(|| anyhow::anyhow!("No overlay added"))
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
                t!("skipping non-existing resource {:?}", resource.path);
                continue;
            }

            let f = fs::File::open(&resource.path)?;
            let modified = f.metadata()?.modified()?;

            // If there is a writable openpgp-cert-d overlay on top of
            // the stack.  We import all certs from our resources
            // there, and use it as a cache into the resources.

            // Get rid of sub-second precision, filetime doesn't seem
            // to set them reliably on Linux.
            let unix_time = |t: SystemTime| {
                t.duration_since(UNIX_EPOCH).unwrap().as_secs()
            };

            if self.overlay.as_ref()
                .and_then(|overlay| overlay.get_cached_mtime(&resource).ok())
                .map(|cached| unix_time(modified) == unix_time(cached))
                .unwrap_or(false)
            {
                // The overlay already contains all data from
                // this resource.
                t!("skipping up-to-date resource {:?}", resource.path);
                continue;
            }

            match resource.kind {
                Kind::Keyring => {
                    use sequoia_openpgp_mt::keyring;
                    t!("loading keyring {:?}", resource.path);
                    for cert in keyring::parse(f)?
                    {
                        let cert = cert.context(
                            format!("While parsing {:?}", resource.path))?;
                        self.insert(cert)?;
                    }
                },
                Kind::Keybox => {
                    use sequoia_ipc::keybox::*;
                    t!("loading keybox {:?}", resource.path);
                    for record in Keybox::from_reader(f)? {
                        let record = record.context(
                            format!("While parsing {:?}", resource.path))?;
                        if let KeyboxRecord::OpenPGP(r) = record {
                            self.insert(
                                r.cert().context(format!(
                                    "While parsing {:?}", resource.path))?)?;
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
                        openpgp_cert_d::CertD::with_base_dir(&resource.path)?;
                    for (_, _, cert) in certd.iter()? {
                        let cert = Cert::from_bytes(&cert)
                            .context(format!(
                                "While parsing {:?}", resource.path))?;
                        self.insert(cert)?;
                    }
                },
            }

            if let Some(overlay) = &self.overlay {
                overlay.set_cached_mtime(&resource, modified)?;
            }
        }

        // Currently, we eagerly parse all certs in the overlay.  In
        // the future, we may defer that until it is really needed
        // (e.g. for WoT computations, but not for lookup by subkey).
        if let Some(overlay) = &self.overlay {
            if let Ok(certd) = openpgp_cert_d::CertD::with_base_dir(&overlay.path) {
                use rayon::prelude::*;
                // XXX: Use upstream version of lazy_iter.
                let items = lazy_iter(&certd, &overlay.path)
                    .into_iter().flatten() // Folds errors.
                    .collect::<Vec<_>>();

                // For performance reasons, we read, parse, and
                // canonicalize certs in parallel.
                for (_fp, tag, cert) in items.into_par_iter()
                    .map(|(fp, tag, file)| {
                        // XXX: Once we have a cached tag and
                        // presumably a Sync index, avoid the work if
                        // tags match.
                        t!("loading {} from overlay", fp);
                        Ok((fp, tag, Cert::from_reader(file)?))
                    })
                    .collect::<Result<Vec<_>>>()?
                {
                    // But in the end, we insert from the main thread,
                    // because our index is not Sync.
                    self.index(cert, Some(tag));
                }
            }
        }

        Ok(())
    }

    /// Inserts the given cert into the in-memory database.
    fn index(&mut self, cert: Cert, _tag: Option<openpgp_cert_d::Tag>) {
        tracer!(TRACE, "KeyDB::index");
        t!("Inserting {} into the in-core caches", cert.fingerprint());
        let rccert = Rc::new(cert);

        let fp = rccert.fingerprint();
        let keyid = KeyID::from(&fp);
        self.by_fp.insert(fp.clone(), rccert.clone());
        self.by_id.insert(keyid, rccert.clone());

        for uidb in rccert.userids() {
            self.by_userid.entry(uidb.userid().clone())
                .or_default()
                .insert(fp.clone());

            if let Ok(Some(email)) = uidb.email() {
                self.by_email.entry(email)
                    .or_default()
                    .insert(fp.clone());
            }
        }

        for subkey in rccert.keys().subkeys() {
            let fp = subkey.fingerprint();
            let keyid = KeyID::from(&fp);
            self.by_subkey_fp.insert(fp, rccert.clone());
            self.by_subkey_id.insert(keyid, rccert.clone());
        }
    }

    /// Inserts the given cert into the database.
    ///
    /// The cert is written to the overlay resource if it exists,
    /// otherwise the cert is inserted into the in-memory database.
    pub fn insert(&mut self, cert: Cert) -> Result<()> {
        tracer!(TRACE, "KeyDB::insert");

        if let Some(overlay) = &self.overlay {
            t!("Inserting {} into the overlay", cert.fingerprint());
            overlay.certd.insert(cert.to_vec()?.into(), |new, old| {
                if let Some(old) = old {
                    Ok(Cert::from_bytes(&old)?
                       .merge_public(Cert::from_bytes(&new)?)?
                       .to_vec()?.into())
                } else {
                    Ok(new)
                }
            })?;

            // We don't index the cert, we rely on KeyDB::initialize
            // to do that when it reads in the overlay.
        } else {
            // No overlay, just index.
            self.index(cert, None);
        }
        Ok(())
    }

    /// Iterates over all certs in the database.
    pub fn iter(&self) -> impl Iterator<Item = Rc<Cert>> + '_ {
        self.by_fp.values().cloned()
    }
}

/// Like CertD::iter, but returns open `File`s.
///
/// XXX: Use the upstream version once available.
fn lazy_iter<'c>(c: &'c openpgp_cert_d::CertD, base: &'c Path)
                 -> Result<impl Iterator<Item = (String,
                                                 openpgp_cert_d::Tag,
                                                 fs::File)> + 'c> {
    Ok(c.iter_fingerprints()?.filter_map(move |fp| {
        let path = base.join(&fp[..2]).join(&fp[2..]);
        let f = fs::File::open(path).ok()?;
        let tag = f.metadata().ok()?.try_into().ok()?;
        Some((fp, tag, f))
    }))
}


pub struct Overlay {
    path: PathBuf,
    certd: openpgp_cert_d::CertD,
    #[allow(dead_code)]
    trust_root: Cert,
}

impl Overlay {
    fn new(p: &Path) -> Result<Overlay> {
        let certd = openpgp_cert_d::CertD::with_base_dir(p)?;

        // Fabricate a dummy packet header to appease the check in
        // CertD::insert_special.
        use openpgp::{
            packet::{Tag, header::*},
            serialize::Marshal,
        };
        let mut dummy = Vec::with_capacity(32 + 2);
        let h = Header::new(CTB::new(Tag::PublicKey),
                            BodyLength::Full(32));
        h.serialize(&mut dummy).unwrap();
        dummy.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0]);

        let (_, trust_root) = certd.insert_special(
            openpgp_cert_d::TRUST_ROOT,
            dummy.into(),
            |_, existing| {
                if let Some(trust_root) = existing {
                    Ok(trust_root)
                } else {
                    Self::generate_trust_root().map_err(Into::into)
                }
            })?;

        Ok(Overlay {
            path: p.into(),
            certd,
            trust_root: Cert::from_bytes(&trust_root)?,
        })
    }

    fn generate_trust_root() -> Result<openpgp_cert_d::Data> {
        use openpgp::{
            cert::CertBuilder,
            packet::signature::SignatureBuilder,
            types::SignatureType,
        };

        // XXX: It would be nice if the direct key signature would
        // also be non-exportable, but Sequoia doesn't have a way to
        // do that yet with the CertBuilder.
        let (root, _) =
            CertBuilder::new()
            .add_userid_with(
                "trust-root",
                SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_exportable_certification(false)?)?
            .generate()?;

        let tsk = root.as_tsk();
        Ok(tsk.to_vec()?.into())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[allow(dead_code)]
    fn certd_mtime(&self) -> Result<SystemTime> {
        Ok(std::fs::metadata(&self.path)?.modified()?)
    }

    fn mtime_cache_path(&self, of: &Resource) -> PathBuf {
        let mut hash = HashAlgorithm::SHA256.context()
            .expect("MTI hash algorithm");
        hash.update(of.path.to_string_lossy().as_bytes());

        let name = format!(
            "_sequoia_gpg_chameleon_mtime_{}",
            openpgp::fmt::hex::encode(
                hash.into_digest().expect("SHA2 is complete")));

        self.path.join(name)
    }

    fn get_cached_mtime(&self, of: &Resource) -> Result<SystemTime> {
        Ok(std::fs::metadata(self.mtime_cache_path(&of))?.modified()?)
    }

    fn set_cached_mtime(&self, of: &Resource, new: SystemTime)
                        -> Result<()> {
        // Make sure the overlay exists.  If we fail to create the
        // directory, caching the mtime would fail anyway, and callers
        // of this function expect a side-effect, so this seems like
        // an okay place to do that.
        std::fs::create_dir_all(&self.path)?;

        let p = self.mtime_cache_path(&of);
        let f = tempfile::NamedTempFile::new_in(&self.path)?;
        filetime::set_file_mtime(f.path(), new.into())?;
        f.persist(p)?;
        Ok(())
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
