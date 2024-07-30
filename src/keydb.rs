//! Manages keyrings and keyboxes.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use rusqlite::{
    Connection,
    OpenFlags,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    cert::raw::{RawCert, RawCertParser},
    crypto::hash::Digest,
    KeyHandle,
    packet::UserID,
    parse::Parse,
    types::HashAlgorithm,
};

use sequoia_cert_store as cert_store;
use cert_store::CertStore;
use cert_store::LazyCert;
use cert_store::store::{openpgp_cert_d, MergeCerts};
use cert_store::Store;
use cert_store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use sequoia_wot as wot;

use crate::{
    common::{Common, Query},
    print_error_chain,
};

trace_module!(TRACE);

#[allow(dead_code)]
pub struct KeyDB<'a> {
    for_gpgv: bool,
    resources: Vec<Resource>,
    // If the overlay is disabled, we use an in-memory certificate
    // store.
    overlay: Result<Overlay<'a>, cert_store::store::Certs<'a>>,

    initialized: bool,
}

#[derive(Clone)]
struct Resource {
    kind: Kind,
    path: PathBuf,
}

#[derive(PartialEq, Eq, Clone, Copy)]
#[allow(dead_code)]
pub enum Kind {
    Keybox,
    KeyboxX509,
    KeyboxDB,
    Keyring,
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

impl<'store> KeyDB<'store> {
    /// Creates a KeyDB for gpg.
    pub fn for_gpg() -> Self {
        Self {
            for_gpgv: false,
            resources: Vec::default(),
            initialized: false,
            overlay: Err(cert_store::store::Certs::empty()),
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
    pub fn add_resource(&mut self,
                        home_dir: &Path,
                        mut url: &str,
                        read_only: bool,
                        default: bool)
                        -> Result<()>
    {
        tracer!(TRACE, "KeyDB::add_resource");
        t!("home_dir {:?}, url {:?}, read_only {:?}, default {:?}",
           home_dir, url, read_only, default);

        let mut kind = None;
        let create = ! read_only && self.resources.is_empty();

        if url.starts_with("gnupg-ring:") {
            kind = Some(Kind::Keyring);
            url = &url[11..];
        } else if url.starts_with("gnupg-kbx:") {
            kind = Some(Kind::Keybox);
            url = &url[10..];
        } else if url.starts_with("gnupg-kbx-db:") {
            kind = Some(Kind::KeyboxDB);
            url = &url[13..];
        }

        // Expand tildes.
        let mut path = PathBuf::from(shellexpand::tilde(url).as_ref());

        if ! path.is_absolute() {
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
                if ! create && ! path.exists() && kind != Kind::KeyboxDB {
                    return
                        Err(anyhow!("Key resource {:?} does not exist", path));
                }

                self.resources.push(
                    Resource {
                        path,
                        kind,
                    }
                );
                Ok(())
            },
        }
    }

    /// Looks up cert candidates matching the given query.
    ///
    /// Note: The returned certs have to be validated using a trust
    /// model!
    pub fn lookup_candidates(&self, config: &dyn Common, query: &Query)
        -> Result<Vec<Arc<LazyCert<'store>>>>
    {
        tracer!(TRACE, "KeyDB::lookup_candidates");
        t!("{}", query);
        match query {
            Query::Key(h) | Query::ExactKey(h) =>
                self.lookup_by_cert_or_subkey(h),
            Query::Email(e) =>
                self.lookup_by_email(e),
            Query::UserIDFragment(f) =>
                self.grep_userid(f),
            Query::ExactUserID(u) =>
                self.select_userid(
                    UserIDQueryParams::new()
                        .set_anchor_start(true)
                        .set_anchor_end(true)
                        .set_email(false)
                        .set_ignore_case(false),
                    u),
        }.map(|certs| {
            for cert in &certs {
                let _ = config.status().emit(
                    crate::status::Status::KeyConsidered {
                        fingerprint: cert.fingerprint(),
                        not_selected: false,
                        all_expired_or_revoked: false,
                    });
            }
            certs
        })
    }

    /// Adds a writable pgp-cert-d overlay to the resources, if not
    /// already in place.
    pub fn add_certd_overlay(&mut self, path: &Path) -> Result<()> {
        tracer!(TRACE, "KeyDB::add_certd_overlay");
        if self.overlay.is_ok() {
            t!("CertD overlay already configured.");
            return Ok(());
        }

        self.overlay = Ok(Overlay::new(path)?);
        Ok(())
    }

    /// Gets the writable pgp-cert-d overlay.
    pub fn get_certd_overlay(&self) -> Result<&Overlay<'store>> {
        self.overlay.as_ref().map_err(|_| anyhow::anyhow!("No overlay added"))
    }

    // Initialize a keyring.
    fn initialize_keyring<P>(&mut self, file: fs::File, path: P)
        -> Result<Vec<LazyCert<'store>>>
        where P: AsRef<Path>,
    {
        tracer!(TRACE, "KeyDB::initialize_keyring");
        let path = path.as_ref();
        t!("loading keyring {:?}", path);

        let results = {
            let iter = match RawCertParser::from_reader(file) {
                Ok(iter) => iter,
                Err(err) => {
                    let err = anyhow::Error::from(err).context(
                        format!("Loading keyring {:?}", path));
                    print_error_chain(&err);
                    return Err(err);
                }
            };

            iter.filter_map(|cert| {
                match cert {
                    Ok(cert) => Some(LazyCert::from(cert)),
                    Err(err) => {
                        let err = anyhow::Error::from(err).context(format!(
                            "While parsing cert from keyring {:?}", path));
                        print_error_chain(&err);
                        None
                    }
                }
            }).collect()
        };

        Ok(results)
    }

    // Initialize a keybox.
    fn initialize_keybox<P>(&mut self, file: fs::File, path: P)
        -> Result<Vec<LazyCert<'store>>>
        where P: AsRef<Path>,
    {
        use sequoia_ipc::keybox::*;

        tracer!(TRACE, "KeyDB::initialize_keybox");
        let path = path.as_ref();
        t!("loading keybox {:?}", path);

        let iter = match Keybox::from_reader(file) {
            Ok(iter) => iter,
            Err(err) => {
                let err = anyhow::Error::from(err).context(format!(
                    "While opening keybox at {:?}", path));
                print_error_chain(&err);
                return Err(err);
            }
        };

        let results = iter.filter_map(|record| {
            let record = match record {
                Ok(record) => record,
                Err(err) => {
                    let err = anyhow::Error::from(err).context(format!(
                        "While parsing a record from keybox {:?}", path));
                    print_error_chain(&err);
                    return None;
                }
            };

            if let KeyboxRecord::OpenPGP(record) = record {
                match record.cert() {
                    Ok(cert) => Some(LazyCert::from(cert)),
                    Err(err) => {
                        let err = anyhow::Error::from(err).context(format!(
                            "While parsing a cert from keybox {:?}", path));
                        print_error_chain(&err);
                        None
                    }
                }
            } else {
                None
            }
        }).collect();

        Ok(results)
    }

    /// Initialize a keybox database.
    fn initialize_keybox_db<P>(&mut self, path: P)
        -> Result<Vec<LazyCert<'store>>>
        where P: AsRef<Path>,
    {
        tracer!(TRACE, "KeyDB::initialize_keybox_db");
        let path = path.as_ref();
        t!("loading keybox database at {}", path.display());

        let conn = Connection::open_with_flags(
            &path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

        let mut stmt = conn.prepare("SELECT keyblob \
                                     FROM pubkey \
                                     WHERE type = 1")?;

        let certs = stmt.query_map([], |row| Ok(row.get::<_, Vec<u8>>(0)?))?
            .filter_map(|bytes| {
                let bytes = std::io::Cursor::new(bytes.ok()?);
                let cert = RawCert::from_reader(bytes).ok()?;
                t!("loaded {}", cert.fingerprint());
                Some(cert.into())
            })
            .collect();
        drop(stmt);

        Ok(certs)
    }

    /// Initializes the store, if not already done.
    #[allow(dead_code)]
    pub fn initialize(&mut self, lazy: bool) -> Result<()> {
        self._initialize(lazy, false)
    }

    /// Re-Initializes the store.
    ///
    /// Calling this function picks up changes in any of the
    /// resources.
    #[allow(dead_code)]
    pub fn reinitialize(&mut self, lazy: bool) -> Result<()> {
        self._initialize(lazy, true)
    }

    fn _initialize(&mut self, lazy: bool, force: bool) -> Result<()> {
        tracer!(TRACE, "KeyDB::_initialize");
        if self.initialized && ! force {
            return Ok(());
        }
        self.initialized = true;
        t!("initializing");

        for resource in &self.resources.clone() {
            if ! resource.path.exists() {
                t!("{}: skipping non-existing resource", resource.path.display());
                continue;
            }

            let f = fs::File::open(&resource.path);
            let modified = match &f {
                Ok(f) => Some(f.metadata()?.modified()?),
                Err(_) => None,
            };
            t!("{}: last modified {:?}", resource.path.display(), modified);

            // If there is a writable openpgp-cert-d overlay on top of
            // the stack.  We import all certs from our resources
            // there, and use it as a cache into the resources.

            // Get rid of sub-second precision, filetime doesn't seem
            // to set them reliably on Linux.
            let unix_time = |t: SystemTime| {
                t.duration_since(UNIX_EPOCH).unwrap().as_secs()
            };

            if self.overlay.as_ref().ok()
                .and_then(|overlay| overlay.get_cached_mtime(&resource).ok())
                .map(|cached| modified.map(unix_time) == Some(unix_time(cached)))
                .unwrap_or(false)
            {
                // The overlay already contains all data from
                // this resource.
                t!("{}: skipping up-to-date resource", resource.path.display());
                continue;
            }

            let certs = match resource.kind {
                Kind::Keyring => {
                    self.initialize_keyring(f?, &resource.path)
                        .with_context(|| format!(
                            "Reading the keyring {:?}", resource.path))
                },
                Kind::Keybox => {
                    self.initialize_keybox(f?, &resource.path)
                        .with_context(|| format!(
                            "Reading the keybox {:?}", resource.path))
                },
                Kind::KeyboxX509 => {
                    t!("ignoring keybox {:?} only used fox X509",
                       resource.path);
                    Ok(Vec::new())
                },
                Kind::KeyboxDB => {
                    self.initialize_keybox_db(&resource.path)
                        .with_context(|| format!(
                            "{}: reading the keybox database",
                            resource.path.display()))
                },
            };

            match certs {
                Ok(certs) => {
                    for cert in certs.into_iter() {
                        let keyid = cert.keyid();
                        if let Err(err) = self.update(Arc::new(cert)) {
                            let err = anyhow::Error::from(err)
                                .context(format!(
                                    "Reading {} from {:?}",
                                    keyid, resource.path));
                            print_error_chain(&err);
                            continue;
                        }
                    }
                }
                Err(err) => print_error_chain(&err),
            }

            if let (Ok(overlay), Some(modified)) = (&self.overlay, modified) {
                overlay.set_cached_mtime(&resource, modified)?;
            }
        }

        if ! lazy {
            match self.overlay.as_mut() {
                Ok(overlay) => overlay.cert_store.prefetch_all(),
                Err(certs) => certs.prefetch_all(),
            }
        }

        Ok(())
    }
}

pub struct Overlay<'store> {
    pub(crate) cert_store: CertStore<'store>,
}

impl<'store> Overlay<'store> {
    fn new(p: &Path) -> Result<Overlay<'store>> {
        use std::fs::DirBuilder;

        let mut builder = DirBuilder::new();
        builder.recursive(true);
        platform!{
            unix => {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            },
            windows => {
                // XXX: Do we need to do something special on Windows
                // to adjust the permissions?
            },
        }
        let create_dir_result = builder.create(p);

        let cert_store = match CertStore::open(p) {
            Ok(cert_store) => cert_store,
            Err(err) => {
                if let Err(err) = create_dir_result {
                    // We can't return two error messages.  Print one here.
                    let err = anyhow::Error::from(err)
                        .context(format!("Creating {:?}", p));
                    print_error_chain(&err);
                }

                return Err(err).context(format!("Opening cert-d at {:?}", p));
            }
        };

        Ok(Overlay {
            cert_store,
        })
    }

    /// Returns the low-level `CertD`.
    pub fn certd(&self) -> &openpgp_cert_d::CertD {
        self.cert_store
            .certd().expect("created using CertStore::open")
            .certd()
    }

    /// Lazily reads (or creates) the trust root.
    pub fn trust_root(&self) -> Result<Arc<LazyCert<'store>>> {
        self.cert_store
            .certd().expect("created using CertStore::open")
            .trust_root()
            .map(move |(cert, _created)| cert)
    }

    pub fn path(&self) -> &Path {
        self.certd().base_dir()
    }

    fn mtime_cache_path(&self, of: &Resource) -> PathBuf {
        let mut hash = HashAlgorithm::SHA256.context()
            .expect("MTI hash algorithm");
        hash.update(of.path.to_string_lossy().as_bytes());

        let name = format!(
            "_sequoia_gpg_chameleon_mtime_{}",
            openpgp::fmt::hex::encode(
                hash.into_digest().expect("SHA2 is complete")));

        self.path().join(name)
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
        std::fs::create_dir_all(self.path())?;

        let p = self.mtime_cache_path(&of);
        let f = tempfile::NamedTempFile::new_in(self.path())?;
        filetime::set_file_mtime(f.path(), new.into())?;
        f.persist(p)?;
        Ok(())
    }
}

macro_rules! forward {
    ( $method:ident, $self:expr $(, $args:ident)* ) => {{
        match $self.overlay.as_ref() {
            Ok(be) => be.cert_store.$method($($args),*),
            Err(be) => be.$method($($args),*),
        }
    }}
}

impl<'a> cert_store::store::Store<'a> for KeyDB<'a> {
    fn lookup_by_cert(&self, kh: &KeyHandle) -> Result<Vec<Arc<LazyCert<'a>>>> {
        forward!(lookup_by_cert, self, kh)
    }

    fn lookup_by_cert_fpr(&self, fingerprint: &Fingerprint) -> Result<Arc<LazyCert<'a>>>
    {
        forward!(lookup_by_cert_fpr, self, fingerprint)
    }

    fn lookup_by_cert_or_subkey(&self, kh: &KeyHandle) -> Result<Vec<Arc<LazyCert<'a>>>> {
        forward!(lookup_by_cert_or_subkey, self, kh)
    }

    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Arc<LazyCert<'a>>>>
    {
        forward!(select_userid, self, query, pattern)
    }

    fn lookup_by_userid(&self, userid: &UserID) -> Result<Vec<Arc<LazyCert<'a>>>> {
        forward!(lookup_by_userid, self, userid)
    }

    fn grep_userid(&self, pattern: &str) -> Result<Vec<Arc<LazyCert<'a>>>> {
        forward!(grep_userid, self, pattern)
    }

    fn lookup_by_email(&self, email: &str) -> Result<Vec<Arc<LazyCert<'a>>>> {
        forward!(lookup_by_email, self, email)
    }

    fn grep_email(&self, pattern: &str) -> Result<Vec<Arc<LazyCert<'a>>>> {
        forward!(grep_email, self, pattern)
    }

    fn lookup_by_email_domain(&self, domain: &str) -> Result<Vec<Arc<LazyCert<'a>>>> {
        forward!(lookup_by_email_domain, self, domain)
    }

    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        forward!(fingerprints, self)
    }

    fn certs<'b>(&'b self) -> Box<dyn Iterator<Item=Arc<LazyCert<'a>>> + 'b>
        where Self: 'b
    {
        forward!(certs, self)
    }

    fn prefetch_all(&self) {
        forward!(prefetch_all, self)
    }

    fn prefetch_some(&self, certs: &[KeyHandle]) {
        forward!(prefetch_some, self, certs)
    }
}

impl<'a> cert_store::store::StoreUpdate<'a> for KeyDB<'a> {
    fn update(&self, cert: Arc<LazyCert<'a>>) -> Result<()> {
        forward!(update, self, cert)
    }

    fn update_by(&self, cert: Arc<LazyCert<'a>>,
                 merge_strategy: &dyn MergeCerts<'a>)
        -> Result<Arc<LazyCert<'a>>>
    {
        forward!(update_by, self, cert, merge_strategy)
    }
}

impl<'a> wot::store::Backend<'a> for KeyDB<'a> {
}

/// KeyDB-related errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("No writable key database resource configured")]
    NoWritableResource,
    #[error("Impossible to update read-only resource")]
    ReadOnly,
}
