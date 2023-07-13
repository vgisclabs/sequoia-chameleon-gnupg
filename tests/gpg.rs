use std::{
    cell::RefCell,
    collections::BTreeMap,
    fmt,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::*,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use regex::bytes::Regex;
use serde::{Serialize, Deserialize};

use serde_with::serde_as;

use sequoia_openpgp as openpgp;

/// Produces the fully qualified function name.
macro_rules! function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        &name[..name.len() - 3]
    }}
}

macro_rules! make_experiment {
    ($($i: expr),*) => {{
        Experiment::new(function!(), vec![$($i.to_string()),*])
    }}
}

mod gpg {
    mod decrypt;
    mod encrypt;
    mod sign;
    mod verify;
    mod list_keys;
    mod version;
    mod trust_models;
    mod status_fd;
    mod print_mds;
    mod list_packets;
    mod export_ssh_key;
}

lazy_static::lazy_static! {
    static ref GPG: Vec<String> =
        vec![std::env::var("REAL_GPG_BIN")
             .unwrap_or("/usr/bin/gpg".into())];
}

lazy_static::lazy_static! {
    static ref GPGV: Vec<String> =
        vec![std::env::var("REAL_GPGV_BIN")
             .unwrap_or("/usr/bin/gpgv".into())];
}

lazy_static::lazy_static! {
    static ref GPG_CHAMELEON: Vec<String> =
        vec![
            if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
                PathBuf::from(target)
            } else {
                std::env::current_dir().unwrap()
                    .join("target")
            }
            .join("debug/gpg-sq")
            .display().to_string()
        ];
}

lazy_static::lazy_static! {
    static ref GPGV_CHAMELEON: Vec<String> =
        vec![
            if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
                PathBuf::from(target)
            } else {
                std::env::current_dir().unwrap()
                    .join("target")
            }
            .join("debug/gpgv-sq")
            .display().to_string()
        ];
}

const GPG_CHAMELEON_BUILD: &[&str] = &["cargo", "build", "--quiet"];

pub const STDOUT_EDIT_DISTANCE_THRESHOLD: usize = 20;
pub const STDERR_EDIT_DISTANCE_THRESHOLD: usize = 20;

/// Sets up the test environment.
fn setup() {
    build();
}

/// Makes sure that we're talking to the right oracle.
fn check_gpg_oracle() {
    use std::sync::Once;

    static START: Once = Once::new();
    START.call_once(|| {
        eprintln!("Checking that {:?} is the stock GnuPG...",
                  &GPG[0]);

        let o = Command::new(&GPG[0])
            .arg("--version").output().unwrap();
        if String::from_utf8_lossy(&o.stdout[..o.stdout.len().min(256)])
            .contains("equoia")
        {
            panic!("The oracle {:?} is Sequoia-based, please provide the \
                    stock gpg in REAL_GPG_BIN", GPG[0]);
        }

        let o = Command::new(&GPGV[0])
            .arg("--version").output().unwrap();
        if String::from_utf8_lossy(&o.stdout[..o.stdout.len().min(256)])
            .contains("equoia")
        {
            panic!("The oracle {:?} is Sequoia-based, please provide the \
                    stock gpg in REAL_GPGV_BIN", GPGV[0]);
        }
    });
}

/// Makes sure that the chameleon is built once.
fn build() {
    use std::sync::Once;

    static START: Once = Once::new();
    START.call_once(|| {
        let mut prog = GPG_CHAMELEON_BUILD.to_vec();

        if cfg!(feature = "crypto-nettle") {
            prog.push("--no-default-features");
            prog.push("--features=crypto-nettle");
        } else if cfg!(feature = "crypto-openssl") {
            prog.push("--no-default-features");
            prog.push("--features=crypto-openssl");
        } else if cfg!(feature = "crypto-botan") {
            prog.push("--no-default-features");
            prog.push("--features=crypto-botan");
        } else if cfg!(feature = "crypto-botan2") {
            prog.push("--no-default-features");
            prog.push("--features=crypto-botan2");
        } else if cfg!(feature = "crypto-cng") {
            prog.push("--no-default-features");
            prog.push("--features=crypto-cng");
        }

        eprintln!("Spawning {:?} to build the chameleon...",
                  prog);

        let mut c = std::process::Command::new(&prog[0]);
        c.args(prog[1..].iter());
        let status = c.status().unwrap();
        if ! status.success() {
            panic!("Building the chameleon failed: {:?}", status);
        }
    });
}

/// A context for GnuPG.
///
/// Creates a temporary directory and cleans it up on Drop.
pub struct Context {
    // How to invoke gpg or gpg-sq.
    //
    // gpg[0] is the executable and the rest are arguments that are
    // implicitly passed to it.
    gpg: Vec<String>,

    // Like `gpg`, but for gpgv or gpgv-sq.
    gpgv: Vec<String>,

    /// What is passed to --homedir.
    home: tempfile::TempDir,
}

impl Context {
    const GPG_AGENT_CONF: &str = "allow-loopback-pinentry\n\
                                  ";

    /// Returns a context for the reference GnuPG implementation.
    pub fn gnupg() -> Result<Self> {
        Context::new(GPG.clone(), GPGV.clone())
    }

    /// Returns a context for the chameleon.
    pub fn chameleon() -> Result<Self> {
        setup();
        Context::new(GPG_CHAMELEON.clone(), GPGV_CHAMELEON.clone())
    }

    /// Returns a custom context for the given GnuPG-like executable.
    pub fn new(gpg: Vec<String>, gpgv: Vec<String>) -> Result<Self> {
        let ctx = Context {
            gpg,
            gpgv,
            home: tempfile::tempdir()?,
        };
        ctx.store("gpg-agent.conf", Self::GPG_AGENT_CONF)?;
        Ok(ctx)
    }

    /// Stores the given data in the home directory, and returns the
    /// absolute path to that file.
    ///
    /// Useful for building up invocations.
    pub fn store(&self, name: &str, data: impl AsRef<[u8]>) -> Result<String> {
        let path = self.home.path().join(name);
        fs::write(&path, data)?;
        Ok(path.to_str().unwrap().into())
    }

    /// Invokes the GnuPG implementation with the given arguments.
    ///
    /// The output of the invocation (stdout and stderr) as well as
    /// any files created under the current directory are returned in
    /// an instance of `Output`.
    pub fn invoke(&self, args: &[&str]) -> Result<Output> {
        // See if the user wants gpg or gpgv.
        let (executable, args) =
            if args[0] == "gpgv" {
                (&self.gpgv, &args[1..])
            } else if args[0] == "gpg" {
                (&self.gpg, &args[1..])
            } else {
                // Implicitly select gpg.
                (&self.gpg, &args[..])
            };

        // We're going to change directories before execve(2)ing in
        // the child, so make sure the path is absolute.
        let exe = fs::canonicalize(&executable[0])?;
        let mut c = Command::new(&exe);
        c.env("LC_ALL", "C");
        c.env("TZ", "Africa/Nairobi"); // EAT, no DST.
        c.env("SEQUOIA_CRYPTO_POLICY", // Use a null policy.
              format!("{}/tests/null-policy.toml",
                      env!("CARGO_MANIFEST_DIR")));
        let workdir = tempfile::TempDir::new()?;
        c.current_dir(workdir.path());
        for arg in &executable[1..] {
            c.arg(arg);
        }
        c.arg("--homedir").arg(self.home.path());

        // IPC.  Stdin, stdout, and stderr we handle using the std
        // library.
        c.stdin(Stdio::piped());
        c.stdout(Stdio::piped());
        c.stderr(Stdio::piped());

        use interprocess::unnamed_pipe::pipe;
        use std::os::unix::io::AsRawFd;
        let (writer, mut reader) = pipe()?;
        c.arg(format!("--status-fd={}", writer.as_raw_fd()));

        // Be nice and close one end of the pipe in the child process.
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::io::FromRawFd;
            use std::os::unix::process::CommandExt;
            let reader_fd = reader.as_raw_fd();
            unsafe {
                c.pre_exec(move || {
                    drop(fs::File::from_raw_fd(reader_fd));
                    Ok(())
                });
            }
        }

        // Finish the arguments and start the process.
        for arg in args {
            c.arg(arg);
        }
        eprintln!("Spawning {:?} {:?}...", exe, c.get_args());
        let mut child = c.spawn()?;

        // Now handle the status-fd pipe.
        drop(writer);
        let status_fd_reader = std::thread::spawn(move || {
            let mut v = Vec::new();
            reader.read_to_end(&mut v).map(|_| v)
        });

        // Handle stdin.
        drop(child.stdin.take());

        // Collect outputs, synchronize.
        let out = child.wait_with_output()?;
        let statusfd = status_fd_reader.join().unwrap()?;

        // Collect any output produced in the working directory.
        let mut files = BTreeMap::default();
        for entry in fs::read_dir(&workdir)? {
            let path = entry?.path();
            files.insert(path.file_name().unwrap().to_str().unwrap().into(),
                         fs::read(&path)?);
        }

        Ok(Output {
            args: args.into_iter().map(ToString::to_string).collect(),
            stdout: out.stdout,
            stderr: out.stderr,
            statusfd,
            status: out.status.to_string(),
            files,
        })
    }
}

/// A dummy type so that we can serialize a Vec<u8> as an
/// STFU8-encoded string.
///
/// By encoding `Vec<u8>` using STFU8, we make the output files human
/// readable instead of an opaque array of integers `[100,101,94,
/// ... ]`.  This is great for examining what exactly the output was
/// without using any special tools.
struct Stfu8Bytes {
}

impl serde_with::SerializeAs<Vec<u8>> for Stfu8Bytes
{
    fn serialize_as<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&stfu8::encode_u8(bytes))
    }
}

impl<'de> serde_with::DeserializeAs<'de, Vec<u8>> for Stfu8Bytes
{
    fn deserialize_as<D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // `SeqIter` is inspired by serde_with's version, which is
        // under the Apache-2.0 or MIT license.
        //
        // https://github.com/jonasbb/serde_with/blob/e010b09/serde_with/src/utils.rs#L71-L105
        struct SeqIter<'de, A, T> {
            access: A,
            marker: std::marker::PhantomData<(&'de (), T)>,
        }

        impl<'de, A, T> SeqIter<'de, A, T> {
            fn new(access: A) -> Self
            where
                A: serde::de::SeqAccess<'de>,
            {
                Self {
                    access,
                    marker: std::marker::PhantomData,
                }
            }
        }

        impl<'de, A, T> Iterator for SeqIter<'de, A, T>
        where
            A: serde::de::SeqAccess<'de>,
            T: Deserialize<'de>,
        {
            type Item = Result<T, A::Error>;

            fn next(&mut self) -> Option<Self::Item> {
                self.access.next_element().transpose()
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                match self.access.size_hint() {
                    Some(size) => (size, Some(size)),
                    None => (0, None),
                }
            }
        }


        struct Stfu8BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for Stfu8BytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>)
                -> fmt::Result
            {
                formatter.write_str("a [u8] or a String")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                Ok(bytes.to_vec())
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(v)
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where E: serde::de::Error
            {
                Ok(stfu8::decode_u8(s).map_err(serde::de::Error::custom)?)
            }

            fn visit_string<E>(self, s: String)
                -> Result<Self::Value, E>
                where E: serde::de::Error
            {
                Ok(stfu8::decode_u8(&s).map_err(serde::de::Error::custom)?)
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                SeqIter::new(seq).collect()
            }
        }
        deserializer.deserialize_any(Stfu8BytesVisitor)
    }
}

/// The output of an invocation of some command.
///
/// This is returned by `Context::invoke`.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output {
    /// The command that was run as well as the arguments.
    ///
    /// This is the unnormalized command.  That is, args[0] is not
    /// mapped to the actual implementation that is used.
    args: Vec<String>,

    /// The captured stderr and stdout.
    #[serde_as(as = "Stfu8Bytes")]
    stderr: Vec<u8>,
    #[serde_as(as = "Stfu8Bytes")]
    stdout: Vec<u8>,
    #[serde(default)]
    #[serde_as(as = "Stfu8Bytes")]
    statusfd: Vec<u8>,

    /// The status code, e.g., "exit status: 0".
    status: String,

    /// Any files that are produced by the invocation under the
    /// working directory.
    #[serde_as(as = "BTreeMap<_, Stfu8Bytes>")]
    files: BTreeMap<String, Vec<u8>>,
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stdout:\n{}\n\nstderr:\n{}\n\nstatus: {}",
               String::from_utf8_lossy(&self.stdout),
               String::from_utf8_lossy(&self.stderr),
               self.status)
    }
}

impl Output {
    /// Returns whether the invocation was successful.
    fn success(&self) -> bool {
        self.status == "exit status: 0"
    }

    /// Canonicalizes the paths in the output.
    ///
    /// This replaces `homedir` with `"/HOMEDIR"` and `experiment`
    /// with `"/EXPERIMENT"` in stdout and stderr, and normalizes the
    /// underline decorating `homedir` in key listings in stdout.
    fn canonicalize(mut self, homedir: &Path, experiment: &Path) -> Self {
        const DASHES: &str =
            "\n------------------------------------------------------------";
        let d = regex::bytes::Regex::new(
            &DASHES[..DASHES.len().min(homedir.to_str().unwrap().len() + 1)])
            .unwrap();
        let h = regex::bytes::Regex::new(homedir.to_str().unwrap()).unwrap();
        let e = regex::bytes::Regex::new(experiment.to_str().unwrap()).unwrap();
        self.stdout =
            e.replace_all(
                &h.replace_all(
                    &d.replace_all(&self.stdout, &b"\n--------"[..]),
                    &b"/HOMEDIR"[..]),
                &b"/EXPERIMENT"[..])
            .into();
        self.stderr =
            e.replace_all(&h.replace_all(&self.stderr, &b"/HOMEDIR"[..]),
                          &b"/EXPERIMENT"[..])
            .into();

        // Normalize key listing headers.
        let keylisting = Regex::new("/HOMEDIR/pubring.cert.d\\n\
                                     -----------------------").unwrap();
        self.stdout = keylisting.replace(&self.stdout,
                                         &b"/HOMEDIR/pubring.kbx\n\
                                            ---------------------"[..]).into();

        // According to doc/DETAILS, "This [KEYEXPIRED] status line is
        // not very useful because it will also be emitted for expired
        // subkeys even if this subkey is not used."  And indeed,
        // GnuPG emits this left, right, and center whenever it
        // encounters an expired key, without any context, without
        // being useful for anyone.  Drop it, as we don't emit it.
        let keyexpired =
            Regex::new(r"\[GNUPG:\] KEYEXPIRED [^\n]*\n").unwrap();
        self.statusfd =
            keyexpired.replace_all(&self.statusfd, &b""[..]).into();

        self
    }

    /// Returns the edit distance of run's stdout with the given one.
    pub fn stdout_edit_distance(&self, to: &Self) -> usize {
        editdistancek::edit_distance(&self.stdout, &to.stdout)
    }

    /// Returns the edit distance of run's stderr with the given one.
    pub fn stderr_edit_distance(&self, to: &Self) -> usize {
        editdistancek::edit_distance(&self.stderr, &to.stderr)
    }

    /// Returns the edit distance of run's status-fd with the given one.
    pub fn statusfd_edit_distance(&self, to: &Self) -> usize {
        editdistancek::edit_distance(&self.statusfd, &to.statusfd)
    }

    /// Invokes a callback with the working directory.
    pub fn with_working_dir<F, T>(&self, fun: &mut F) -> Result<T>
    where
        F: FnMut(&BTreeMap<String, Vec<u8>>) -> Result<T>,
    {
        fun(&self.files)
    }
}

#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
struct ArtifactStore {
    /// The oracle's output.
    outputs: Vec<Output>,
    /// Our previous invocations' output.
    former_us_outputs: Option<Vec<Output>>,
    /// The files created by the invocation below the working
    /// directory.
    #[serde_as(as = "BTreeMap<_, Stfu8Bytes>")]
    artifacts: BTreeMap<String, Vec<u8>>,

    /// Difference to the Chameleon's stderr and stdout at the time
    /// this output was recorded.
    #[serde(default)]
    dynamic_upper_bounds: Vec<Vec<usize>>,
}

impl ArtifactStore {
    fn load(path: &Path) -> Result<Self> {
        let mut f = match fs::File::open(&path) {
            Ok(f) => f,
            Err(err) => {
                eprintln!("Opening artifact store {:?}: {}",
                          path, err);
                return Err(err.into());
            }
        };

        match serde_json::from_reader(&mut f) {
            Ok(r) => Ok(r),
            Err(err) => {
                eprintln!("Reading artifact store {:?}: {}",
                          path, err);
                Err(err.into())
            }
        }
    }

    fn store(&self, path: &Path) -> Result<()> {
        fs::create_dir_all(path.parent().unwrap())?;
        let mut f = fs::File::create(path)?;
        serde_json::to_writer_pretty(&mut f, self)?;
        Ok(())
    }
}

/// A bisimulation framework.
///
/// Runs the reference GnuPG and the Chameleon in tandem, observing
/// the differences.
pub struct Experiment {
    wd: tempfile::TempDir,
    /// A record of what actions were performed (storing a file,
    /// invoking a command) and their order.
    log: std::cell::RefCell<Vec<Action>>,
    /// We store the output of GnuPG so that we don't build-depend on
    /// it.
    artifacts: ArtifactStore,
    artifacts_store: PathBuf,
    oracle: Context,
    us: Context,

    /// Canonicalization rules.
    canonicalizations: Vec<Canonicalization>,
}

impl Drop for Experiment {
    fn drop(&mut self) {
        let _ = self.artifacts.store(&self.artifacts_store);
    }
}

/// An experiment consists of a number of actions, which are executed
/// in order.
enum Action {
    /// Store a file in the working directory.
    Store(PathBuf),
    /// Invoke a command.
    Invoke(Vec<String>),
}

impl Experiment {
    /// Creates a new experiment with empty state directories.
    pub fn new(function: &str, parameters: Vec<String>) -> Result<Self> {
        let mut path: PathBuf =
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(function
                  // Added by ntest.
                  .strip_suffix("::ntest_callback").unwrap_or(function)
                  // Drop the extra "gpg::".
                  [5..]
                  // Turn it into a relative path.
                  .replace("::", &std::path::MAIN_SEPARATOR.to_string()));
        for parameter in parameters {
            path.push(parameter);
        }
        let artifacts_store = path.with_extension("json");

        // Load the stored artifacts, if any.
        let artifacts =
            ArtifactStore::load(&artifacts_store).unwrap_or_default();

        Ok(Experiment {
            wd: tempfile::tempdir()?,
            log: Default::default(),
            artifacts,
            artifacts_store,
            oracle: Context::gnupg()?,
            us: Context::chameleon()?,
            canonicalizations: Default::default(),
        })
    }

    /// Creates or loads an artifact for the experiment.
    pub fn artifact<C, S, L, T>(&mut self, name: &str,
                                mut create: C, mut store: S, load: L)
                                -> Result<T>
    where
        C: FnMut() -> Result<T>,
        S: FnMut(&T, &mut Vec<u8>) -> Result<()>,
        L: FnMut(&Vec<u8>) -> Result<T>,
    {
        self.artifacts.artifacts.get(name)
            .ok_or_else(|| anyhow::anyhow!("Not found, need to create it"))
            .and_then(load)
            .or_else(|_| {
                let a = create()?;
                let mut b = Vec::new();
                store(&a, &mut b)?;
                self.artifacts.artifacts.insert(name.into(), b);
                Ok(a)
            })
    }

    /// Returns the reference time of this experiment.
    pub fn now() -> SystemTime {
        UNIX_EPOCH + Duration::new(1671553073, 0)
    }

    /// Invokes the given command on both implementations.
    pub fn invoke(&mut self, args: &[&str]) -> Result<Diff> {
        // Get the number of commands invoked in this experiment.  We
        // use this to enumerate the stored artifacts.
        let n = self.log.borrow().iter()
            .filter(|a| if let Action::Invoke(_) = a { true } else { false })
            .count();

        // Implicitly add --faked-system-time.
        let faked_system_time = vec![
            format!("--faked-system-time={}!",
                    Self::now().duration_since(UNIX_EPOCH)?.as_secs()),
        ];
        let args: Vec<&str> = if args[0] == "gpgv" {
            args.iter().cloned().collect()
        } else if args[0] == "gpg" {
            std::iter::once("gpg")
                .chain(faked_system_time.iter().map(|s| s.as_str()))
                .chain(args.iter().skip(1).cloned())
                .collect()
        } else {
            faked_system_time.iter().map(|s| s.as_str())
                .chain(args.iter().cloned())
                .collect()
        };

        self.log.borrow_mut().push(
            Action::Invoke(args.iter().map(ToString::to_string).collect()));

        // See if we have a stored artifact and whether it matches our
        // arguments.
        let normalized_args: Vec<String> =
            args.iter().map(|a| {
                // Normalize the experiment's working directory.
                format!("{:?}", a)
                    .replace(&self.wd.path().display().to_string(),
                             "/EXPERIMENT")
            })
            .collect();

        let what = if args[0] == "gpgv" {
            "gpgv"
        } else {
            "gpg"
        };
        eprintln!("Invoking {:?} {}", what, normalized_args.join(" "));

        // First, invoke the Chameleon.
        eprintln!("Invoking the chameleon");
        let mut us = self.us.invoke(&args)?
            .canonicalize(self.us.home.path(), self.wd.path());
        self.canonicalizations.iter().for_each(|c| c.apply(&mut us));

        us.args = normalized_args.clone();

        let use_cache = std::env::var_os("GPG_SQ_IGNORE_CACHE").is_none();
        let former_us = if let Some(o) = self.artifacts
            .former_us_outputs.as_ref()
            .and_then(|o| o.get(n))
            .filter(|v| v.args == normalized_args)
            .filter(|_| use_cache)
        {
            eprintln!("Have previous output from the chameleon");
            Some(o.clone())
        } else {
            // Save the current output for the next run.
            eprintln!("No previous output from the chameleon");
            if self.artifacts.former_us_outputs.is_none() {
                self.artifacts.former_us_outputs = Some(Vec::new());
            }
            let o = self.artifacts.former_us_outputs.as_mut().expect("have it");
            o.truncate(n);
            o.push(us.clone());

            None
        };

        // Then, invoke GnuPG if we don't have a cached artifact.
        let oracle = if let Some(o) = self.artifacts.outputs.get(n)
            .filter(|v| v.args == normalized_args)
            .filter(|_| use_cache)
        {
            eprintln!("Not invoking the oracle: using cached results");
            o.clone()
        } else {
            // Cache miss or the arguments changed.
            check_gpg_oracle();
            eprintln!("Invoking the oracle");
            let mut output = self.oracle.invoke(&args)?
                .canonicalize(self.oracle.home.path(), self.wd.path());
            self.canonicalizations.iter().for_each(|c| c.apply(&mut output));
            output.args = normalized_args;
            self.artifacts.outputs.truncate(n);
            self.artifacts.outputs.push(output.clone());
            self.artifacts.dynamic_upper_bounds.truncate(n);
            self.artifacts.dynamic_upper_bounds.push(vec![
                output.stdout_edit_distance(&us),
                output.stderr_edit_distance(&us),
                output.statusfd_edit_distance(&us),
            ]);
            output
        };

        Ok(Diff {
            experiment: RefCell::new(&mut *self),
            args: args.iter().map(ToString::to_string).collect(),
            oracle,
            former_us,
            us,
            index: n,
        })
    }

    /// Stores the given data in the state directory, returning a path
    /// to that file.
    ///
    /// Useful for building up invocations.
    pub fn store(&self, name: &str, data: impl AsRef<[u8]>)
                 -> Result<String> {
        let path = self.wd.path().join(name);
        self.log.borrow_mut().push(Action::Store(path.clone()));
        fs::write(&path, data)?;
        Ok(path.to_str().unwrap().into())
    }

    /// Writes a reproducer to `sink`.
    pub fn reproducer(&self, mut sink: &mut dyn io::Write) -> Result<()> {
        writeln!(&mut sink, "export GNUPGHOME=$(mktemp -d)")?;
        writeln!(&mut sink, "echo -e {:?} > $GNUPGHOME/gpg-agent.conf",
                 Context::GPG_AGENT_CONF)?;
        writeln!(&mut sink, "mkdir -p {}", self.wd.path().display())?;
        for a in self.log.borrow().iter() {
            writeln!(&mut sink)?;
            match a {
                Action::Invoke(args) => {
                    write!(&mut sink, "gpg")?;
                    for a in args {
                        write!(&mut sink, " {:?}", a)?;
                    }
                    writeln!(&mut sink)?;
                },
                Action::Store(path) => {
                    writeln!(&mut sink, "gpg --dearmor >{} <<EOF",
                             path.display())?;
                    use openpgp::armor::*;
                    let mut w = Writer::new(&mut sink, Kind::File)?;
                    let mut s = fs::File::open(path)?;
                    io::copy(&mut s, &mut w)?;
                    w.finalize()?;
                    writeln!(&mut sink, "EOF")?;
                },
            }
        }
        writeln!(&mut sink)?;
        writeln!(&mut sink, "# end of reproducer")?;
        Ok(())
    }
}

/// Canonicalizations that are applied to all the (future) outputs of
/// an experiment.
struct Canonicalization {
    re: Regex,
    substitute: Vec<u8>,
}

impl Canonicalization {
    /// Applies the canonicalization rule to the given output.
    fn apply(&self, o: &mut Output) {
        o.stdout = self.re.replace_all(&o.stdout, &self.substitute).into();
        o.stderr = self.re.replace_all(&o.stderr, &self.substitute).into();
        o.statusfd = self.re.replace_all(&o.statusfd, &self.substitute).into();
    }
}

/// The difference between invoking the reference GnuPG & the former
/// Chameleon and the Chameleon.
pub struct Diff<'a> {
    experiment: RefCell<&'a mut Experiment>,
    args: Vec<String>,
    oracle: Output,
    us: Output,
    former_us: Option<Output>,
    index: usize,
}

impl Diff<'_> {
    /// Canonicalizes the outputs with the given function.
    pub fn canonicalize_with<F>(&mut self, mut fun: F)
        -> Result<()>
    where
        F: FnMut(&mut Output) -> Result<()>,
    {
        fun(&mut self.oracle)?;
        fun(&mut self.us)?;
        if let Some(former_us) = self.former_us.as_mut() {
            fun(former_us)?;
        }

        if let Some(bounds) = self.experiment.get_mut()
            .artifacts.dynamic_upper_bounds.get_mut(self.index)
        {
            *bounds = vec![
                self.oracle.stdout_edit_distance(&self.us),
                self.oracle.stderr_edit_distance(&self.us),
                self.oracle.statusfd_edit_distance(&self.us),
            ];
        }

        Ok(())
    }

    /// Canonicalizes the first fingerprints in the outputs.
    pub fn canonicalize_fingerprints(&mut self, n: usize) -> Result<()> {
        let find_fp = Regex::new(r"[0-9A-F]{40}")?;
        let mut canonicalizations =
            std::mem::take(&mut self.experiment.get_mut().canonicalizations);

        self.canonicalize_with(|o| {
            if let Some(fp) = find_fp.find(&o.stdout)
                .or_else(|| find_fp.find(&o.stderr))
                .or_else(|| find_fp.find(&o.statusfd))
            {
                let fingerprint =
                    String::from_utf8_lossy(fp.as_bytes()).to_string();
                let keyid =
                    String::from_utf8_lossy(&fp.as_bytes()[24..]).to_string();

                let c = Canonicalization {
                    re: Regex::new(&fingerprint)?,
                    substitute: format!("[FINGERPRINT-{}]", n).into(),
                };
                c.apply(o);
                canonicalizations.push(c);

                if let Ok(fp) = openpgp::Fingerprint::from_str(&fingerprint) {
                    let c = Canonicalization {
                        re: Regex::new(&fp.to_spaced_hex())?,
                        substitute: format!("[FINGERPRINT-{}]", n).into(),
                    };
                    c.apply(o);
                    canonicalizations.push(c);
                }

                let c = Canonicalization {
                    re: Regex::new(&keyid)?,
                    substitute: format!("[KEYID-{}]", n).into(),
                };
                c.apply(o);
                canonicalizations.push(c);
            }
            Ok(())
        })?;

        self.experiment.get_mut().canonicalizations = canonicalizations;
        Ok(())
    }

    /// Ignore former us.
    ///
    /// On some tests, comparing with the output from ourselves (and
    /// leaving no slack while doing that!) is counterproductive.
    ///
    /// Notably, some outputs include lists of supported algorithms,
    /// and different cryptographic backends or library versions
    /// support different sets of algorithms.  Or, they include
    /// versions of crates or libraries.
    pub fn ignore_former_us(mut self) -> Self {
        self.former_us = None;
        self
    }

    /// Asserts that both implementations returned success.
    ///
    /// Panics otherwise.
    pub fn assert_success(&self) {
        let pass = self.oracle.success()
            && self.us.success();
        if ! pass {
            eprintln!("Invocation not successful.\n\n{}", self);
            panic!();
        }
        self.assert_dynamic_upper_bounds();
        self.assert_unchanged_output();
    }

    /// Asserts that both implementations returned failure.
    ///
    /// Panics otherwise.
    pub fn assert_failure(&self) {
        let pass = !self.oracle.success()
            && !self.us.success();
        if ! pass {
            eprintln!("Invocation did not fail.\n\n{}", self);
            panic!();
        }
        self.assert_dynamic_upper_bounds();
        self.assert_unchanged_output();
    }

    /// Asserts that the current output is the same as the recorded
    /// output.
    pub fn assert_unchanged_output(&self) {
        let mut pass = true;

        if let Some(former_us) = self.former_us.as_ref() {
            eprintln!("asserting output matches output from last run.");

            if former_us.stdout != self.us.stdout {
                pass = false;
                eprintln!("Stdout changed from last run.");
            }
            if former_us.stderr != self.us.stderr {
                pass = false;
                eprintln!("Stderr changed from last run.");
            }
            if former_us.statusfd != self.us.statusfd {
                pass = false;
                eprintln!("Status-fd changed from last run.");
            }
            if former_us.status != self.us.status {
                pass = false;
                eprintln!("Status changed from last run.");
            }
        } else {
            eprintln!("Can't compare output to last run: \
                       no output for last run is recorded");
        }

        if ! pass {
            eprintln!("\n{}", self);
            panic!();
        }
    }

    /// Asserts that both implementations wrote the same output up to
    /// a limit recorded when the artifact was recorded.
    ///
    /// Assert that the edit distance between the implementations
    /// output on stdout (stderr) does not exceed the recorded limits.
    /// Panics otherwise.
    pub fn assert_dynamic_upper_bounds(&self) {
        // We need to do a little dance to avoid borrowing
        // self.experiment twice, once here and once in _assert_limits
        // when producing a reproducer.
        let mut new_limits = None;
        if let Some(limits) = self.experiment.borrow()
            .artifacts.dynamic_upper_bounds.get(self.index).clone()
        {
            let out_limit = limits.get(0).cloned().unwrap_or_default();
            let err_limit = limits.get(1).cloned().unwrap_or_default();
            let statusfd_limit = limits.get(2).cloned().unwrap_or_default();
            eprintln!("Asserting recorded limits of {}, {}, {}",
                      out_limit, err_limit, statusfd_limit);
            new_limits = Some(
                self._assert_limits(false, out_limit, err_limit, statusfd_limit)
            );
        }

        if let Some(l) = new_limits {
            *self.experiment.borrow_mut()
                .artifacts.dynamic_upper_bounds.get_mut(self.index).unwrap()
                = l;
        }
    }

    /// Asserts that both implementations wrote the same output up to
    /// a limit.
    ///
    /// Assert that the edit distance between the implementations
    /// output on stdout (stderr) does not exceed the given
    /// `out_limit` (`err_limit`).  Panics otherwise.
    pub fn assert_equal_up_to(&self, out_limit: usize, err_limit: usize) {
        self.assert_limits(out_limit, err_limit, 0)
    }

    pub fn assert_limits(&self,
                         out_limit: usize, err_limit: usize,
                         statusfd_limit: usize) {
        eprintln!("Asserting static limits of {}, {}, {}",
                  out_limit, err_limit, statusfd_limit);
        self._assert_limits(true, out_limit, err_limit, statusfd_limit);
    }

    fn _assert_limits(&self,
                      static_limits: bool,
                      out_limit: usize,
                      err_limit: usize,
                      statusfd_limit: usize)
                      -> Vec<usize>
    {
        let mut limits = Vec::new();
        let mut pass = true;

        let d = self.oracle.stdout_edit_distance(&self.us);
        limits.push(d);
        if d > out_limit {
            pass = false;
            eprintln!("Stdout edit distance {} exceeds limit of {}.",
                      d, out_limit);
        }
        if static_limits && out_limit > 20 && d < out_limit / 2 {
            pass = false;
            eprintln!("Stdout edit distance {} smaller than half of limit {}.",
                      d, out_limit);
        }

        let d = self.oracle.stderr_edit_distance(&self.us);
        limits.push(d);
        if d > err_limit {
            pass = false;
            eprintln!("Stderr edit distance {} exceeds limit of {}.",
                      d, err_limit);
        }
        if static_limits && err_limit > 20 && d < err_limit / 2 {
            pass = false;
            eprintln!("Stderr edit distance {} smaller than half of limit {}.",
                      d, err_limit);
        }

        let d = self.oracle.statusfd_edit_distance(&self.us);
        limits.push(d);
        if d > statusfd_limit {
            pass = false;
            eprintln!("Statusfd_limit edit distance {} exceeds limit of {}.",
                      d, statusfd_limit);
        }
        if static_limits && statusfd_limit > 20 && d < statusfd_limit / 2 {
            pass = false;
            eprintln!("Statusfd_limit edit distance {} smaller than half of limit {}.",
                      d, statusfd_limit);
        }

        if ! pass {
            eprintln!("\n{}", self);
            panic!();
        }

        limits
    }

    /// Invokes a callback with the working directory.
    pub fn with_working_dir<F, T>(&self, mut fun: F) -> Result<Vec<T>>
    where
        F: FnMut(&BTreeMap<String, Vec<u8>>) -> Result<T>,
    {
        Ok(vec![self.oracle.with_working_dir(&mut fun)?,
                self.us.with_working_dir(&mut fun)?])
    }
}

impl fmt::Display for Diff<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "args:\n {}\n",
                 self.args
                     .iter()
                     .map(|arg| format!("{:?}", arg))
                     .collect::<Vec<String>>()
                     .join(" "))?;

        if self.oracle.stdout.len() + self.us.stdout.len() > 0 {
            writeln!(f, "stdout: (edit distance {})",
                     self.oracle.stdout_edit_distance(&self.us))?;
            udiff(f,
                  "oracle stdout",
                  &String::from_utf8_lossy(&self.oracle.stdout),
                  "chameleon stdout",
                  &String::from_utf8_lossy(&self.us.stdout))?;
        }

        if let Some(former_us) = self.former_us.as_ref() {
            if former_us.stdout.len() + self.us.stdout.len() > 0 {
                writeln!(f, "stdout: (edit distance {})",
                         former_us.stdout_edit_distance(&self.us))?;
                udiff(f,
                      "former gpg-chameleon stdout",
                      &String::from_utf8_lossy(&former_us.stdout),
                      "gpg-chameleon stdout",
                      &String::from_utf8_lossy(&self.us.stdout))?;
            } else {
                writeln!(f, "Can't compare to previous run: output not recorded")?;
            }
        } else {
            writeln!(f, "Can't compare to previous run: output not recorded")?;
        }

        if self.oracle.stderr.len() + self.us.stderr.len() > 0 {
            writeln!(f, "stderr: (edit distance {})",
                     self.oracle.stderr_edit_distance(&self.us))?;
            udiff(f, "oracle stderr",
                  &String::from_utf8_lossy(&self.oracle.stderr),
                  "chameleon stderr",
                  &String::from_utf8_lossy(&self.us.stderr))?;
        }

        if let Some(former_us) = self.former_us.as_ref() {
            if former_us.stderr.len() + self.us.stderr.len() > 0 {
            writeln!(f, "stderr: (edit distance {})",
                     former_us.stderr_edit_distance(&self.us))?;
                udiff(f,
                      "former chameleon stderr",
                      &String::from_utf8_lossy(&former_us.stderr),
                      "chameleon stderr",
                      &String::from_utf8_lossy(&self.us.stderr))?;
            } else {
                writeln!(f, "Can't compare to previous run: output not recorded")?;
            }
        }

        if self.oracle.statusfd.len() + self.us.statusfd.len() > 0 {
            writeln!(f, "statusfd: (edit distance {})",
                     self.oracle.statusfd_edit_distance(&self.us))?;
            udiff(f, "oracle statusfd",
                  &String::from_utf8_lossy(&self.oracle.statusfd),
                  "chameleon statusfd",
                  &String::from_utf8_lossy(&self.us.statusfd))?;
        }

        if let Some(former_us) = self.former_us.as_ref() {
            if former_us.statusfd.len() + self.us.statusfd.len() > 0 {
            writeln!(f, "statusfd: (edit distance {})",
                     former_us.statusfd_edit_distance(&self.us))?;
                udiff(f,
                      "former chameleon statusfd",
                      &String::from_utf8_lossy(&former_us.statusfd),
                      "chameleon statusfd",
                      &String::from_utf8_lossy(&self.us.statusfd))?;
            } else {
                writeln!(f, "Can't compare to previous run: output not recorded")?;
            }
        }

        writeln!(f, "exit status:")?;
        udiff(f, "oracle status",
              &self.oracle.status.to_string(),
              "chameleon status", &self.us.status.to_string())?;

        if let Some(former_us) = self.former_us.as_ref() {
            udiff(f, "former gpg-sq", &former_us.status.to_string(),
                  "gpg-sq", &self.us.status.to_string())?;
        } else {
            writeln!(f, "Can't compare to previous run: output not recorded")?;
        }

        let mut r = Vec::new();
        self.experiment.borrow().reproducer(&mut r).unwrap();
        writeln!(f, "reproducer:\n")?;
        writeln!(f, "{}", String::from_utf8_lossy(&r))?;
        Ok(())
    }
}

/// Prints a unified-diff style line-based difference.
fn udiff(f: &mut fmt::Formatter<'_>,
         left_name: &str, left: &str,
         right_name: &str, right: &str) -> fmt::Result {
    writeln!(f, "--- {}", left_name)?;
    writeln!(f, "+++ {}", right_name)?;
    for diff in diff::lines(left, right) {
        match diff {
            diff::Result::Left(l)    => writeln!(f, "-{}", l)?,
            diff::Result::Both(l, _) => writeln!(f, " {}", l)?,
            diff::Result::Right(r)   => writeln!(f, "+{}", r)?,
        }
    }
    Ok(())
}
