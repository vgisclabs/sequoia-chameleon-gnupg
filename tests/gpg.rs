use std::{
    collections::BTreeMap,
    fmt,
    fs,
    io,
    path::{Path, PathBuf},
    process::*,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use serde::{Serialize, Deserialize};

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
    mod verify;
    mod list_keys;
    mod version;
    mod trust_models;
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
    check_gpg_oracle();
    build();
}

/// Makes sure that we're talking to the right oracle.
fn check_gpg_oracle() {
    use std::sync::Once;

    static START: Once = Once::new();
    START.call_once(|| {
        let o = Command::new(&GPG[0])
            .arg("--version").output().unwrap();
        if String::from_utf8_lossy(&o.stdout).contains("equoia") {
            panic!("The oracle {:?} is Sequoia-based, please provide the \
                    stock gpg in REAL_GPG_BIN", GPG[0]);
        }

        let o = Command::new(&GPGV[0])
            .arg("--version").output().unwrap();
        if String::from_utf8_lossy(&o.stdout).contains("equoia") {
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
        let prog = GPG_CHAMELEON_BUILD;
        let mut c = Command::new(&prog[0]);
        for arg in &prog[1..] {
            c.arg(arg);
        }
        c.output().unwrap();
    });
}

/// A context for GnuPG.
///
/// Creates a temporary directory and cleans up on Drop.
pub struct Context {
    gpg: Vec<String>,
    gpgv: Vec<String>,
    home: tempfile::TempDir,
}

impl Context {
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
        Ok(Context {
            gpg,
            gpgv,
            home: tempfile::tempdir()?,
        })
    }

    /// Stores the given data in the state directory, returning a path
    /// to that file.
    ///
    /// Useful for building up invocations.
    pub fn store(&self, name: &str, data: impl AsRef<[u8]>) -> Result<String> {
        let path = self.home.path().join(name);
        fs::write(&path, data)?;
        Ok(path.to_str().unwrap().into())
    }

    /// Invokes the GnuPG implementation with the given arguments.
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

        let mut c = Command::new(&executable[0]);
        c.env("LC_ALL", "C");
        c.env("TZ", "Africa/Nairobi"); // EAT, no DST.
        let workdir = tempfile::TempDir::new()?;
        c.current_dir(workdir.path());
        for arg in &executable[1..] {
            c.arg(arg);
        }
        c.arg("--homedir").arg(self.home.path());

        // XXX construct an inheritable pipe and pass it in as
        // status-fd.

        for arg in args {
            c.arg(arg);
        }
        let out = c.output()?;

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
            status: out.status.to_string(),
            files,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output {
    args: Vec<String>,
    stderr: Vec<u8>,
    stdout: Vec<u8>,
    status: String,
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
    fn canonicalize(mut self, homedir: &Path, experiment: &Path) -> Self {
        let h = regex::bytes::Regex::new(homedir.to_str().unwrap()).unwrap();
        let e = regex::bytes::Regex::new(experiment.to_str().unwrap()).unwrap();
        self.stdout =
            e.replace_all(&h.replace_all(&self.stdout, &b"/HOMEDIR"[..]),
                          &b"/EXPERIMENT"[..])
            .into();
        self.stderr =
            e.replace_all(&h.replace_all(&self.stderr, &b"/HOMEDIR"[..]),
                          &b"/EXPERIMENT"[..])
            .into();
        self
    }

    /// Returns the edit distance of run's stdout with the given one.
    pub fn stdout_edit_distance(&self, to: &Self) -> usize {
        edit_distance::edit_distance(
            &String::from_utf8_lossy(&self.stdout).to_string(),
            &String::from_utf8_lossy(&to.stdout).to_string())
    }

    /// Returns the edit distance of run's stderr with the given one.
    pub fn stderr_edit_distance(&self, to: &Self) -> usize {
        edit_distance::edit_distance(
            &String::from_utf8_lossy(&self.stderr).to_string(),
            &String::from_utf8_lossy(&to.stderr).to_string())
    }

    /// Invokes a callback with the working directory.
    pub fn with_working_dir<F, T>(&self, fun: &mut F) -> Result<T>
    where
        F: FnMut(&BTreeMap<String, Vec<u8>>) -> Result<T>,
    {
        fun(&self.files)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ArtifactStore {
    outputs: Vec<Output>,
    artifacts: BTreeMap<String, Vec<u8>>,

    /// Difference to the Chameleon's stderr and stdout at the time
    /// this output was recorded.
    #[serde(default)]
    dynamic_upper_bounds: Vec<(usize, usize)>,
}

impl ArtifactStore {
    fn load(path: &Path) -> Result<Self> {
        let mut f = fs::File::open(&path)?;
        Ok(serde_cbor::from_reader(&mut f)?)
    }

    fn store(&self, path: &Path) -> Result<()> {
        fs::create_dir_all(path.parent().unwrap())?;
        let mut f = fs::File::create(path)?;
        serde_cbor::to_writer(&mut f, self)?;
        Ok(())
    }
}

/// A bisimulation framework.
///
/// Runs the reference GnuPG and the Chameleon in tandem, observing
/// the differences.
pub struct Experiment {
    wd: tempfile::TempDir,
    log: std::cell::RefCell<Vec<Action>>,
    /// We store the output of GnuPG so that we don't build-depend on
    /// it.
    artifacts: ArtifactStore,
    artifacts_store: PathBuf,
    oracle: Context,
    us: Context,
}

impl Drop for Experiment {
    fn drop(&mut self) {
        let _ = self.artifacts.store(&self.artifacts_store);
    }
}

enum Action {
    Store(PathBuf),
    Invoke(Vec<String>),
}

impl Experiment {
    /// Creates a new experiment with empty state directories.
    pub fn new(function: &str, parameters: Vec<String>) -> Result<Self> {
        let mut path: PathBuf =
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(function[5..] // Drop the extra "gpg::".
                  // Turn it into a relative path.
                  .replace("::", &std::path::MAIN_SEPARATOR.to_string()));
        for parameter in parameters {
            path.push(parameter);
        }
        let artifacts_store = path.with_extension("cbor");

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
        let us = self.us.invoke(&args)?
            .canonicalize(self.us.home.path(), self.wd.path());

        // Then, invoke GnuPG if we don't have a cached artifact.
        let oracle = if let Some(o) = self.artifacts.outputs.get(n)
            .filter(|v| v.args == normalized_args)
        {
            o.clone()
        } else {
            // Cache miss or the arguments changed.
            let mut output = self.oracle.invoke(&args)?
                .canonicalize(self.oracle.home.path(), self.wd.path());
            output.args = normalized_args;
            self.artifacts.outputs.truncate(n);
            self.artifacts.outputs.push(output.clone());
            self.artifacts.dynamic_upper_bounds.truncate(n);
            self.artifacts.dynamic_upper_bounds.push(
                (output.stdout_edit_distance(&us),
                 output.stderr_edit_distance(&us)));
            output
        };

        Ok(Diff {
            experiment: &*self,
            args: args.iter().map(ToString::to_string).collect(),
            oracle,
            us,
            dynamic_upper_bounds: self.artifacts.dynamic_upper_bounds.get(n),
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

/// The difference between invoking the reference GnuPG and the
/// Chameleon.
pub struct Diff<'a> {
    experiment: &'a Experiment,
    args: Vec<String>,
    oracle: Output,
    us: Output,
    dynamic_upper_bounds: Option<&'a (usize, usize)>,
}

impl Diff<'_> {
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
    }

    /// Asserts that both implementations wrote the same output up to
    /// a limit recorded when the artifact was recorded.
    ///
    /// Assert that the edit distance between the implementations
    /// output on stdout (stderr) does not exceed the recorded limits.
    /// Panics otherwise.
    pub fn assert_dynamic_upper_bounds(&self) {
        if let Some(&(out_limit, err_limit)) = self.dynamic_upper_bounds {
            eprintln!("asserting recorded limits of {}, {}", out_limit, err_limit);
            self.assert_equal_up_to(out_limit, err_limit);
        }
    }

    /// Asserts that both implementations wrote the same output up to
    /// a limit.
    ///
    /// Assert that the edit distance between the implementations
    /// output on stdout (stderr) does not exceed the given
    /// `out_limit` (`err_limit`).  Panics otherwise.
    pub fn assert_equal_up_to(&self, out_limit: usize, err_limit: usize) {
        let mut pass = true;

        let d = self.oracle.stdout_edit_distance(&self.us);
        if d > out_limit {
            pass = false;
            eprintln!("Stdout edit distance {} exceeds limit of {}.",
                      d, out_limit);
        }
        if out_limit > 20 && d < out_limit / 2 {
            pass = false;
            eprintln!("Stdout edit distance {} smaller than half of limit {}.",
                      d, out_limit);
        }

        let d = self.oracle.stderr_edit_distance(&self.us);
        if d > err_limit {
            pass = false;
            eprintln!("Stderr edit distance {} exceeds limit of {}.",
                      d, err_limit);
        }
        if err_limit > 20 && d < err_limit / 2 {
            pass = false;
            eprintln!("Stderr edit distance {} smaller than half of limit {}.",
                      d, err_limit);
        }

        if ! pass {
            eprintln!("\n{}", self);
            panic!();
        }
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
        writeln!(f, "args:\n {:?}\n", self.args)?;

        if self.oracle.stdout.len() + self.us.stdout.len() > 0 {
            writeln!(f, "stdout (edit distance {}):",
                     self.oracle.stdout_edit_distance(&self.us))?;
            udiff(f,
                  &String::from_utf8_lossy(&self.oracle.stdout),
                  &String::from_utf8_lossy(&self.us.stdout))?;
        }

        if self.oracle.stderr.len() + self.us.stderr.len() > 0 {
            writeln!(f, "stderr (edit distance {}):",
                     self.oracle.stderr_edit_distance(&self.us))?;
            udiff(f, &String::from_utf8_lossy(&self.oracle.stderr),
                  &String::from_utf8_lossy(&self.us.stderr))?;
        }

        writeln!(f, "status:")?;
        udiff(f, &self.oracle.status.to_string(), &self.us.status.to_string())?;

        let mut r = Vec::new();
        self.experiment.reproducer(&mut r).unwrap();
        writeln!(f, "reproducer:\n")?;
        writeln!(f, "{}", String::from_utf8_lossy(&r))?;
        Ok(())
    }
}

/// Prints a unified-diff style line-based difference.
fn udiff(f: &mut fmt::Formatter<'_>, left: &str, right: &str) -> fmt::Result {
    for diff in diff::lines(left, right) {
        match diff {
            diff::Result::Left(l)    => writeln!(f, "-{}", l)?,
            diff::Result::Both(l, _) => writeln!(f, " {}", l)?,
            diff::Result::Right(r)   => writeln!(f, "+{}", r)?,
        }
    }
    Ok(())
}
