use std::{
    fmt,
    fs,
    io,
    path::{Path, PathBuf},
    process::*,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;

use sequoia_openpgp as openpgp;

mod gpg {
    mod decrypt;
    mod encrypt;
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
    static ref GPG_CHAMELEON: Vec<String> =
        vec![
            if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
                PathBuf::from(target)
            } else {
                std::env::current_dir().unwrap()
                    .join("target")
            }
            .join("debug/sequoia-chameleon-gpg")
            .display().to_string()
        ];
}

const GPG_CHAMELEON_BUILD: &[&str] =
    &["cargo", "build", "--quiet", "--bin", "sequoia-chameleon-gpg"];

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
    executable: Vec<String>,
    home: tempfile::TempDir,
}

impl Context {
    /// Returns a context for the reference GnuPG implementation.
    pub fn gnupg() -> Result<Self> {
        Context::new(GPG.clone())
    }

    /// Returns a context for the chameleon.
    pub fn chameleon() -> Result<Self> {
        setup();
        Context::new(GPG_CHAMELEON.clone())
    }

    /// Returns a custom context for the given GnuPG-like executable.
    pub fn new(executable: Vec<String>) -> Result<Self> {
        Ok(Context {
            executable,
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
        let mut c = Command::new(&self.executable[0]);
        let workdir = tempfile::TempDir::new()?;
        c.current_dir(workdir.path());
        for arg in &self.executable[1..] {
            c.arg(arg);
        }
        c.arg("--homedir").arg(self.home.path());

        // XXX construct an inheritable pipe and pass it in as
        // status-fd.

        for arg in args {
            c.arg(arg);
        }
        let out = c.output()?;

        // Canonicalizes the path to the state directory.
        let canonicalize = |d: Vec<u8>| -> Vec<u8> {
            let p = self.home.path().to_str().unwrap();
            let r = regex::bytes::Regex::new(p).unwrap();
            r.replace_all(&d, &b"/HOMEDIR/"[..]).into()
        };

        Ok(Output {
            workdir,
            stdout: canonicalize(out.stdout),
            stderr: canonicalize(out.stderr),
            status: out.status,
        })
    }
}

#[derive(Debug)]
pub struct Output {
    workdir: tempfile::TempDir,
    stderr: Vec<u8>,
    stdout: Vec<u8>,
    status: ExitStatus,
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
        F: FnMut(&Path) -> Result<T>,
    {
        fun(self.workdir.path())
    }
}

/// A bisimulation framework.
///
/// Runs the reference GnuPG and the Chameleon in tandem, observing
/// the differences.
pub struct Experiment {
    wd: tempfile::TempDir,
    log: std::cell::RefCell<Vec<Action>>,
    faketime: Option<SystemTime>,
    oracle: Context,
    us: Context,
}

enum Action {
    Store(PathBuf),
    Invoke(Vec<String>),
}

impl Experiment {
    /// Creates a new experiment with empty state directories.
    pub fn new() -> Result<Self> {
        Ok(Experiment {
            wd: tempfile::tempdir()?,
            log: Default::default(),
            faketime: Some(SystemTime::now()
                           // Don't use the current time, that makes
                           // setting the timemode in GnuPG unreliable
                           // (see gnupg_set_time).
                           .checked_sub(Duration::new(3600, 0)).unwrap()),
            oracle: Context::gnupg()?,
            us: Context::chameleon()?,
        })
    }

    /// Returns the reference time of this experiment.
    pub fn now(&self) -> SystemTime {
        self.faketime.unwrap_or_else(SystemTime::now)
    }

    /// Invokes the given command on both implementations.
    pub fn invoke(&self, args: &[&str]) -> Result<Diff> {
        // Implicitly add --faked-system-time if we have
        // self.faketime.
        let mut faked_system_time = Vec::new();
        if let Some(faketime) = self.faketime {
            faked_system_time.push(format!(
                "--faked-system-time={}!",
                faketime.duration_since(UNIX_EPOCH)?.as_secs()));
        }
        let args = faked_system_time.iter().map(|s| s.as_str())
            .chain(args.iter().cloned())
            .collect::<Vec<&str>>();

        self.log.borrow_mut().push(
            Action::Invoke(args.iter().map(ToString::to_string).collect()));
        let oracle = self.oracle.invoke(&args)?;
        let us = self.us.invoke(&args)?;
        Ok(Diff {
            experiment: &self,
            args: args.iter().map(ToString::to_string).collect(),
            oracle,
            us,
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
}

impl Diff<'_> {
    /// Asserts that both implementations returned success.
    ///
    /// Panics otherwise.
    pub fn assert_success(&self) {
        let pass = self.oracle.status.success()
            && self.us.status.success();
        if ! pass {
            eprintln!("Invocation not successful.\n\n{}", self);
            panic!();
        }
    }

    /// Asserts that both implementations returned failure.
    ///
    /// Panics otherwise.
    pub fn assert_failure(&self) {
        let pass = !self.oracle.status.success()
            && !self.us.status.success();
        if ! pass {
            eprintln!("Invocation did not fail.\n\n{}", self);
            panic!();
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
        F: FnMut(&Path) -> Result<T>,
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
