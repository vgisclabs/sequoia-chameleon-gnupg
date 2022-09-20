use std::{
    collections::BTreeSet,
    fmt,
    fs,
    path::Path,
    process::*,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;

mod gpg {
    mod decrypt;
    mod encrypt;
    mod list_keys;
}

lazy_static::lazy_static! {
    static ref GPG: Vec<String> =
        vec![std::env::var("REAL_GPG_BIN")
             .unwrap_or("/usr/bin/gpg".into())];
}

lazy_static::lazy_static! {
    static ref GPG_CHAMELEON: Vec<String> =
        vec![std::env::current_dir().unwrap()
             .join("target/debug/sequoia-chameleon-gpg")
             .display().to_string()];
}

const GPG_CHAMELEON_BUILD: &[&str] =
    &["cargo", "run", "--quiet", "--bin", "sequoia-chameleon-gpg"];

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
        let canonicalize = |mut d: Vec<u8>| -> Vec<u8> {
            let p = self.home.path().to_str().unwrap().as_bytes();
            let mut r = p.to_vec();
            for i in r.len() - 6..r.len() {
                r[i] = 'X' as _;
            }

            for i in 0..d.len() {
                if d[i..].starts_with(p) {
                    d[i..i + r.len()].copy_from_slice(&r);
                }
            }
            d
        };

        Ok(Output {
            workdir,
            stdout: canonicalize(out.stdout),
            stderr: canonicalize(out.stderr),
            status_fd: Default::default(), // XXX
            status: out.status,
        })
    }
}

#[derive(Debug)]
pub struct Output {
    workdir: tempfile::TempDir,
    stderr: Vec<u8>,
    stdout: Vec<u8>,
    status_fd: Vec<Box<[u8]>>,
    status: ExitStatus,
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_lines =
            self.status_fd.iter().map(|l| String::from_utf8_lossy(l))
            .collect::<Vec<_>>();

        write!(f, "stdout:\n{}\n\nstderr:\n{}\n\nstatus_fd:\n{}\n\nstatus: {}",
               String::from_utf8_lossy(&self.stdout),
               String::from_utf8_lossy(&self.stderr),
               status_lines.join("\n"),
               self.status)
    }
}

impl Output {
    /// Returns all status messages.
    pub fn status_messages(&self) -> impl Iterator<Item = &[u8]> {
        self.status_fd.iter()
            .filter(|l| l.starts_with(b"[GNUPG:]"))
            .map(|l| &l[9..])
    }

    /// Returns all status messages, normalized and sorted.
    pub fn normalized_status_messages(&self) -> BTreeSet<String> {
        self.status_messages()
            .filter(|l| ! l.starts_with(b"NOTATION_DATA")) // GnuPG bug 5667
            .map(|l| String::from_utf8_lossy(l).to_string())
        // GnuPG emits those if primary key is expired but the subkey
        // is not.  Filter it out, because even the DETAILS admits
        // that this status line is not helpful:
        //
        // > This status line is not very useful because
        // > it will also be emitted for expired subkeys even if this subkey is
        // > not used.  To check whether a key used to sign a message has
        // > expired, the EXPKEYSIG status line is to be used.
            .filter(|l| l != "KEYEXPIRED 0")
        // XXX: For now, exclude compliance messages.
            .filter(|l| ! l.contains("_COMPLIANCE_MODE "))
            .map(|l| {
                if l.starts_with("GOODSIG")
                    || l.starts_with("EXPSIG")
                    || l.starts_with("EXPSIG")
                    || l.starts_with("EXPKEYSIG")
                    || l.starts_with("REVKEYSIG")
                    || l.starts_with("BADSIG")
                {
                    // Normalize to keyid.
                    let mut s = l.splitn(3, " ");
                    let status = s.next().unwrap();
                    let fp = s.next().unwrap();
                    let rest = s.next().unwrap();
                    if fp.len() == 40 {
                        format!("{} {} {}", status, &fp[24..], rest)
                    } else {
                        l
                    }
                } else {
                    l
                }
            })
            .collect()
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
    faketime: Option<SystemTime>,
    oracle: Context,
    us: Context,
}

impl Experiment {
    /// Creates a new experiment with empty state directories.
    pub fn new() -> Result<Self> {
        Ok(Experiment {
            wd: tempfile::tempdir()?,
            faketime: Some(SystemTime::now()
                           // Don't use the current time, that makes
                           // setting the timemode in GnuPG unreliable
                           // (see gnupg_set_time).
                           .checked_sub(Duration::new(1, 0)).unwrap()),
            oracle: Context::gnupg()?,
            us: Context::chameleon()?,
        })
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

        let oracle = self.oracle.invoke(&args)?;
        let us = self.us.invoke(&args)?;
        Ok(Diff {
            args: args.iter().map(ToString::to_string).collect(),
            oracle,
            us,
        })
    }

    /// Stores the given data in the state directory, returning a path
    /// to that file.
    ///
    /// Useful for building up invocations.
    pub fn store(&self, name: &str, data: impl AsRef<[u8]>) -> Result<String> {
        let path = self.wd.path().join(name);
        fs::write(&path, data)?;
        Ok(path.to_str().unwrap().into())
    }
}

/// The difference between invoking the reference GnuPG and the
/// Chameleon.
pub struct Diff {
    args: Vec<String>,
    oracle: Output,
    us: Output,
}

impl Diff {
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

impl fmt::Display for Diff {
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
