use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    io,
    path::{Path, PathBuf},
    process::*,
    os::unix::io::{AsRawFd, FromRawFd},
    sync::OnceLock,
    time,
};

use anyhow::{Context as _, Result};
use histo::Histogram;
use indexmap::IndexMap;
use regex::bytes::Regex;
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Command},
};

// The tests:

#[test]
#[ntest::timeout(600000)]
fn password_store_git() -> Result<()> {
    Experiment::new("password-store-git")?.with_null_policy()?.run()
}

// The framework:

const EDIT_DISTANCE_CUTOFF: usize = 1000;

/// Recording metadata.
///
/// Keep in sync with the definition in src/gpg-recorder.rs and make
/// only forward-compatible changes if possible.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct Metadata {
    package: String,
    version: String,
    source: String,
    creation_time: time::SystemTime,
}

impl Metadata {
    fn emit(&self) {
        eprintln!("  - Package: {}", self.package);
        eprintln!("  - Version: {}", self.version);
        eprintln!("  - Source: {}", self.source);
        eprintln!("  - Created: {}",
                  chrono::DateTime::<chrono::Utc>::from(self.creation_time));
        eprintln!();
    }
}

/// Stored distances.
///
/// We store the distances per component for every sample.  This way,
/// we can detect regressions.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Distances {
    metadata: Metadata,
    samples: Vec<BTreeMap<String, Option<usize>>>,
}

fn gpg_chameleon() -> &'static Vec<String> {
    static GPG_CHAMELEON: OnceLock<Vec<String>> = OnceLock::new();
    GPG_CHAMELEON.get_or_init(||
        vec![
            if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
                PathBuf::from(target)
            } else {
                std::env::current_dir().unwrap()
                    .join("target")
            }
            .join("debug/gpg-sq")
            .display().to_string()
        ])
}

fn gpgv_chameleon() -> &'static Vec<String> {
    static GPGV_CHAMELEON: OnceLock<Vec<String>> = OnceLock::new();
    GPGV_CHAMELEON.get_or_init(||
        vec![
            if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
                PathBuf::from(target)
            } else {
                std::env::current_dir().unwrap()
                    .join("target")
            }
            .join("debug/gpgv-sq")
            .display().to_string()
        ])
}

const GPG_CHAMELEON_BUILD: &[&str] = &["cargo", "build", "--quiet"];

pub const STDOUT_EDIT_DISTANCE_THRESHOLD: usize = 20;
pub const STDERR_EDIT_DISTANCE_THRESHOLD: usize = 20;

/// Sets up the test environment.
fn setup() {
    build();
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

/// Opens a pipe.
fn pipe() -> Result<(tokio::fs::File, tokio::fs::File)> {
    use interprocess::unnamed_pipe::pipe;
    use std::os::unix::io::IntoRawFd;
    let (writer, reader) = pipe()?;
    unsafe {
        Ok((tokio::fs::File::from_raw_fd(writer.into_raw_fd()),
            tokio::fs::File::from_raw_fd(reader.into_raw_fd())))
    }
}

/// Copies data from `source` to `sink0` and `sink1`, returning the
/// amount of data copied.
async fn copy<R, W>(mut source: R, mut sink: W)
                    -> Result<usize>
where
    R: AsyncRead + Unpin + 'static,
    W: AsyncWrite + Unpin + 'static,
{
    let mut buf = vec![0; 4096];
    let mut total = 0;
    loop {
        // When the child process ends, we still try to read from our
        // stdin and block the join.  To prevent that, use a time out
        // here and when it expires, we try to flush the sink.  If the
        // sink has been closed, this will fail and we break the loop.
        let amount = source.read(&mut buf).await?;
        if amount == 0 {
            break;
        }
        sink.write_all(&buf[..amount]).await?;
        total += amount;
    }
    Ok(total)
}

/// A context for GnuPG.
///
/// Creates a temporary directory and cleans it up on Drop.
pub struct Context<'env> {
    /// Environment variables set when executing commands.
    env: &'env BTreeMap<String, OsString>,

    // How to invoke gpg or gpg-sq.
    //
    // gpg[0] is the executable and the rest are arguments that are
    // implicitly passed to it.
    gpg: Vec<String>,

    // Like `gpg`, but for gpgv or gpgv-sq.
    gpgv: Vec<String>,

    /// The directory containing the recording.
    recorder_dir: PathBuf,
}

impl<'env> Context<'env> {
    /// Returns a context for the chameleon.
    pub fn new(recorder_dir: PathBuf, env: &'env BTreeMap<String, OsString>)
               -> Result<Self>
    {
        setup();
        Ok(Context {
            env,
            gpg: gpg_chameleon().clone(),
            gpgv: gpgv_chameleon().clone(),
            recorder_dir,
        })
    }

    fn gnupghome(&self) -> PathBuf {
        self.recorder_dir.join("gnupghome")
    }

    /// Invokes the Chameleon.
    pub fn invoke(&self, previous: Option<BTreeMap<String, Option<usize>>>)
                  -> Result<Diff> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(self._invoke(previous))
    }

    async fn _invoke(&self, previous: Option<BTreeMap<String, Option<usize>>>)
                     -> Result<Diff> {
        let args_path = self.recorder_dir.join("args");
        let args: Vec<String> =
            serde_json::from_reader(
                fs::File::open(&args_path).with_context(
                    || format!("failed to open {}", args_path.display()))?)?;

        // See if the user wants gpg or gpgv.
        let executable = if args[0] == "gpgv" {
            &self.gpgv
        } else {
            &self.gpg
        };
        let mut args = args[1..].to_vec();

        // We're going to change directories before execve(2)ing in
        // the child, so make sure the path is absolute.
        let exe = fs::canonicalize(&executable[0])?;
        let mut c = {
            if let Some(unix_now) =
                fs::read(self.recorder_dir.join("time")).ok()
                .and_then(|v| String::from_utf8(v).ok())
                .and_then(|v| v.parse::<u64>().ok())
            {
                let mut c = Command::new("faketime");
                c.arg(format!("@{}", unix_now));
                c.arg(&exe);
                c
            } else {
                Command::new(&exe)
            }
        };
        c.env("LC_ALL", "C");
        c.env("TZ", "UTC"); // XXX: maybe track and store the TZ.
        for (k, v) in self.env.iter() {
            c.env(k, v);
        }

        // Create and populate a working directory.
        let workdir = tempfile::TempDir::new()?;
        c.current_dir(workdir.path());
        for entry in fs::read_dir(&self.recorder_dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with("input") {
                fs::copy(entry.path(),
                         workdir.path().join(entry.file_name()))?;
            }
        }

        c.args(executable[1..].iter());
        c.arg("--homedir").arg(self.gnupghome());

        let cc_stdin =
            File::open(self.recorder_dir.join("stdin")).await?;
        let cc_stdout =
            File::create(workdir.path().join("stdout")).await?;
        let cc_stderr =
            File::create(workdir.path().join("stderr")).await?;
        let cc_statusfd =
            File::create(workdir.path().join("statusfd")).await?;
        let cc_loggerfd =
            File::create(workdir.path().join("loggerfd")).await?;
        let cc_attributefd =
            File::create(workdir.path().join("attributefd")).await?;
        let cc_commandfd =
            File::open(self.recorder_dir.join("commandfd")).await?;

        // IPC.  Stdin, stdout, and stderr we handle using the std
        // library.
        c.stdin(Stdio::piped());
        c.stdout(Stdio::piped());
        c.stderr(Stdio::piped());

        // All extra streams like statusfd require special care.

        // Status-FD.
        let (statusfd_w, statusfd_r) = pipe()?;
        let statusfd_w_fd = statusfd_w.as_raw_fd();
        let statusfd_r_fd = statusfd_r.as_raw_fd();
        let statusfd = {
            if let Some(i) =
                args.iter().position(|a| a.as_str() == "--status-fd")
            {
                args[i + 1] = statusfd_w_fd.to_string();
            } else if let Some(i) =
                args.iter().position(|a| a.starts_with("--status-fd="))
            {
                args[i] = format!("--status-fd={}", statusfd_w_fd);
            }

            copy(statusfd_r, cc_statusfd)
        };

        // Logger-FD.
        let (loggerfd_w, loggerfd_r) = pipe()?;
        let loggerfd_w_fd = loggerfd_w.as_raw_fd();
        let loggerfd_r_fd = loggerfd_r.as_raw_fd();
        let loggerfd = {
            if let Some(i) =
                args.iter().position(|a| a.as_str() == "--logger-fd")
            {
                args[i + 1] = loggerfd_w_fd.to_string();
            } else if let Some(i) =
                args.iter().position(|a| a.starts_with("--logger-fd="))
            {
                args[i] = format!("--logger-fd={}", loggerfd_w_fd);
            }

            copy(loggerfd_r, cc_loggerfd)
        };

        // Attribute-FD.
        let (attributefd_w, attributefd_r) = pipe()?;
        let attributefd_w_fd = attributefd_w.as_raw_fd();
        let attributefd_r_fd = attributefd_r.as_raw_fd();
        let attributefd = {
            if let Some(i) =
                args.iter().position(|a| a.as_str() == "--attribute-fd")
            {
                args[i + 1] = attributefd_w_fd.to_string();
            } else if let Some(i) =
                args.iter().position(|a| a.starts_with("--attribute-fd="))
            {
                args[i] = format!("--attribute-fd={}", attributefd_w_fd);
            }

            copy(attributefd_r, cc_attributefd)
        };

        // Command-FD.
        let (commandfd_w, commandfd_r) = pipe()?;
        let commandfd_w_fd = commandfd_w.as_raw_fd();
        let commandfd_r_fd = commandfd_r.as_raw_fd();
        let commandfd = {
            if let Some(i) =
                args.iter().position(|a| a.as_str() == "--command-fd")
            {
                args[i + 1] = commandfd_r_fd.to_string();
            } else if let Some(i) =
                args.iter().position(|a| a.starts_with("--command-fd="))
            {
                args[i] = format!("--command-fd={}", commandfd_r_fd);
            }

            copy(cc_commandfd, commandfd_w)
        };

        // Be nice and drop our ends of the pipes in the child process.
        unsafe {
            c.pre_exec(move || {
                drop(fs::File::from_raw_fd(statusfd_r_fd));
                drop(fs::File::from_raw_fd(loggerfd_r_fd));
                drop(fs::File::from_raw_fd(attributefd_r_fd));
                drop(fs::File::from_raw_fd(commandfd_w_fd));
                Ok(())
            });
        }

        // Finish the arguments and start the process.
        //eprintln!("Spawning {:?} {:?}...", exe, args);
        args.insert(0, "--no-permission-warning".into());
        c.args(args.iter());
        let mut child = c.spawn()
            .with_context(|| format!(
                "failed to spawn {}",
                c.as_std().get_program().to_string_lossy()))?;

        drop(statusfd_w);
        drop(attributefd_w);
        drop(loggerfd_w);

        let child_stdin = child.stdin.take().unwrap();
        let stdin = copy(cc_stdin, child_stdin);
        let child_stdout = child.stdout.take().unwrap();
        let stdout = copy(child_stdout, cc_stdout);
        let child_stderr = child.stderr.take().unwrap();
        let stderr = copy(child_stderr, cc_stderr);

        //eprintln!("waiting for child process...");
        let (result, stdin, stdout, stderr,
             statusfd, loggerfd, attributefd, commandfd) =
            tokio::join!(child.wait(), stdin, stdout, stderr,
                         statusfd, loggerfd, attributefd, commandfd);
        let result = result?;
        fs::write(workdir.path().join("result"), result.to_string())?;
        stdin?;
        stdout?;
        stderr?;
        statusfd?;
        loggerfd?;
        attributefd?;
        commandfd?;

        // Collect any output produced in the working directory.
        Diff::new(self.recorder_dir.clone(), args, workdir, previous)
    }
}

/// The difference between invoking the reference GnuPG & the former
/// Chameleon and the Chameleon.
pub struct Diff {
    args: Vec<String>,
    recorder_dir: PathBuf,
    workdir: tempfile::TempDir,
    _distances: OnceLock<Vec<(&'static str, Vec<u8>, Vec<u8>, Option<usize>)>>,

    /// The previously recorded differences, if any.
    previous: Option<BTreeMap<String, Option<usize>>>,
}

impl Diff {
    fn new(recorder_dir: PathBuf, args: Vec<String>, workdir: tempfile::TempDir,
           previous: Option<BTreeMap<String, Option<usize>>>)
           -> Result<Diff>
    {
        Ok(Diff {
            recorder_dir,
            args,
            workdir,
            _distances: OnceLock::new(),
            previous,
        })
    }

    fn components() -> impl Iterator<Item = &'static str> {
        [
            "stdout", "stderr",
            "statusfd", "loggerfd", "attributefd",
            "output",
            "result",
        ].iter().cloned()
    }

    fn distances(&self) -> &[(&'static str, Vec<u8>, Vec<u8>, Option<usize>)] {
        self._distances.get_or_init(|| {
            let recorder_dir = self.recorder_dir.clone();
            let workdir = self.workdir.path().clone();
            Self::components().map(move |c: &'static str| {
                let mut oracle =
                    fs::read(recorder_dir.join(c)).unwrap_or_default();
                let mut us =
                    fs::read(workdir.join(c)).unwrap_or_default();

                if c == "stderr" || c == "loggerfd" {
                    // Normalize GNUPGHOME in the oracle output.
                    let original_gnupghome = String::from_utf8(
                        fs::read(recorder_dir.join("original-gnupghome")).unwrap()).unwrap();
                    let re = Regex::new(&regex::escape(&original_gnupghome)).unwrap();
                    oracle = re.replace(&oracle, b"/GNUPGHOME").to_vec();

                    // Normalize GNUPGHOME in our output.
                    let gnupghome = self.recorder_dir.join("gnupghome")
                        .display().to_string();
                    let re = Regex::new(&regex::escape(&gnupghome)).unwrap();
                    us = re.replace(&us, b"/GNUPGHOME").to_vec();
                }

                if c == "stdout" || c == "output" {
                    if plausible_pgp(&oracle) {
                        oracle = inspect_pgp(oracle).unwrap();
                        us = inspect_pgp(us).unwrap();
                    }
                }

                let distance =
                    editdistancek::edit_distance_bounded(
                        &oracle, &us, EDIT_DISTANCE_CUTOFF);
                (c, oracle, us, distance)
            }).collect()
        })
    }

    fn distance(&self, component: &str) -> (&Vec<u8>, &Vec<u8>, Option<usize>) {
        self.distances().iter().filter_map(|(c, oracle, us, d)| if c == &component {
            Some((oracle, us, d.clone()))
        } else {
            None
        }).next().expect("unknown component")
    }

    fn result_matches(&self) -> bool {
        self.distance("result").2 == Some(0)
    }

    /// Returns whether this sample regressed with respect to
    /// previously recorded distances.
    fn regressed(&self) -> bool {
        if let Some(p) = &self.previous {
            self.distances().iter()
                .map(|(what, _, _, dist)|
                     (dist, p.get(*what).unwrap_or(&Some(0))))
                .any(|(dist, prev)| match (dist, prev) {
                    (None, None) => false,
                    (None, Some(_)) => true,
                    (Some(_), None) => false,
                    (Some(a), Some(b)) => a > b,
                })
        } else {
            false
        }
    }

    fn emit(&self) -> Result<()> {
        let mut printed_args = false;

        for (what, oracle, us, d) in self.distances() {
            if ! printed_args && d != &Some(0) {
                eprintln!();
                eprintln!("  - Invoking the chameleon\n    gpg-sq {}\n",
                          self.args
                          .iter()
                          .map(|arg| format!("{:?}", arg))
                          .collect::<Vec<String>>()
                          .join(" "));
                printed_args = true;
            }

            let previously = match self.previous.as_ref()
                .map(|components| components.get(*what).unwrap_or(&Some(0)))
            {
                Some(Some(d)) => format!("; previously {}", d),
                Some(None) =>
                    format!("; previously > {}", EDIT_DISTANCE_CUTOFF),
                None => format!(""),
            };

            if let Some(d) = d {
                if d > &0 {
                    eprintln!("{}: (edit distance {}{})",
                              what, d, previously);
                    budiff(&format!("oracle {}", what),
                           &oracle,
                           &format!("chameleon {}", what),
                           &us,
                           None)?;
                }
            } else {
                eprintln!("{}: (edit distance > {}{})",
                          what, EDIT_DISTANCE_CUTOFF, previously);
                budiff(&format!("oracle {}", what),
                       &oracle,
                       &format!("chameleon {}", what),
                       &us,
                       None)?;
            }
        }
        if printed_args {
            eprintln!();
        }

        Ok(())
    }
}

fn plausible_pgp(d: &[u8]) -> bool {
    d.starts_with(b"-----BEGIN PGP ") ||
        d.get(0).map(|b| b & 0x80 > 0).unwrap_or(false)
}

fn inspect_pgp(d: Vec<u8>) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut child = std::process::Command::new("sq").arg("inspect")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn sq")?;
    child.stdin.take().unwrap().write_all(&d)?;
    Ok(child.wait_with_output()?.stdout)
}

use bzip2::read::BzDecoder;

struct Experiment {
    name: String,
    metadata: Metadata,
    #[allow(dead_code)]
    sample_dir: tempfile::TempDir,
    diffs: Vec<Diff>,
    failures: Vec<usize>,
    old_distances: Option<Distances>,

    /// Environment variables set when executing commands.
    env: BTreeMap<String, OsString>,
}

impl Experiment {
    fn new(name: &str) -> Result<Self> {
        setup();
        let tmp = tempfile::tempdir()?;
        let tar = fs::File::open(Self::archive_file(name))
            .with_context(|| format!("failed to open archive {}",
                                     Self::archive_file(name).display()))?;
        tar::Archive::new(BzDecoder::new(tar)).unpack(tmp.path())?;
        let metadata: Metadata = serde_json::from_reader(
            fs::File::open(tmp.path().join("metadata.json"))
                .context("failed to read metadata.json from archive")?)?;

        let mut e = Experiment {
            name: name.into(),
            metadata,
            sample_dir: tmp,
            diffs: vec![],
            failures: vec![],
            old_distances: None,
            env: Default::default(),
        };

        e.load_distances()?;
        Ok(e)
    }

    /// Use the given crypto policy configuration file.
    fn with_policy<P: AsRef<Path>>(mut self, policy: P) -> Result<Self> {
        self.env.insert("SEQUOIA_CRYPTO_POLICY".into(),
                        fs::canonicalize(policy)?.into());
        Ok(self)
    }

    /// Use the null crypto policy.
    fn with_null_policy(self) -> Result<Self> {
        self.with_policy(format!("{}/tests/null-policy.toml",
                                 env!("CARGO_MANIFEST_DIR")))
    }

    fn basepath() -> &'static Path {
        <str as AsRef<OsStr>>::as_ref("tests/integration").as_ref()
    }

    fn distance_file(&self) -> PathBuf {
        Self::basepath().join(format!("{}.json", self.name))
    }

    fn archive_file(name: &str) -> PathBuf {
        Self::basepath().join(format!("{}.tar.bz2", name))
    }

    fn run(&mut self) -> Result<()> {
        eprintln!("# Recording {}", self.name);
        eprintln!();
        self.metadata.emit();

        let mut n = 0;
        loop {
            let base = self.sample_dir.path().join(n.to_string());
            if ! base.exists() {
                break;
            }

            let ctx = Context::new(base, &self.env)?;
            eprintln!("## Testing sample {}", n);

            let previously =
                self.old_distances.as_ref().and_then(|d| d.samples.get(n));
            let diff = ctx.invoke(previously.map(Clone::clone))?;
            diff.emit()?;
            if ! diff.result_matches() || diff.regressed() {
                self.failures.push(n);
            }
            self.diffs.push(diff);

            n += 1;
        }

        self.emit()?;
        self.persist_distances()?;
        if self.failures.is_empty() {
            Ok(())
        } else {
            for i in &self.failures {
                eprintln!("error: sample {} {}", i,
                          if self.diffs[*i].regressed() {
                              "regressed"
                          } else {
                              "returned wrong status code"
                          });
                self.diffs[*i].emit()?;
            }
            self.emit_failure_summary()?;
            Err(anyhow::anyhow!("{} samples failed", self.failures.len()))
        }
    }

    fn emit_failure_summary(&self) -> Result<()> {
        if ! self.failures.is_empty() {
            eprintln!("\nerror: {}/{} ({:.2}%) samples failed \
                       (regressed or exit status didn't match).",
                      self.failures.len(), self.diffs.len(),
                      self.failures.len() as f32 / self.diffs.len() as f32
                      * 100.);

            eprint!("\nFailures:");
            for n in &self.failures {
                eprint!(" {}", n);
            }
            eprintln!();
        }
        Ok(())
    }

    fn load_distances(&mut self) -> Result<()> {
        if let Ok(f) = fs::File::open(self.distance_file()) {
            let d: Distances = serde_json::from_reader(f)?;
            if d.metadata == self.metadata {
                self.old_distances = Some(d);
            } else {
                eprintln!("Note: Metadata changed, discarding old results.");
            }
        }
        Ok(())
    }

    fn persist_distances(&self) -> Result<()> {
        let d = Distances {
            metadata: self.metadata.clone(),
            samples: self.diffs.iter().map(
                |d| if d.regressed() {
                    // Keep the old distances instead, so that we
                    // don't write out the regressed ones.
                    d.previous.clone().unwrap()
                } else {
                    d.distances().iter().filter_map(
                        |(component, _, _, distance)|
                        if distance == &Some(0) {
                            None
                        } else {
                            Some((component.to_string(), *distance))
                        })
                        .collect()
                })
                .collect(),
        };
        let mut sink = fs::File::create(self.distance_file())?;
        serde_json::to_writer_pretty(&mut sink, &d)?;
        Ok(())
    }

    fn emit(&self) -> Result<()> {
        eprintln!();
        eprintln!("# Summary");
        eprintln!();
        self.metadata.emit();
        eprintln!();

        struct StreamSummary {
            histogram: Histogram,
            worst_index: usize,
            worst_distance: usize,
        }
        let mut streams: IndexMap<&'static str, StreamSummary> =
            Default::default();
        for (i, what, distance) in self.diffs.iter().enumerate()
            .flat_map(|(i, d)| d.distances().iter().map(
                move |(what, _, _, distance)|
                (i, what, distance.unwrap_or(EDIT_DISTANCE_CUTOFF))))
        {
            let mut summary = streams.entry(what)
                .or_insert_with(|| StreamSummary {
                    histogram: Histogram::with_buckets(20),
                    worst_index: 0,
                    worst_distance: 0,
                });
            summary.histogram.add(distance.try_into().unwrap());
            if summary.worst_distance < distance {
                summary.worst_distance = distance;
                summary.worst_index = i;
            }
        }

        for (stream, summary) in streams.iter() {
            if *stream == "result" {
                // These histograms are really boring, and we track
                // failures in self.failures.
                continue;
            }

            if summary.histogram.buckets().skip(1).all(|b| b.count() == 0) {
                // Skip all zero differences.
                continue;
            }

            eprintln!("{}:\n\n{}", stream, summary.histogram);
            eprintln!("Worst offender: sample {} with distance {}",
                     summary.worst_index, summary.worst_distance);
            eprintln!();
        }

        self.emit_failure_summary().unwrap();
        Ok(())
    }
}

/// Prints a unified-diff style line-based difference.
fn udiff(left_name: &str, left: &str,
         right_name: &str, right: &str,
         context: Option<usize>) -> io::Result<()> {
    eprintln!("--- {}", left_name);
    eprintln!("+++ {}", right_name);

    let context = context.unwrap_or(3);
    // Stash the prefix for printing the context when we encounter a
    // change.
    let mut prefix = std::collections::VecDeque::with_capacity(context + 1);
    // Counter to print the context after we encounter a change.
    let mut suffix = 0;

    for diff in diff::lines(left, right) {
        if let diff::Result::Both(l, _) = diff {
            if suffix > 0 {
                eprintln!(" {}", l);
                suffix -= 1;
            } else {
                prefix.push_back(l);
                while prefix.len() > context {
                    prefix.pop_front();
                }
            }
        } else {
            if ! prefix.is_empty() {
                eprintln!("@@");
            }

            // Print any context that we stashed.
            while let Some(l) = prefix.pop_front() {
                eprintln!(" {}", l);
            }

            match diff {
                diff::Result::Left(l)    => eprintln!("-{}", l),
                diff::Result::Both(_, _) => unreachable!(),
                diff::Result::Right(r)   => eprintln!("+{}", r),
            }

            // Make sure to print context after the change.
            suffix = context;
        }
    }
    Ok(())
}

/// Prints a unified-diff style line-based difference.
#[allow(dead_code)]
fn budiff(left_name: &str, left: &[u8],
          right_name: &str, right: &[u8],
          context: Option<usize>) -> io::Result<()> {
    udiff(left_name, &String::from_utf8_lossy(left),
          right_name, &String::from_utf8_lossy(right),
          context)
}
