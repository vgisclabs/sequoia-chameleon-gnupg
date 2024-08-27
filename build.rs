use std::{
    env,
    fmt,
    fs,
    path::PathBuf,
};

use clap::{arg, Command, ValueEnum};

fn main() {
    let mut gpg_sq = cli_gpg_sq();
    let mut gpgv_sq = cli_gpgv_sq();

    generate_shell_completions(&mut gpg_sq, &mut gpgv_sq).unwrap();
    generate_man_pages(gpg_sq, gpgv_sq).unwrap();
}

/// Variable name to control the asset out directory with.
const ASSET_OUT_DIR: &str = "ASSET_OUT_DIR";

/// Returns the directory to write the given assets to.
fn asset_out_dir(asset: &str) -> Result<PathBuf> {
    println!("cargo:rerun-if-env-changed={}", ASSET_OUT_DIR);
    let outdir: PathBuf =
        env::var_os(ASSET_OUT_DIR).unwrap_or_else(
            || env::var_os("OUT_DIR").expect("OUT_DIR not set")).into();
    if outdir.exists() && ! outdir.is_dir() {
        return Err(Error(
            format!("{}={:?} is not a directory", ASSET_OUT_DIR, outdir)).into());
    }

    let path = outdir.join(asset);
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Generates shell completions.
fn generate_shell_completions(gpg_sq: &mut clap::Command,
                              gpgv_sq: &mut clap::Command)
                              -> Result<()> {
    let path = asset_out_dir("shell-completions")?;

    for shell in clap_complete::Shell::value_variants() {
        clap_complete::generate_to(*shell, gpg_sq, "gpg-sq", &path)?;
        clap_complete::generate_to(*shell, gpgv_sq, "gpgv-sq", &path)?;
    };

    println!("cargo:warning=shell completions written to {}", path.display());
    Ok(())
}

/// Generates man pages.
fn generate_man_pages(gpg_sq: clap::Command,
                      gpgv_sq: clap::Command)
                      -> Result<()> {
    let path = asset_out_dir("man-pages")?;

    let man = clap_mangen::Man::new(gpg_sq);
    let mut sink = fs::File::create(path.join("gpg-sq.1"))?;
    man.render(&mut sink)?;

    let man = clap_mangen::Man::new(gpgv_sq);
    let mut sink = fs::File::create(path.join("gpgv-sq.1"))?;
    man.render(&mut sink)?;

    println!("cargo:warning=man pages written to {}", path.display());

    Ok(())
}

fn cli_gpg_sq() -> Command {
    Command::new("gpg-sq")
        .version(env!("CARGO_PKG_VERSION"))
        .about(
            "This is a re-implementation and drop-in replacement of gpg using the Sequoia OpenPGP implementation.

gpg-sq is not feature-complete. It currently implements a commonly used subset of the signature creation and verification commands, the encryption and decryption commands, the key listing commands, and some miscellaneous commands.

Support for trust models is limited. Currently, the Web-of-Trust (\"pgp\") and always trust (\"always\") are implemented.",
        )
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .args(&[
            arg!(-s --"sign" "make a signature"),
            arg!(--"clear-sign" "make a clear text signature"),
            arg!(--"clearsign" "@"),
            arg!(-b --"detach-sign" "make a detached signature"),
            arg!(-e --"encrypt" "encrypt data"),
            arg!(--"encrypt-files" "@"),
            arg!(-c --"symmetric" "encryption only with symmetric cipher"),
            arg!(--"store" "@"),
            arg!(-d --"decrypt" "decrypt data (default)"),
            arg!(--"decrypt-files" "@"),
            arg!(--"verify" "verify a signature"),
            arg!(--"verify-files" "@"),
            arg!(-k --"list-keys" "list keys"),
            arg!(--"list-public-keys" "@"),
            arg!(--"list-signatures" "list keys and signatures"),
            arg!(--"list-sigs" "@"),
            arg!(--"check-signatures" "list and check key signatures"),
            arg!(--"check-sigs" "@"),
            arg!(--"fingerprint" "list keys and fingerprints"),
            arg!(-K --"list-secret-keys" "list secret keys"),
            arg!(--"generate-key" "generate a new key pair"),
            arg!(--"gen-key" "@"),
            arg!(--"quick-generate-key" "quickly generate a new key pair"),
            arg!(--"quick-gen-key" "@"),
            arg!(--"quick-add-uid" "quickly add a new user-id"),
            arg!(--"quick-adduid" "@"),
            arg!(--"quick-add-key" "@"),
            arg!(--"quick-addkey" "@"),
            arg!(--"quick-revoke-uid" "quickly revoke a user-id"),
            arg!(--"quick-revuid" "@"),
            arg!(--"quick-set-expire" "quickly set a new expiration date"),
            arg!(--"quick-set-primary-uid" "@"),
            arg!(--"full-generate-key" "full featured key pair generation"),
            arg!(--"full-gen-key" "@"),
            arg!(--"generate-revocation" "generate a revocation certificate"),
            arg!(--"gen-revoke" "@"),
            arg!(--"delete-keys" "remove keys from the public keyring"),
            arg!(--"delete-secret-keys" "remove keys from the secret keyring"),
            arg!(--"quick-sign-key" "quickly sign a key"),
            arg!(--"quick-lsign-key" "quickly sign a key locally"),
            arg!(--"quick-revoke-sig" "quickly revoke a key signature"),
            arg!(--"sign-key" "sign a key"),
            arg!(--"lsign-key" "sign a key locally"),
            arg!(--"edit-key" "sign or edit a key"),
            arg!(--"key-edit" "@"),
            arg!(--"change-passphrase" "change a passphrase"),
            arg!(--"passwd" "@"),
            arg!(--"generate-designated-revocation" "@"),
            arg!(--"desig-revoke" "@"),
            arg!(--"export" "export keys"),
            arg!(--"send-keys" "export keys to a keyserver"),
            arg!(--"receive-keys" "import keys from a keyserver"),
            arg!(--"recv-keys" "@"),
            arg!(--"search-keys" "search for keys on a keyserver"),
            arg!(--"refresh-keys" "update all keys from a keyserver"),
            arg!(--"locate-keys" "@"),
            arg!(--"locate-external-keys" "@"),
            arg!(--"fetch-keys" "@"),
            arg!(--"show-keys" "@"),
            arg!(--"export-secret-keys" "@"),
            arg!(--"export-secret-subkeys" "@"),
            arg!(--"export-ssh-key" "@"),
            arg!(--"import" "import/merge keys"),
            arg!(--"fast-import" "@"),
            arg!(--"list-config" "@"),
            arg!(--"list-gcrypt-config" "@"),
            arg!(--"gpgconf-list" "@"),
            arg!(--"gpgconf-test" "@"),
            arg!(--"list-packets" "@"),
            arg!(--"export-ownertrust" "@"),
            arg!(--"import-ownertrust" "@"),
            arg!(--"update-trustdb" "update the trust database"),
            arg!(--"check-trustdb" "@"),
            arg!(--"fix-trustdb" "@"),
            arg!(--"list-trustdb" "@"),
            arg!(--"dearmor" "@"),
            arg!(--"dearmour" "@"),
            arg!(--"enarmor" "@"),
            arg!(--"enarmour" "@"),
            arg!(--"print-md" "print message digests"),
            arg!(--"print-mds" "@"),
            arg!(--"gen-prime" "@"),
            arg!(--"gen-random" "@"),
            arg!(--"server" "run in server mode"),
            arg!(--"tofu-policy" <VALUE> "set the TOFU policy for a key"),
            arg!(--"delete-secret-and-public-keys" "@"),
            arg!(--"rebuild-keydb-caches" "@"),
            arg!(--"list-key" "@"),
            arg!(--"list-sig" "@"),
            arg!(--"check-sig" "@"),
            arg!(--"show-key" "@"),
            arg!(--"Monitor" "Options controlling the diagnostic output"),
            arg!(-v --"verbose" "verbose"),
            arg!(--"no-verbose" "@"),
            arg!(-q --"quiet" "be somewhat more quiet"),
            arg!(--"no-tty" "@"),
            arg!(--"no-greeting" "@"),
            arg!(--"debug" "@"),
            arg!(--"debug-level" "@"),
            arg!(--"debug-all" "@"),
            arg!(--"debug-iolbf" "@"),
            arg!(--"display-charset" "@"),
            arg!(--"charset" "@"),
            arg!(--"options" <FILE> "read options from FILE"),
            arg!(--"no-options" "@"),
            arg!(--"logger-fd" "@"),
            arg!(--"log-file" <FILE> "write server mode logs to FILE"),
            arg!(--"logger-file" "@"),
            arg!(--"debug-quick-random" "@"),
            arg!(--"Configuration" "Options controlling the configuration"),
            arg!(--"homedir" "@"),
            arg!(--"faked-system-time" "@"),
            arg!(--"default-key" <NAME> "use NAME as default secret key"),
            arg!(--"encrypt-to" <NAME> "encrypt to user ID NAME as well"),
            arg!(--"no-encrypt-to" "@"),
            arg!(--"hidden-encrypt-to" "@"),
            arg!(--"encrypt-to-default-key" "@"),
            arg!(--"default-recipient" "@"),
            arg!(--"default-recipient-self" "@"),
            arg!(--"no-default-recipient" "@"),
            arg!(--"group" <SPEC> "set up email aliases"),
            arg!(--"ungroup" "@"),
            arg!(--"no-groups" "@"),
            arg!(--"compliance" "@"),
            arg!(--"gnupg" "@"),
            arg!(--"no-pgp2" "@"),
            arg!(--"no-pgp6" "@"),
            arg!(--"no-pgp7" "@"),
            arg!(--"no-pgp8" "@"),
            arg!(--"rfc2440" "@"),
            arg!(--"rfc4880" "@"),
            arg!(--"rfc4880bis" "@"),
            arg!(--"openpgp" "use strict OpenPGP behavior"),
            arg!(--"pgp6" "@"),
            arg!(--"pgp7" "@"),
            arg!(--"pgp8" "@"),
            arg!(--"default-new-key-algo" "@"),
            arg!(--"min-rsa-length" "@"),
            arg!(--"always-trust" "@"),
            arg!(--"trust-model" "@"),
            arg!(--"photo-viewer" "@"),
            arg!(--"known-notation" "@"),
            arg!(--"agent-program" "@"),
            arg!(--"dirmngr-program" "@"),
            arg!(--"exit-on-status-write-error" "@"),
            arg!(--"limit-card-insert-tries" "@"),
            arg!(--"enable-progress-filter" "@"),
            arg!(--"temp-directory" "@"),
            arg!(--"exec-path" "@"),
            arg!(--"expert" "@"),
            arg!(--"no-expert" "@"),
            arg!(--"no-secmem-warning" "@"),
            arg!(--"require-secmem" "@"),
            arg!(--"no-require-secmem" "@"),
            arg!(--"no-permission-warning" "@"),
            arg!(-n --"dry-run" "do not make any changes"),
            arg!(-i --"interactive" "prompt before overwriting"),
            arg!(--"default-sig-expire" "@"),
            arg!(--"ask-sig-expire" "@"),
            arg!(--"no-ask-sig-expire" "@"),
            arg!(--"default-cert-expire" "@"),
            arg!(--"ask-cert-expire" "@"),
            arg!(--"no-ask-cert-expire" "@"),
            arg!(--"default-cert-level" "@"),
            arg!(--"min-cert-level" "@"),
            arg!(--"ask-cert-level" "@"),
            arg!(--"no-ask-cert-level" "@"),
            arg!(--"only-sign-text-ids" "@"),
            arg!(--"enable-large-rsa" "@"),
            arg!(--"disable-large-rsa" "@"),
            arg!(--"enable-dsa2" "@"),
            arg!(--"disable-dsa2" "@"),
            arg!(--"personal-cipher-preferences" "@"),
            arg!(--"personal-digest-preferences" "@"),
            arg!(--"personal-compress-preferences" "@"),
            arg!(--"default-preference-list" "@"),
            arg!(--"default-keyserver-url" "@"),
            arg!(--"no-expensive-trust-checks" "@"),
            arg!(--"allow-non-selfsigned-uid" "@"),
            arg!(--"no-allow-non-selfsigned-uid" "@"),
            arg!(--"allow-freeform-uid" "@"),
            arg!(--"no-allow-freeform-uid" "@"),
            arg!(--"preserve-permissions" "@"),
            arg!(--"default-cert-check-level" "@"),
            arg!(--"tofu-default-policy" "@"),
            arg!(--"lock-once" "@"),
            arg!(--"lock-multiple" "@"),
            arg!(--"lock-never" "@"),
            arg!(--"compress-algo" "@"),
            arg!(--"compression-algo" "@"),
            arg!(--"bzip2-decompress-lowmem" "@"),
            arg!(--"completes-needed" "@"),
            arg!(--"marginals-needed" "@"),
            arg!(--"max-cert-depth" "@"),
            arg!(--"trustdb-name" "@"),
            arg!(--"auto-check-trustdb" "@"),
            arg!(--"no-auto-check-trustdb" "@"),
            arg!(--"force-ownertrust" "@"),
            arg!(--"Input" "Options controlling the input"),
            arg!(--"multifile" "@"),
            arg!(--"input-size-hint" "@"),
            arg!(--"utf8-strings" "@"),
            arg!(--"no-utf8-strings" "@"),
            arg!(--"set-filesize" "@"),
            arg!(--"no-literal" "@"),
            arg!(--"set-notation" "@"),
            arg!(--"sig-notation" "@"),
            arg!(--"cert-notation" "@"),
            arg!(--"set-policy-url" "@"),
            arg!(--"sig-policy-url" "@"),
            arg!(--"cert-policy-url" "@"),
            arg!(--"sig-keyserver-url" "@"),
            arg!(--"Output" "Options controlling the output"),
            arg!(-a --"armor" "create ascii armored output"),
            arg!(--"armour" "@"),
            arg!(--"no-armor" "@"),
            arg!(--"no-armour" "@"),
            arg!(-o --"output" <FILE> "write output to FILE"),
            arg!(--"max-output" "@"),
            arg!(--"comment" "@"),
            arg!(--"default-comment" "@"),
            arg!(--"no-comments" "@"),
            arg!(--"emit-version" "@"),
            arg!(--"no-emit-version" "@"),
            arg!(--"no-version" "@"),
            arg!(--"not-dash-escaped" "@"),
            arg!(--"escape-from-lines" "@"),
            arg!(--"no-escape-from-lines" "@"),
            arg!(--"mimemode" "@"),
            arg!(--"textmode" "use canonical text mode"),
            arg!(--"no-textmode" "@"),
            arg!(--"set-filename" "@"),
            arg!(--"for-your-eyes-only" "@"),
            arg!(--"no-for-your-eyes-only" "@"),
            arg!(--"show-notation" "@"),
            arg!(--"no-show-notation" "@"),
            arg!(--"show-session-key" "@"),
            arg!(--"use-embedded-filename" "@"),
            arg!(--"no-use-embedded-filename" "@"),
            arg!(--"unwrap" "@"),
            arg!(--"mangle-dos-filenames" "@"),
            arg!(--"no-mangle-dos-filenames" "@"),
            arg!(--"no-symkey-cache" "@"),
            arg!(--"skip-verify" "@"),
            arg!(--"list-only" "@"),
            arg!(-z <N> "set compress level to N (0 disables)"),
            arg!(--"compress-level" "@"),
            arg!(--"bzip2-compress-level" "@"),
            arg!(--"disable-signer-uid" "@"),
            arg!(--"ImportExport" "Options controlling key import and export"),
            arg!(--"auto-key-locate" <MECHANISMS> "use MECHANISMS to locate keys by mail address"),
            arg!(--"no-auto-key-locate" "@"),
            arg!(--"auto-key-import" "import missing key from a signature"),
            arg!(--"no-auto-key-import" "@"),
            arg!(--"auto-key-retrieve" "@"),
            arg!(--"no-auto-key-retrieve" "@"),
            arg!(--"include-key-block" "include the public key in signatures"),
            arg!(--"no-include-key-block" "@"),
            arg!(--"disable-dirmngr" "disable all access to the dirmngr"),
            arg!(--"keyserver" "@"),
            arg!(--"keyserver-options" "@"),
            arg!(--"key-origin" "@"),
            arg!(--"import-options" "@"),
            arg!(--"import-filter" "@"),
            arg!(--"export-options" "@"),
            arg!(--"export-filter" "@"),
            arg!(--"merge-only" "@"),
            arg!(--"allow-secret-key-import" "@"),
            arg!(--"Keylist" "Options controlling key listings"),
            arg!(--"list-options" "@"),
            arg!(--"show-photos" "@"),
            arg!(--"no-show-photos" "@"),
            arg!(--"show-policy-url" "@"),
            arg!(--"no-show-policy-url" "@"),
            arg!(--"with-colons" "@"),
            arg!(--"with-tofu-info" "@"),
            arg!(--"with-key-data" "@"),
            arg!(--"with-sig-list" "@"),
            arg!(--"with-sig-check" "@"),
            arg!(--"with-fingerprint" "@"),
            arg!(--"with-subkey-fingerprint" "@"),
            arg!(--"with-subkey-fingerprints" "@"),
            arg!(--"with-icao-spelling" "@"),
            arg!(--"with-keygrip" "@"),
            arg!(--"with-secret" "@"),
            arg!(--"with-wkd-hash" "@"),
            arg!(--"with-key-origin" "@"),
            arg!(--"fast-list-mode" "@"),
            arg!(--"fixed-list-mode" "@"),
            arg!(--"legacy-list-mode" "@"),
            arg!(--"print-pka-records" "@"),
            arg!(--"print-dane-records" "@"),
            arg!(--"keyid-format" "@"),
            arg!(--"show-keyring" "@"),
            arg!(-r --"recipient" <USERID> "encrypt for USERID"),
            arg!(--"hidden-recipient" "@"),
            arg!(--"recipient-file" "@"),
            arg!(--"hidden-recipient-file" "@"),
            arg!(--"remote-user" "@"),
            arg!(--"throw-keyids" "@"),
            arg!(--"no-throw-keyids" "@"),
            arg!(-u --"local-user" <USERID> "use USERID to sign or decrypt"),
            arg!(--"trusted-key" "@"),
            arg!(--"sender" "@"),
            arg!(--"try-secret-key" "@"),
            arg!(--"try-all-secrets" "@"),
            arg!(--"no-default-keyring" "@"),
            arg!(--"no-keyring" "@"),
            arg!(--"keyring" "@"),
            arg!(--"primary-keyring" "@"),
            arg!(--"secret-keyring" "@"),
            arg!(--"skip-hidden-recipients" "@"),
            arg!(--"no-skip-hidden-recipients" "@"),
            arg!(--"override-session-key" "@"),
            arg!(--"override-session-key-fd" "@"),
            arg!(--"Security" "Options controlling the security"),
            arg!(--"s2k-mode" "@"),
            arg!(--"s2k-digest-algo" "@"),
            arg!(--"s2k-cipher-algo" "@"),
            arg!(--"s2k-count" "@"),
            arg!(--"require-backsigs" "@"),
            arg!(--"require-cross-certification" "@"),
            arg!(--"no-require-backsigs" "@"),
            arg!(--"no-require-cross-certification" "@"),
            arg!(--"verify-options" "@"),
            arg!(--"enable-special-filenames" "@"),
            arg!(--"no-random-seed-file" "@"),
            arg!(--"no-sig-cache" "@"),
            arg!(--"ignore-time-conflict" "@"),
            arg!(--"ignore-valid-from" "@"),
            arg!(--"ignore-crc-error" "@"),
            arg!(--"ignore-mdc-error" "@"),
            arg!(--"disable-cipher-algo" "@"),
            arg!(--"disable-pubkey-algo" "@"),
            arg!(--"cipher-algo" "@"),
            arg!(--"digest-algo" "@"),
            arg!(--"cert-digest-algo" "@"),
            arg!(--"override-compliance-check" "@"),
            arg!(--"allow-weak-key-signatures" "@"),
            arg!(--"allow-weak-digest-algos" "@"),
            arg!(--"weak-digest" "@"),
            arg!(--"allow-multisig-verification" "@"),
            arg!(--"allow-multiple-messages" "@"),
            arg!(--"no-allow-multiple-messages" "@"),
            arg!(--"batch" "@"),
            arg!(--"no-batch" "@"),
            arg!(--"yes" "@"),
            arg!(--"no" "@"),
            arg!(--"status-fd" "@"),
            arg!(--"status-file" "@"),
            arg!(--"attribute-fd" "@"),
            arg!(--"attribute-file" "@"),
            arg!(--"command-fd" "@"),
            arg!(--"command-file" "@"),
            arg!(--"passphrase" "@"),
            arg!(--"passphrase-fd" "@"),
            arg!(--"passphrase-file" "@"),
            arg!(--"passphrase-repeat" "@"),
            arg!(--"pinentry-mode" "@"),
            arg!(--"force-sign-key" "@"),
            arg!(--"request-origin" "@"),
            arg!(--"display" "@"),
            arg!(--"ttyname" "@"),
            arg!(--"ttytype" "@"),
            arg!(--"lc-ctype" "@"),
            arg!(--"lc-messages" "@"),
            arg!(--"xauthority" "@"),
            arg!(--"no-autostart" "@"),
            arg!(--"forbid-gen-key" "@"),
            arg!(--"require-compliance" "@"),
            arg!(--"use-only-openpgp-card" "@"),
            arg!(--"rfc2440-text" "@"),
            arg!(--"no-rfc2440-text" "@"),
            arg!(--"personal-cipher-prefs" "@"),
            arg!(--"personal-digest-prefs" "@"),
            arg!(--"personal-compress-prefs" "@"),
            arg!(--"sign-with" "@"),
            arg!(--"user" "@"),
            arg!(--"use-agent" "@"),
            arg!(--"no-use-agent" "@"),
            arg!(--"gpg-agent-info" "@"),
            arg!(--"reader-port" "@"),
            arg!(--"ctapi-driver" "@"),
            arg!(--"pcsc-driver" "@"),
            arg!(--"disable-ccid" "@"),
            arg!(--"honor-http-proxy" "@"),
            arg!(--"tofu-db-format" "@"),
            arg!(--"strict" "@"),
            arg!(--"no-strict" "@"),
            arg!(--"load-extension" "@"),
            arg!(--"sk-comments" "@"),
            arg!(--"no-sk-comments" "@"),
            arg!(--"compress-keys" "@"),
            arg!(--"compress-sigs" "@"),
            arg!(--"force-v3-sigs" "@"),
            arg!(--"no-force-v3-sigs" "@"),
            arg!(--"force-v4-certs" "@"),
            arg!(--"no-force-v4-certs" "@"),
            arg!(--"no-mdc-warning" "@"),
            arg!(--"force-mdc" "@"),
            arg!(--"no-force-mdc" "@"),
            arg!(--"disable-mdc" "@"),
            arg!(--"no-disable-mdc" "@"),
            arg!(--"x-sequoia-parcimonie" "continuously update certificates"),
            arg!(--"x-sequoia-autostart-parcimonie" "automatically start daemon to update certs"),
            arg!(--"x-sequoia-parcimonie-daemonize" "@"),
            arg!(--"warranty" "@"),
            arg!(--"dump-option-table" "@"),
            arg!(--"dump-options" "@"),

        ])
}

fn cli_gpgv_sq() -> Command {
    Command::new("gpgv-sq")
        .version(env!("CARGO_PKG_VERSION"))
        .about("gpgv-sq - Verify OpenPGP signatures as gpgv")
        .long_about(
            "This is a re-implementation and drop-in replacement of gpgv using the Sequoia OpenPGP implementation.

gpgv-sq is feature-complete. Please report any problems you encounter when replacing gpgv with gpgv-sq.",
        )
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .args(&[
            arg!(-v --verbose "verbose"),
            arg!(-q --quiet "be somewhat more quiet"),
            arg!(--keyring <FILE> "take the keys from the keyring FILE"),
            arg!(-o --output <FILE> "write output to FILE"),
            arg!(--"ignore-time-conflict" "make timestamp conflicts only a warning"),
            arg!(--"status-fd" <FD> "write status info to this FD"),
            arg!(--"weak-digest" <ALGO> "reject signatures made with ALGO")
        ])
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}
