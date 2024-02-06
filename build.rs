use clap::{arg, Command};
use clap_complete::{generate_to, shells::Shell};
use std::env;

fn cli_gpg_sq() -> Command {
    Command::new("gpg-sq")
        .about(
            "This is a re-implementation and drop-in replacement of gpg using the Sequoia OpenPGP implementation.

gpg-sq is not feature-complete. It currently implements a commonly used subset of the signature creation and verification commands, the encryption and decryption commands, the key listing commands, and some miscellaneous commands.

Support for trust models is limited. Currently, the Web-of-Trust (\"pgp\") and always trust (\"always\") are implemented.",
        )
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .args(&[
            arg!(-s --sign "make a signature"),
            arg!(--"clear-sign" "make a clear text signature"),
            arg!(-b --"detach-sign" "make a detached signature"),
            arg!(-e --encrypt "encrypt data"),
            arg!(-c --symmetric "encryption only with symmetric cipher"),
            arg!(-d --decrypt "decrypt data (default)"),
            arg!(--verify "verify a signature"),
            arg!(-k --"list-keys" "list keys"),
            arg!(--"list-signatures" "list keys and signatures"),
            arg!(--"check-signatures" "list and check key signatures"),
            arg!(--fingerprint "list keys and fingerprints"),
            arg!(-K --"list-secret-keys" "list secret keys"),
            arg!(--"generate-key" "generate a new key pair"),
            arg!(--"quick-generate-key" "quickly generate a new key pair"),
            arg!(--"quick-add-uid" "quickly add a new user-id"),
            arg!(--"quick-revoke-uid" "quickly revoke a user-id"),
            arg!(--"quick-set-expire" "quickly set a new expiration date"),
            arg!(--"full-generate-key" "full featured key pair generation"),
            arg!(--"generate-revocation" "generate a revocation certificate"),
            arg!(--"delete-keys" "remove keys from the public keyring"),
            arg!(--"delete-secret-keys" "remove keys from the secret keyring"),
            arg!(--"quick-sign-key" "quickly sign a key"),
            arg!(--"quick-lsign-key" "quickly sign a key locally"),
            arg!(--"quick-revoke-sig" "quickly revoke a key signature"),
            arg!(--"sign-key" "sign a key"),
            arg!(--"lsign-key" "sign a key locally"),
            arg!(--"edit-key" "sign or edit a key"),
            arg!(--"change-passphrase" "change a passphrase"),
            arg!(--export "export keys"),
            arg!(--"send-keys" "export keys to a keyserver"),
            arg!(--"receive-keys" "import keys from a keyserver"),
            arg!(--"search-keys" "search for keys on a keyserver"),
            arg!(--"refresh-keys" "update all keys from a keyserver"),
            arg!(--import "import/merge keys"),
            arg!(--"update-trustdb" "update the trust database"),
            arg!(--"print-md" "print message digests"),
            arg!(--server "run in server mode"),
            arg!(--"tofu-policy" <VALUE> "set the TOFU policy for a key"),
            arg!(-v --verbose "verbose"),
            arg!(-q --quiet "be somewhat more quiet"),
            arg!(--options <FILE> "read options from FILE"),
            arg!(--"log-file" <FILE> "write server mode logs to FILE"),
            arg!(--"default-key" <NAME> "use NAME as default secret key"),
            arg!(--"encrypt-to" <NAME> "encrypt to user ID NAME as well"),
            arg!(--group <SPEC> "set up email aliases"),
            arg!(--openpgp "use strict OpenPGP behavior"),
            arg!(-n --"dry-run" "do not make any changes"),
            arg!(-i --interactive "prompt before overwriting"),
            arg!(-a --armor "create ascii armored output"),
            arg!(-o --output <FILE> "write output to FILE"),
            arg!(--textmode "use canonical text mode"),
            arg!(-z <N> "set compress level to N (0 disables)"),
            arg!(--"auto-key-locate" <MECHANISMS> "use MECHANISMS to locate keys by mail address"),
            arg!(--"auto-key-import" "import missing key from a signature"),
            arg!(--"include-key-block" "include the public key in signatures"),
            arg!(--"disable-dirmngr" "disable all access to the dirmngr"),
            arg!(-r --recipient <USERID> "encrypt for USERID"),
            arg!(-u --"local-user" <USERID> "use USERID to sign or decrypt")
        ])
}

fn cli_gpgv_sq() -> Command {
    Command::new("gpgv-sq")
        .about(
            "This is a re-implementation and drop-in replacement of gpgv using the Sequoia OpenPGP implementation.

gpgv-sq is feature-complete. Please report any problems you encounter when replacing gpgv with gpgv-sq.

Support for trust models is limited. Currently, the Web-of-Trust (\"pgp\") and always trust (\"always\") are implemented.",
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

fn main() {
    let outdir = match env::var_os("OUT_DIR") {
        None => return (),
        Some(outdir) => outdir,
    };
    let mut gpg_sq = cli_gpg_sq();
    let mut gpgv_sq = cli_gpgv_sq();

    let shells = [Shell::Bash, Shell::Elvish, Shell::Fish, Shell::Zsh];
    for shell in shells {
        let path = generate_to(
            shell, &mut gpg_sq,
            "gpg-sq",
            outdir.clone(),
        ).unwrap();
        let pathv = generate_to(
            shell, &mut gpgv_sq,
            "gpgv-sq",
            outdir.clone(),
        ).unwrap();
    }

    let outdir = std::path::PathBuf::from(outdir);
    let man = clap_mangen::Man::new(gpg_sq);
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer).unwrap();

    std::fs::write(outdir.join("gpg-sq.1"), buffer).unwrap();

    let man = clap_mangen::Man::new(gpgv_sq);
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer).unwrap();

    std::fs::write(outdir.join("gpgv-sq.1"), buffer).unwrap();
    ()
}
