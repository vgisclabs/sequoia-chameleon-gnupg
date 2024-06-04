//! Parses GnuPG's machine readable output (`--with-colons`).
//!
//! Note: The canonical source for this module is in the Sequoia
//! Chameleon repository under `examples/explain-with-colons.rs`.

use std::io::{self, Write};

#[allow(dead_code)]
fn main() {
    let echo =
        std::env::args().nth(1).map(|a| a == "--echo").unwrap_or_default();
    let mut first = true;

    let mut line_buffer = String::new();
    while let Ok(_) = io::stdin().read_line(&mut line_buffer) {
        if line_buffer.is_empty() {
            break;
        }

        if echo {
            if ! first {
                println!();
            }
            println!("{}", line_buffer.trim_end());
            first = false;
        }
        explain(&line_buffer, &io::stdout()).unwrap();
        line_buffer.clear();
    }
}

pub fn explain<S: Write>(line: &str, mut sink: S) -> io::Result<bool> {
    let mut line = line.trim();
    if line.starts_with("+") || line.starts_with("-") {
        line = &line[1..];
    }

    let mut p = line.split(':');

    // Field 1 - Type of record
    let typ = match p.next() {
        None => {
            writeln!(sink, "Malformed line: {:?}", line)?;
            return Ok(false);
        },
        Some(t) => t,
    };

    let type_human_readable = match typ {
        "pub" => "Public key",
        "crt" => "X.509 certificate",
        "crs" => "X.509 certificate and private key available",
        "sub" => "Subkey (secondary key)",
        "sec" => "Secret key",
        "ssb" => "Secret subkey (secondary key)",
        "uid" => "User id",
        "uat" => "User attribute",
        "sig" => "Signature",
        "rev" => "Revocation signature",
        "rvs" => "Revocation signature (standalone) [since 2.2.9]",
        "fpr" => "Fingerprint",
        "fp2" => "SHA-256 fingerprint",
        "pkd" => "Public key data",
        "grp" => "Keygrip",
        "rvk" => "Revocation key",
        "tfs" => "TOFU statistics",
        "tru" => "Trust database information",
        "spk" => "Signature subpacket",
        "cfg" => "Configuration data",
        t => if t.len() == 3 && line.chars().nth(4) == Some(':') {
            "Unknown"
        } else {
            return Ok(false);
        },
    };
    writeln!(sink, "Field {:2.}:{:>22}: {}", 1, "Type", type_human_readable)?;

    match typ {
        "cfg" => explain_cfg(p, typ, sink),
        "spk" => explain_spk(p, typ, sink),
        "pkd" => explain_pkd(p, typ, sink),
        "tfs" => explain_tfs(p, typ, sink),
        "tru" => explain_tru(p, typ, sink),
        _ => explain_std(p, typ, sink),
    }
}

pub fn explain_std<'a, S>(mut p: impl Iterator<Item = &'a str>,
                          typ: &str,
                          mut sink: S)
                          -> io::Result<bool>
where
    S: Write,
{
    // Field 2 - Validity
    //
    // If the validity information is given for a UID or UAT record, it
    // describes the validity calculated based on this user ID.  If given
    // for a key record it describes the validity taken from the best
    // rated user ID.
    //
    // For X.509 certificates a 'u' is used for a trusted root
    // certificate (i.e. for the trust anchor) and an 'f' for all other
    // valid certificates.
    //
    // In "sig" records, this field may have one of these values as first
    // character:
    //
    // - ! :: Signature is good.
    // - - :: Signature is bad.
    // - ? :: No public key to verify signature or public key is not usable.
    // - % :: Other error verifying a signature
    //
    // More values may be added later.  The field may also be empty if
    // gpg has been invoked in a non-checking mode (--list-sigs) or in a
    // fast checking mode.  Since 2.2.7 '?' will also be printed by the
    // command --list-sigs if the key is not in the local keyring.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        let hr = match v {
            "o" => "Unknown (this key is new to the system)",
            "i" => "The key is invalid (e.g. due to a missing self-signature)",
            "d" => "The key has been disabled \
                    (deprecated - use the 'D' in field 12 instead)",
            "r" => "The key has been revoked",
            "e" => "The key has expired",
            "-" => "Unknown validity (i.e. no value assigned)",
            "q" => "Undefined validity.  '-' and 'q' may safely be treated as \
                    the same value for most purposes",
            "n" => "The key is not valid",
            "m" => "The key is marginal valid.",
            "f" => "The key is fully valid",
            "u" => "The key is ultimately valid.  This often means that the \
                    secret key is available, but any key may be marked as \
                    ultimately valid.",
            "w" => "The key has a well known private part.",
            "s" => "The key has special validity.  This means that it might be \
                    self-signed and expected to be used in the STEED system.",
            _ => "Unknown",
        };
        writeln!(sink, "Field {:2.}:{:>22}: {}", 2, "Validity", hr)?;
    }

    // Field 3 - Key length
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {} bits", 3, "Key length", v)?;
    }

    // Field 4 - Public key algorithm
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 4, "Public key algorithm", v)?;
    }

    // Field 5 - KeyID
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 5, "KeyID", v)?;
    }

    // Field 6 - Creation date
    //
    // The creation date of the key is given in UTC.  For UID and UAT
    // records, this is used for the self-signature date.  Note that the
    // date is usually printed in seconds since epoch, however, we are
    // migrating to an ISO 8601 format (e.g. "19660205T091500").  This is
    // currently only relevant for X.509.  A simple way to detect the new
    // format is to scan for the 'T'.  Note that old versions of gpg
    // without using the =--fixed-list-mode= option used a "yyyy-mm-tt"
    // format.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 6, "Creation date", v)?;
    }

    // Field 7 - Expiration date
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 7, "Expiration date", v)?;
    }

    // Field 8 - Certificate S/N, UID hash, trust signature info
    //
    // Used for serial number in crt records.  For UID and UAT records,
    // this is a hash of the user ID contents used to represent that
    // exact user ID.  For trust signatures, this is the trust depth
    // separated by the trust value by a space.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        let what = match typ {
            "crt" | "crs" => "Serial number",
            "uid" | "uat" => "Hashed User ID",
            "tru" => "Trust depth and value",
            _ => "Unknown",
        };
        writeln!(sink, "Field {:2.}:{:>22}: {}", 8, what, v)?;
    }

    // Field 9 -  Ownertrust
    //
    // This is only used on primary keys.  This is a single letter, but
    // be prepared that additional information may follow in future
    // versions.  For trust signatures with a regular expression, this is
    // the regular expression value, quoted as in field 10.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 9, "Ownertrust", v)?;
    }

    // Field 10 - User-ID
    //
    // The value is quoted like a C string to avoid control characters
    // (the colon is quoted =\x3a=).  For a "pub" record this field is
    // not used on --fixed-list-mode.  A UAT record puts the attribute
    // subpacket count here, a space, and then the total attribute
    // subpacket size.  In gpgsm the issuer name comes here.  The FPR and FP2
    // records store the fingerprints here.  The fingerprint of a
    // revocation key is stored here.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        if typ == "uat" {
            let mut p = v.split(' ');
            let count = p.next().unwrap_or_default();
            let total_size = p.next().unwrap_or_default();
            writeln!(sink, "Field {:2.}:{:>22}: {} subpackets, {} bytes total",
                     10, "User attribute", count, total_size)?;
        } else {
            let what = match typ {
                "fpr" | "fp2" => "Fingerprint",
                "grp" => "Keygrip",
                _ => "User ID",
            };
            writeln!(sink, "Field {:2.}:{:>22}: {}", 10, what, v)?;
        }
    }

    // Field 11 - Signature class
    //
    // Signature class as per RFC-4880.  This is a 2 digit hexnumber
    // followed by either the letter 'x' for an exportable signature or
    // the letter 'l' for a local-only signature.  The class byte of an
    // revocation key is also given here, by a 2 digit hexnumber and
    // optionally followed by the letter 's' for the "sensitive"
    // flag.  This field is not used for X.509.
    //
    // "rev" and "rvs" may be followed by a comma and a 2 digit hexnumber
    // with the revocation reason.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 11, "Signature class", v)?;
    }

    // Field 12 - Key capabilities
    //
    // The defined capabilities are:
    //
    // - e :: Encrypt
    // - s :: Sign
    // - c :: Certify
    // - a :: Authentication
    // - r :: Restricted encryption (subkey only use)
    // - t :: Timestamping
    // - g :: Group key
    // - ? :: Unknown capability
    //
    // A key may have any combination of them in any order.  In addition
    // to these letters, the primary key has uppercase versions of the
    // letters to denote the _usable_ capabilities of the entire key, and
    // a potential letter 'D' to indicate a disabled key.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 12, "Key capabilities", v)?;
    }

    // Field 13 - Issuer certificate fingerprint or other info
    //
    // Used in FPR records for S/MIME keys to store the fingerprint of
    // the issuer certificate.  This is useful to build the certificate
    // path based on certificates stored in the local key database it is
    // only filled if the issuer certificate is available. The root has
    // been reached if this is the same string as the fingerprint. The
    // advantage of using this value is that it is guaranteed to have
    // been built by the same lookup algorithm as gpgsm uses.
    //
    // For "uid" records this field lists the preferences in the same way
    // gpg's --edit-key menu does.
    //
    // For "sig", "rev" and "rvs" records, this is the fingerprint of the
    // key that issued the signature.  Note that this may only be filled
    // if the signature verified correctly.  Note also that for various
    // technical reasons, this fingerprint is only available if
    // --no-sig-cache is used.  Since 2.2.7 this field will also be set
    // if the key is missing but the signature carries an issuer
    // fingerprint as meta data.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 13, "Issuer certificate fingerprint", v)?;
    }

    // Field 14 - Flag field
    //
    // Flag field used in the --edit-key menu output
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 14, "Flag field", v)?;
    }

    // Field 15 - S/N of a token
    //
    // Used in sec/ssb to print the serial number of a token (internal
    // protect mode 1002) or a '#' if that key is a simple stub (internal
    // protect mode 1001).  If the option --with-secret is used and a
    // secret key is available for the public key, a '+' indicates this.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 15, "Token S/N", v)?;
    }

    // Field 16 - Hash algorithm
    //
    // For sig records, this is the used hash algorithm.  For example:
    // 2 = SHA-1, 8 = SHA-256.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 16, "Hash algorithm", v)?;
    }

    // Field 17 - Curve name
    //
    // For pub, sub, sec, ssb, crt, and crs records this field is used
    // for the ECC curve name.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 17, "Curve name", v)?;
    }

    // Field 18 - Compliance flags
    //
    // Space separated list of asserted compliance modes and
    // screening result for this key.
    //
    // Valid values are:
    //
    // - 8  :: The key is compliant with RFC4880bis
    // - 23 :: The key is compliant with compliance mode "de-vs".
    // - 6001 :: Screening hit on the ROCA vulnerability.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 18, "Compliance flags", v)?;
    }

    // Field 19 - Last update
    //
    // The timestamp of the last update of a key or user ID.  The update
    // time of a key is defined a lookup of the key via its unique
    // identifier (fingerprint); the field is empty if not known.  The
    // update time of a user ID is defined by a lookup of the key using a
    // trusted mapping from mail address to key.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 19, "Last update", v)?;
    }

    // Field 20 - Origin
    //
    // The origin of the key or the user ID.  This is an integer
    // optionally followed by a space and an URL.  This goes along with
    // the previous field.  The URL is quoted in C style.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 20, "Origin", v)?;
    }

    // Field 21 - Comment
    //
    // This is currently only used in "rev" and "rvs" records to carry
    // the the comment field of the recocation reason.  The value is
    // quoted in C style.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 21, "Comment", v)?;
    }

    Ok(true)
}

/// CFG - Configuration data.
pub fn explain_cfg<'a, S>(mut p: impl Iterator<Item = &'a str>,
                          _typ: &str,
                          mut sink: S)
                          -> io::Result<bool>
where
    S: Write,
{
    // Key-value pairs.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 2, "Key", v)?;
    }

    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 3, "Value", v)?;
    }

    Ok(true)
}

/// PKD - Public key data.
pub fn explain_pkd<'a, S>(mut p: impl Iterator<Item = &'a str>,
                          _typ: &str,
                          mut sink: S)
                          -> io::Result<bool>
where
    S: Write,
{
    // pkd:0:1024:B665B1435F4C2 .... FF26ABB:
    //     !  !   !-- the value
    //     !  !------ for information number of bits in the value
    //     !--------- index (eg. DSA goes from 0 to 3: p,q,g,y)
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 2, "Index", v)?;
    }

    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {} bits", 3, "Length", v)?;
    }

    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 4, "Value", v)?;
    }

    Ok(true)
}

/// SPK - Signature subpacket records.
pub fn explain_spk<'a, S>(mut p: impl Iterator<Item = &'a str>,
                          _typ: &str,
                          mut sink: S)
                          -> io::Result<bool>
where
    S: Write,
{
    // Field 2 :: Subpacket number as per RFC-4880 and later.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 2, "Subpacket number", v)?;
    }

    // Field 3 :: Flags in hex.  Currently the only two bits assigned
    //            are 1, to indicate that the subpacket came from the
    //            hashed part of the signature, and 2, to indicate the
    //            subpacket was marked critical.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 3, "Flags", v)?;
    }

    // Field 4 :: Length of the subpacket.  Note that this is the
    //            length of the subpacket, and not the length of field
    //            5 below.  Due to the need for %-encoding, the length
    //            of field 5 may be up to 3x this value.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 4, "Subpacket length", v)?;
    }

    // Field 5 :: The subpacket data.  Printable ASCII is shown as
    //            ASCII, but other values are rendered as %XX where XX
    //            is the hex value for the byte.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 5, "Subpacket data", v)?;
    }

    Ok(true)
}

pub fn explain_tfs<'a, S>(mut p: impl Iterator<Item = &'a str>,
                          _typ: &str,
                          mut sink: S)
                          -> io::Result<bool>
where
    S: Write,
{
    // Field 2 :: tfs record version (must be 1)
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 2, "Record version", v)?;
    }

    // Field 3 :: validity -  A number with validity code.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 3, "# with validity code", v)?;
    }

    // Field 4 :: signcount - The number of signatures seen.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 4, "# signatures seen", v)?;
    }

    // Field 5 :: encrcount - The number of encryptions done.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 5, "# encryptions done", v)?;
    }

    // Field 6 :: policy - A string with the policy
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 6, "Policy", v)?;
    }

    // Field 7 :: signture-first-seen - a timestamp or 0 if not known.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 7, "First seen", v)?;
    }

    // Field 8 :: signature-most-recent-seen - a timestamp or 0 if not known.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 8, "Most recent seen", v)?;
    }

    // Field 9 :: encryption-first-done - a timestamp or 0 if not known.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 9, "First encryption @", v)?;
    }

    // Field 10 :: encryption-most-recent-done - a timestamp or 0 if not known.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 10, "Recent encryption @", v)?;
    }

    Ok(true)
}

pub fn explain_tru<'a, S>(mut p: impl Iterator<Item = &'a str>,
                          _typ: &str,
                          mut sink: S)
                          -> io::Result<bool>
where
    S: Write,
{
    // - Field 2 :: Reason for staleness of trust.  If this field is
    //              empty, then the trustdb is not stale.  This field may
    //              have multiple flags in it:
    //
    //              - o :: Trustdb is old
    //              - t :: Trustdb was built with a different trust model
    //                     than the one we are using now.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 2, "Reason for staleness", v)?;
    }

    // - Field 3 :: Trust model
    //
    //              - 0 :: Classic trust model, as used in PGP 2.x.
    //              - 1 :: PGP trust model, as used in PGP 6 and later.
    //                     This is the same as the classic trust model,
    //                     except for the addition of trust signatures.
    //
    //              GnuPG before version 1.4 used the classic trust model
    //              by default. GnuPG 1.4 and later uses the PGP trust
    //              model by default.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        let v = match v {
            "0" => "classic",
            "1" => "PGP",
            v => v,
        };
        writeln!(sink, "Field {:2.}:{:>22}: {}", 3, "Trust model", v)?;
    }

    // - Field 4 :: Date trustdb was created in seconds since Epoch.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 4, "Creation time", v)?;
    }

    // - Field 5 :: Date trustdb will expire in seconds since Epoch.
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 5, "Expiration time", v)?;
    }

    // - Field 6 :: Number of marginally trusted users to introduce a new
    //              key signer (gpg's option --marginals-needed).
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 6, "Marginals needed", v)?;
    }

    // - Field 7 :: Number of completely trusted users to introduce a new
    //              key signer.  (gpg's option --completes-needed)
    //
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 7, "Completes needed", v)?;
    }

    // - Field 8 :: Maximum depth of a certification chain. (gpg's option
    //              --max-cert-depth)
    if let Some(v) = p.next().filter(|v| ! v.is_empty()) {
        writeln!(sink, "Field {:2.}:{:>22}: {}", 8, "Max cert depth", v)?;
    }

    Ok(true)
}
