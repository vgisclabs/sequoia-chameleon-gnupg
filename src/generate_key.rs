use std::{
    io::{self, BufRead},
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    cert::{
        Cert,
        CertRevocationBuilder,
    },
    crypto::{Password, Signer},
    packet::{
        Key,
        Signature,
        Packet,
        key::{
            self,
            Key4,
        },
        signature::{
            SignatureBuilder,
        },
    },
    serialize::Serialize,
    types::*,
};

use sequoia_ipc::{
    Keygrip,
};

use sequoia_cert_store::{
    Store,
    StoreUpdate,
};

use crate::{
    KeyserverURL,
    Preferences,
    babel,
    common::{BRAINPOOL_P384_OID, Common},
    status::Status,
    trust::OwnerTrustLevel,
    utils,
};

/// How many seconds to backdate signatures.
pub(crate) const SIG_BACKDATE_BY: u64 = 60;

fn check_forbid_gen_key(config: &crate::Config) -> Result<()> {
    if config.forbid_gen_key {
        config.status().emit(
            Status::Failure {
                location: "gen-key",
                error: crate::error_codes::Error::GPG_ERR_NOT_ENABLED,
            })?;
        config.error(format_args!(
            "This command is not allowed while in forbid-gen-key mode."));
        Err(anyhow::anyhow!(
            "This command is not allowed while in forbid-gen-key mode."))
    } else {
        Ok(())
    }
}

/// Dispatches the --generate-key and --full-generate-key commands.
pub fn cmd_generate_key(config: &mut crate::Config, args: &[String], full: bool)
                        -> Result<()>
{
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(real_cmd_generate_key(config, args, full))
}

async fn real_cmd_generate_key(config: &mut crate::Config<'_>, args: &[String],
                               full: bool)
                               -> Result<()>
{
    check_forbid_gen_key(config)?;

    if args.len() > 1 {
        config.wrong_args(format_args!("--generate-key [parameterfile]"));
    }

    let filename = args.get(0).cloned().unwrap_or_else(|| "-".into());
    if config.batch {
        let source = utils::open(config, &filename)?;
        proc_parameter_file(config, &filename, source).await
    } else {
        let _ = full;
        return Err(anyhow::anyhow!(
            "Interactive key generation is not yet implemented."));
    }
}

/// Dispatches the --quick-add-key command.
pub fn cmd_quick_add_key(config: &mut crate::Config, args: &[String])
                         -> Result<()>
{
    check_forbid_gen_key(config)?;
    if args.len() < 1 || args.len() > 4 {
        config.wrong_args(format_args!(
            "--quick-add-key FINGERPRINT [ALGO [USAGE [EXPIRE]]]"));
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(real_cmd_quick_add_key(config, args))
}

async fn real_cmd_quick_add_key(config: &mut crate::Config<'_>, args: &[String])
                                -> Result<()>
{
    let cert_fp: Fingerprint = args[0].parse()?;
    let algo = args.get(1).cloned().unwrap_or_else(|| "-".into());
    let usage = args.get(2).cloned().unwrap_or_else(|| "-".into());
    let expire = args.get(3).cloned().unwrap_or_else(|| "-".into());

    // This is awkward: we need to know whether a the algorithm is an
    // encryption algorithm, but in order to select the correct
    // algorithm (in case a default one is selected), we need to know
    // whether it is encryption-capable or not.  Hardcode a list.
    let for_encryption = match algo.to_ascii_lowercase().as_str() {
        "dsa" | "ecdsa" | "eddsa" | "ed25519" => false,
        _ => true,
    };

    let usage = if usage == "-" || usage.eq_ignore_ascii_case("default") {
        if for_encryption {
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption()
        } else {
            KeyFlags::empty()
                .set_signing()
        }
    } else {
        Parameter::parse_usage(&usage)?
    };

    let (pk_algo, pk_length, curve) =
        parse_key_parameter_part(config, &algo, &usage)?;

    let cert = config.keydb().lookup_by_cert_fpr(&cert_fp)?;
    // Consider the cert.
    config.status().emit(
        Status::KeyConsidered {
            fingerprint: cert.fingerprint(),
            not_selected: false,
            all_expired_or_revoked: false,
        })?;

    let vcert = cert.with_policy(config.policy(), None)?;
    let mut primary_signer =
        config.get_signer(&vcert, cert.primary_key().role_as_unspecified()).await?;

    let (subkey, binding, _subkey_signer) =
        do_create(config, Some((cert.to_cert()?, &mut primary_signer)),
                  pk_algo,
                  pk_length,
                  curve,
                  config.now(),
                  crate::utils::parse_expiration(config, &expire)?,
                  usage,
                  None,
                  &config.def_preferences.clone(),
                  None,
                  None)?;

    // Emit key created.
    config.status().emit(
        Status::KeyCreated {
            primary: false,
            subkey: true,
            fingerprint: subkey.fingerprint(),
            handle: None,
        })?;

    let cert = cert.to_cert()?.clone()
        .insert_packets(vec![
            Packet::from(subkey.clone().role_into_subordinate()),
            binding.into(),
        ])?;

    // Actually store the cert.
    config.mut_keydb().update(
        Arc::new(cert.clone().strip_secret_key_material().into()))?;

    // Store the secrets in the agent.
    let mut agent = config.connect_agent().await?;
    // See if we import a new key or subkey.
    crate::gpg_agent::import(&mut agent,
                             config.policy(),
                             &cert, &subkey,
                             config.batch).await?;

    Ok(())
}

/// Computes algorithm, key length, and curve given the algorithm
/// string and usage.
fn parse_key_parameter_part(_: &crate::Config, algo: &str, usage: &KeyFlags)
                            -> Result<(PublicKeyAlgorithm, Option<usize>,
                                       Option<Curve>)>
{
    // Case insensitive matching.
    let algo = algo.to_ascii_lowercase();

    // For the classic algorithms, split off the desired key length.
    let (algo, size) = if let Some(first_digit) =
        algo.char_indices().find_map(|(i, c)| c.is_digit(10).then_some(i))
        .filter(|_| algo != "ed25519"
                && algo != "cv25519"
                && ! algo.starts_with("nistp")
                && ! algo.starts_with("brainpool"))
    {
        (&algo[..first_digit], Some(algo[first_digit..].parse::<usize>()?))
    } else {
        (algo.as_str(), None)
    };

    // For the classic ECC curves, determine the correct pk algorithm.
    let pk_ecc = if usage.for_signing() {
        PublicKeyAlgorithm::ECDSA
    } else {
        PublicKeyAlgorithm::ECDH
    };

    match algo.to_ascii_lowercase().as_str() {
        "" | "-" | "default" | "rsa" =>
            Ok((PublicKeyAlgorithm::RSAEncryptSign, size.or(Some(3072)), None)),
        "future-default" | "futuredefault" => if usage.for_signing() {
            Ok((PublicKeyAlgorithm::EdDSA, None, Some(Curve::Ed25519)))
        } else {
            Ok((PublicKeyAlgorithm::ECDH, None, Some(Curve::Cv25519)))
        },
        "dsa" => Ok((PublicKeyAlgorithm::DSA, size.or(Some(2048)), None)),
        "elg" =>
            Ok((PublicKeyAlgorithm::ElGamalEncrypt, size.or(Some(2048)), None)),
        "ed25519" =>
            Ok((PublicKeyAlgorithm::EdDSA, None, Some(Curve::Ed25519))),
        "cv25519" =>
            Ok((PublicKeyAlgorithm::ECDH, None, Some(Curve::Cv25519))),
        "nistp256" => Ok((pk_ecc, None, Some(Curve::NistP256))),
        "nistp384" => Ok((pk_ecc, None, Some(Curve::NistP384))),
        "nistp521" => Ok((pk_ecc, None, Some(Curve::NistP521))),
        "brainpoolp256r1" => Ok((pk_ecc, None, Some(Curve::BrainpoolP256))),
        "brainpoolp384r1" =>
            Ok((pk_ecc, None, Some(Curve::Unknown(BRAINPOOL_P384_OID.into())))),
        "brainpoolp521r1" => Ok((pk_ecc, None, Some(Curve::BrainpoolP512))),
        _ => Err(anyhow::anyhow!(
            "Key generation failed: Unknown elliptic curve")),
    }
}

#[derive(Debug)]
enum Parameter {
    KeyType(PublicKeyAlgorithm),
    KeyLength(usize),
    KeyCurve(Curve),
    KeyUsage(KeyFlags),
    SubkeyType(PublicKeyAlgorithm),
    SubkeyLength(usize),
    SubkeyCurve(Curve),
    SubkeyUsage(KeyFlags),
    UserID(openpgp::packet::UserID),
    NameReal(String),
    NameEmail(String),
    NameComment(String),
    ExpireDate(Option<Duration>),
    SubkeyExpireDate(Option<Duration>),
    CreationDate(SystemTime),
    Passphrase(Password),
    Preferences(Preferences),
    Revoker(RevocationKey),
    Handle(String),
    Keyserver(crate::KeyserverURL),
    KeyGrip(Keygrip),
    SubkeyGrip(Keygrip),
}

impl Parameter {
    fn key_type(&self) -> Option<PublicKeyAlgorithm> {
        if let Parameter::KeyType(t) = self { Some(*t) } else { None }
    }

    fn key_length(&self) -> Option<usize> {
        if let Parameter::KeyLength(t) = self { Some(*t) } else { None }
    }

    fn key_curve(&self) -> Option<Curve> {
        if let Parameter::KeyCurve(t) = self { Some(t.clone()) } else { None }
    }

    fn key_usage(&self) -> Option<KeyFlags> {
        if let Parameter::KeyUsage(t) = self { Some(t.clone()) } else { None }
    }

    fn subkey_type(&self) -> Option<PublicKeyAlgorithm> {
        if let Parameter::SubkeyType(t) = self { Some(*t) } else { None }
    }

    fn subkey_length(&self) -> Option<usize> {
        if let Parameter::SubkeyLength(t) = self { Some(*t) } else { None }
    }

    fn subkey_curve(&self) -> Option<Curve> {
        if let Parameter::SubkeyCurve(t) = self { Some(t.clone()) } else { None }
    }

    fn subkey_usage(&self) -> Option<KeyFlags> {
        if let Parameter::SubkeyUsage(t) = self { Some(t.clone()) } else { None }
    }

    fn userid(&self) -> Option<&openpgp::packet::UserID> {
        if let Parameter::UserID(u) = self { Some(u) } else { None }
    }

    fn name_real(&self) -> Option<&str> {
        if let Parameter::NameReal(v) = self { Some(v) } else { None }
    }

    fn name_comment(&self) -> Option<&str> {
        if let Parameter::NameComment(v) = self { Some(v) } else { None }
    }

    fn name_email(&self) -> Option<&str> {
        if let Parameter::NameEmail(v) = self { Some(v) } else { None }
    }

    fn preferences(&self) -> Option<&Preferences> {
        if let Parameter::Preferences(v) = self { Some(v) } else { None }
    }

    fn keyserver(&self) -> Option<&crate::KeyserverURL> {
        if let Parameter::Keyserver(v) = self { Some(v) } else { None }
    }

    fn revoker(&self) -> Option<&RevocationKey> {
        if let Parameter::Revoker(v) = self { Some(v) } else { None }
    }

    fn creation_date(&self) -> Option<SystemTime> {
        if let Parameter::CreationDate(v) = self { Some(*v) } else { None }
    }

    fn expiration_date(&self) -> Option<Duration> {
        if let Parameter::ExpireDate(v) = self { *v } else { None }
    }

    fn subkey_expiration_date(&self) -> Option<Duration> {
        if let Parameter::SubkeyExpireDate(v) = self { *v } else { None }
    }

    fn passphrase(&self) -> Option<&Password> {
        if let Parameter::Passphrase(v) = self { Some(v) } else { None }
    }

    fn parse_usage(s: &str) -> Result<KeyFlags> {
        s.parse::<Usage>().map(Into::into)
    }

    fn parse_revocation_key(s: &str) -> Result<RevocationKey> {
        let mut p = s.split(':');
        let pk_algo: PublicKeyAlgorithm =
            p.next().ok_or(anyhow::anyhow!("no algorithm given"))?
            .parse::<u8>()?.into();
        let fp_flags =
            p.next().ok_or(anyhow::anyhow!("no fingerprint given"))?.trim();

        let (fp, sensitive) =
            if fp_flags.to_lowercase().ends_with("sensitive") {
                (&fp_flags[..fp_flags.len() - "sensitive".len()], true)
            } else {
                (fp_flags, false)
            };

        Ok(RevocationKey::new(pk_algo, fp.parse()?, sensitive))
    }

    fn parse_preferences(s: &str) -> Result<Option<Preferences>> {
        Preferences::parse(s)
    }

    fn parse_creation(s: &str) -> Result<SystemTime>
    {
        // XXX have a closer look
        crate::utils::parse_iso_date(s)
    }

    fn parse_algo(s: &str, for_signing: bool) -> Result<PublicKeyAlgorithm>
    {
        if let Ok(n) = s.parse::<u8>() {
            return Ok(PublicKeyAlgorithm::from(n));
        }

        match s.to_lowercase().as_str() {
            "default" => Ok(PublicKeyAlgorithm::RSAEncryptSign),
            "future-default" => Ok(if for_signing {
                PublicKeyAlgorithm::EdDSA
            } else {
                PublicKeyAlgorithm::ECDH
            }),
            "elg-e" | "elg" => Ok(PublicKeyAlgorithm::ElGamalEncrypt),
            "eddsa" => Ok(PublicKeyAlgorithm::EdDSA),
            "ecdsa" => Ok(PublicKeyAlgorithm::ECDSA),
            "ecdh" => Ok(PublicKeyAlgorithm::ECDH),
            n => n.parse::<babel::Fish<PublicKeyAlgorithm>>().map(|f| f.0),
        }
    }
}

/// Key usage flags.
#[derive(Default)]
struct Usage {
    certify: bool,
    sign: bool,
    authenticate: bool,
    encrypt: bool,
}

impl std::str::FromStr for Usage {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut usage = Usage::default();
        for u in s.split(&[':', ' ', ',']) {
            match u.trim().to_lowercase().as_str() {
                "cert" => usage.certify = true,
                "sign" => usage.sign = true,
                "auth" => usage.authenticate = true,
                "encr" | "encrypt" => usage.encrypt = true,
                t => return
                    Err(anyhow::anyhow!("unknown usage {:?}", t)),
            }
        }
        Ok(usage)
    }
}

impl From<Usage> for KeyFlags {
    fn from(u: Usage) -> KeyFlags {
        KeyFlags::empty()
            .set_certification_to(u.certify)
            .set_signing_to(u.sign)
            .set_authentication_to(u.authenticate)
            .set_storage_encryption_to(u.encrypt)
            .set_transport_encryption_to(u.encrypt)
    }
}

async fn proc_parameter_file<'a>(config: &mut crate::Config<'_>,
                            filename: &str,
                            source: Box<dyn io::Read + Send + Sync + 'a>)
                            -> Result<()>
{
    let mut pubring = None;
    let mut dry_run = false;
    let mut no_protection = false;
    let mut parameters = Vec::new();

    let mut last_line = 0;
    for (i, line) in io::BufReader::new(source).lines().enumerate() {
        last_line = i;

        let line = line.with_context(
            || format!("Non-UTF8 line {} in key generation script.", i))?;
        let line = line.trim();

        // Empty lines and comments.
        if line.is_empty() || line.starts_with("#") {
            continue;
        }

        if line.starts_with("%") {
            // Dispatch control statement.
            let mut p = line.splitn(2, char::is_whitespace);
            let keyword = p.next().unwrap();
            let value = p.next().map(|v| v.trim_start());

            match keyword.to_lowercase().as_str() {
                "%echo" => config.info(format_args!("{}", value.unwrap_or(""))),
                "%dry-run" => dry_run = true,
                "%ask-passphrase" => (), // Ignore.
                "%no-ask-passphrase" => (), // Ignore.
                "%no-protection" => no_protection = true,
                "%transient-key" => {
                    // If this directive is given, gpg-agent may use a
                    // less secure random number generator.  Since we
                    // generate the keys instead of asking gpg-agent
                    // to do that (because we want to use a different
                    // secret key store some day), we simply ignore
                    // this.
                },
                "%commit" => {
                    create_key(config, filename, i,
                               dry_run, no_protection,
                               pubring.take(),
                               std::mem::take(&mut parameters)).await?;
                },
                "%pubring" => {
                    pubring = value.map(ToString::to_string);
                }
                "%secring" => (), // Ignore.
                _ => config.info(format_args!(
                    "skipping control '{}' ({})",
                    keyword, value.unwrap_or(""))),
            }

            continue;
        }

        let error_out = |message| -> anyhow::Error {
            config.error(format_args!("{}:{}: {}", filename, i + 1, message));
            anyhow::Error::msg(message)
        };

        // Parse parameter.
        let mut p = line.splitn(2, ':');
        let keyword = p.next().unwrap();
        let value = p.next().map(|v| v.trim_start())
            .ok_or_else(|| error_out("missing colon"))?;
        if value.is_empty() {
            return Err(error_out("missing argument"));
        }

        let p = match keyword.to_lowercase().as_str() {
	    "key-type" => Parameter::KeyType(
                Parameter::parse_algo(value, true)
                    .map_err(|_| error_out("invalid algorithm"))?),
	    "key-length" => Parameter::KeyLength(
                value.parse().map_err(|_| error_out("invalid "))?),
	    "key-curve" => Parameter::KeyCurve(
                value.parse::<babel::Fish<Curve>>().map(|v| v.0)
                    .map_err(|_| error_out("invalid curve"))?),
	    "key-usage" => Parameter::KeyUsage(
                Parameter::parse_usage(value)
                    .map_err(|_| error_out("invalid usage list"))?),
	    "subkey-type" => Parameter::SubkeyType(
                Parameter::parse_algo(value, true)
                    .map_err(|_| error_out("invalid algorithm"))?),
	    "subkey-length" => Parameter::SubkeyLength(
                value.parse().map_err(|_| error_out("invalid "))?),
	    "subkey-curve" => Parameter::SubkeyCurve(
                value.parse::<babel::Fish<Curve>>().map(|v| v.0)
                    .map_err(|_| error_out("invalid curve"))?),
	    "subkey-usage" => Parameter::SubkeyUsage(
                Parameter::parse_usage(value)
                    .map_err(|_| error_out("invalid usage list"))?),
	    "name-real" => Parameter::NameReal(value.into()),
	    "name-email" => Parameter::NameEmail(value.into()),
	    "name-comment" => Parameter::NameComment(value.into()),
	    "expire-date" => Parameter::ExpireDate(
                crate::utils::parse_expiration(config, value)
                    .map_err(|_| error_out("invalid expire date"))?),
	    "creation-date" => Parameter::CreationDate(
                Parameter::parse_creation(value)
                .map_err(|_| error_out("invalid creation date"))?),
	    "passphrase" => Parameter::Passphrase(value.into()),
	    "preferences" => Parameter::Preferences(
                Parameter::parse_preferences(value)?.unwrap_or_else(
                    || config.def_preferences.clone())),
	    "revoker" => Parameter::Revoker(
                Parameter::parse_revocation_key(value)?),
            "handle" => Parameter::Handle(value.into()),
            "keyserver" => Parameter::Keyserver(
                value.parse().map_err(|_| error_out("invalid keyserver url"))?),
            "keygrip" => Parameter::KeyGrip(
                value.parse().map_err(|_| error_out("invalid "))?),
            "key-grip" => Parameter::KeyGrip(
                value.parse().map_err(|_| error_out("invalid "))?),
            "subkey-grip" => Parameter::SubkeyGrip(
                value.parse().map_err(|_| error_out("invalid "))?),
            _ => todo!(),
        };

        // If we start a new key, implicitly commit the current one.
        if let Parameter::KeyType(_) = &p {
            create_key(config, filename, i,
                       dry_run, no_protection,
                       pubring.take(),
                       std::mem::take(&mut parameters)).await?;
        }

        parameters.push(p);
    }

    // Implicitly commit the current key.
    create_key(config, filename, last_line,
               dry_run, no_protection, pubring,
               std::mem::take(&mut parameters)).await?;

    Ok(())
}

async fn create_key(config: &mut crate::Config<'_>, filename: &str, i: usize,
                    dry_run: bool, no_protection: bool,
                    pubring: Option<String>,
                    mut parameters: Vec<Parameter>)
                    -> Result<()>
{
    if parameters.is_empty() {
        // This is convenient to implement implicit commits in
        // `proc_parameter_file`.
        return Ok(());
    }

    let error_out = |message| -> anyhow::Error {
        config.error(format_args!("{}:{}: {}", filename, i, message));
        anyhow::Error::msg(message)
    };

    // Like error_out, but less specific.
    let fail = |message| -> anyhow::Error {
        config.error(format_args!("{}: {}", filename, message));
        anyhow::Error::msg(message)
    };

    let key_type =
        parameters.iter().find_map(Parameter::key_type)
        .ok_or_else(|| fail("no Key-Type specified"))?;
    let key_length =
        parameters.iter().find_map(Parameter::key_length);
    let key_curve =
        parameters.iter().find_map(Parameter::key_curve);
    let key_usage =
        parameters.iter().find_map(Parameter::key_usage)
        .unwrap_or_else(|| {
            let mut flags = KeyFlags::empty();
            if key_type.for_signing() {
                flags = flags
                    .set_certification()
                    .set_signing()
                    .set_authentication();
            }
            if key_type.for_encryption() {
                flags = flags
                    .set_transport_encryption()
                    .set_storage_encryption();
            }
            flags
        });

    if ((key_usage.for_signing()
        || key_usage.for_certification()
        || key_usage.for_authentication()) && ! key_type.for_signing())
        || ((key_usage.for_transport_encryption()
             || key_usage.for_storage_encryption())
            && ! key_type.for_encryption())
    {
        return Err(error_out(
            format!("specified Key-Usage not allowed for algo {}",
                    u8::from(key_type))));
    }

    let subkey = if let Some(subkey_type) =
        parameters.iter().find_map(Parameter::subkey_type)
    {
        let subkey_usage =
            parameters.iter().find_map(Parameter::subkey_usage)
            .unwrap_or_else(|| {
                let mut flags = KeyFlags::empty();
                if subkey_type.for_signing() {
                    flags = flags.set_signing()
                        .set_authentication();
                }
                if subkey_type.for_encryption() {
                    flags = flags
                        .set_transport_encryption()
                        .set_storage_encryption();
                }
                flags
            });

        if ((subkey_usage.for_signing()
             || subkey_usage.for_certification()
             || subkey_usage.for_authentication()) && ! subkey_type.for_signing())
            || ((subkey_usage.for_transport_encryption()
                 || subkey_usage.for_storage_encryption())
                && ! subkey_type.for_encryption())
        {
            return Err(error_out(
                format!("specified Subkey-Usage not allowed for algo {}",
                        u8::from(subkey_type))));
        }

        Some((subkey_type, subkey_usage))
    } else {
        None
    };

    let userid = parameters.iter().find_map(Parameter::userid);
    if userid.is_none() {
        let mut parts = Vec::with_capacity(3);
        if let Some(p) = parameters.iter().find_map(Parameter::name_real) {
            parts.push(p.to_string());
        }

        if let Some(p) = parameters.iter().find_map(Parameter::name_comment) {
            parts.push(format!("({})", p));
        }

        if let Some(p) = parameters.iter().find_map(Parameter::name_email) {
            parts.push(format!("<{}>", p));
        }

        parameters.push(Parameter::UserID(parts.join(" ").into()));
    }

    let key_creation_date = parameters.iter().find_map(Parameter::creation_date)
        .unwrap_or_else(|| {
            config.now() - Duration::new(SIG_BACKDATE_BY, 0)
        });
    let key_validity_period =
        parameters.iter().find_map(Parameter::expiration_date);
    if let Some(v) = key_validity_period {
        parameters.push(Parameter::SubkeyExpireDate(Some(v)));
    }
    let subkey_validity_period =
        parameters.iter().find_map(Parameter::subkey_expiration_date);
    let mut passphrase = parameters.iter().find_map(Parameter::passphrase);

    let mut agent = config.connect_agent().await?;
    let passphrase_store;
    if passphrase.is_none() && ! no_protection {
        passphrase_store = crate::gpg_agent::get_passphrase(
            &mut agent, &None, &None,
            Some("Passphrase:".into()),
            Some("Please enter passphrase to protect your new key".into()),
            false, 1, true, true, |_, _| None).await?;
        passphrase = Some(&passphrase_store);
    };


    let preferences = parameters.iter().find_map(Parameter::preferences)
        .map(Clone::clone).unwrap_or(config.def_preferences.clone());
    let preferred_keyserver = parameters.iter().find_map(Parameter::keyserver)
        .or(config.def_keyserver_url.as_ref())
        .map(Clone::clone);
    let revoker = parameters.iter().find_map(Parameter::revoker)
        .map(Clone::clone);

    // Actually start generating the artifact here.
    if dry_run {
        config.info(format_args!("dry-run mode - key generation skipped"));
        return Ok(())
    }

    // Create the primary key.
    let (primary, binding, primary_signer) =
        do_create(config, None, key_type, key_length, key_curve,
                  key_creation_date, key_validity_period,
                  key_usage.clone(),
                  passphrase,
                  &preferences,
                  preferred_keyserver.as_ref(),
                  revoker.as_ref())?;
    let primary = primary.role_into_primary();
    let mut primary_signer = primary_signer.expect("to have a primary signer");

    // Construct a skeleton cert.  We need this to bind the new
    // components to.
    let cert = Cert::try_from(vec![
        openpgp::Packet::SecretKey(primary.clone()),
    ])?;
    // We will, however, collect any signatures and components in
    // a separate vector, and only add them in the end, so that we
    // canonicalize the new certificate just once.
    let mut acc = vec![
        openpgp::Packet::from(binding),
    ];

    // Sign UserIDs.
    let mut emitted_primary_user_thing = false;
    for uid in parameters.iter().filter_map(Parameter::userid) {
        let sig = SignatureBuilder::new(SignatureType::PositiveCertification);
        let sig = signature_common(sig, key_creation_date)?;
        let mut sig = add_primary_key_metadata(
            sig, key_validity_period, key_usage.clone(),
            &preferences,
            preferred_keyserver.as_ref(),
            revoker.as_ref())?;

        // Make sure we mark exactly one User ID or Attribute as
        // primary.
        if ! emitted_primary_user_thing {
            // Implicitly mark the first as primary.
            sig = sig.set_primary_userid(true)?;
            emitted_primary_user_thing = true;
        }

        let signature = uid.bind(&mut primary_signer, &cert, sig)?;
        acc.push(uid.clone().into());
        acc.push(signature.into());
    }

    // Generate and sign subkey.
    if let Some((subkey_type, subkey_usage)) = &subkey {
        let subkey_length =
            parameters.iter().find_map(Parameter::subkey_length);
        let subkey_curve =
            parameters.iter().find_map(Parameter::subkey_curve);

        let (subkey, binding, _subkey_signer) =
            do_create(config, Some((&cert, &mut primary_signer)),
                      *subkey_type, subkey_length, subkey_curve,
                      key_creation_date, subkey_validity_period,
                      subkey_usage.clone(),
                      passphrase,
                      &preferences,
                      preferred_keyserver.as_ref(),
                      revoker.as_ref())?;
        acc.push(subkey.role_into_subordinate().into());
        acc.push(binding.into());
    }

    // Now add the new components and canonicalize once.
    let cert = cert.insert_packets(acc)?;

    // Build a revocation certificate.
    let revocation = CertRevocationBuilder::new()
        .set_signature_creation_time(key_creation_date)?
        .set_reason_for_revocation(
            ReasonForRevocation::Unspecified, b"Unspecified")?
        .build(&mut primary_signer, &cert, None)?;

    // Consider the cert.
    config.status().emit(
        Status::KeyConsidered {
            fingerprint: cert.fingerprint(),
            not_selected: false,
            all_expired_or_revoked: false,
        })?;

    // Actually store the cert.
    if let Some(f) = pubring {
        // In the alternative keyring.
        let mut f = std::fs::File::options().append(true).create(true).open(f)?;
        cert.serialize(&mut f)?;
    } else {
        // In the database.
        config.mut_keydb().update(
            Arc::new(cert.clone().strip_secret_key_material().into()))?;
    }

    // Store the secrets in the agent.
    for subkey in cert.keys().secret() {
        // See if we import a new key or subkey.
        crate::gpg_agent::import(&mut agent,
                                 config.policy(),
                                 &cert, &subkey,
                                 config.batch).await?;
    }

    // Set to ultimately trusted.
    config.trustdb.set_ownertrust(
        cert.fingerprint(), OwnerTrustLevel::Ultimate.into());
    config.trustdb.commit_overlay(config.keydb())?;

    // Store the revocation certificate.
    config.store_revocation(&cert, revocation)?;

    // Emit key created.
    config.status().emit(
        Status::KeyCreated {
            primary: true,
            subkey: subkey.is_some(),
            fingerprint: cert.fingerprint(),
            handle: None, // XXX: get the handle from the gpg-agent
        })?;

    Ok(())
}


/// Creates the primary key and a direct key signature.
fn do_create(config: &mut crate::Config<'_>,
             cert: Option<(&Cert, &mut dyn Signer)>,
             algo: PublicKeyAlgorithm,
             bits: Option<usize>,
             curve: Option<Curve>,
             creation_time: SystemTime,
             validity_period: Option<Duration>,
             flags: KeyFlags,
             password: Option<&Password>,
             preferences: &Preferences,
             preferred_keyserver: Option<&KeyserverURL>,
             revoker: Option<&RevocationKey>)
             -> Result<(Key<key::SecretParts, key::UnspecifiedRole>,
                        Signature,
                        Option<Box<dyn Signer>>)>
{
    let mut key: Key<key::SecretParts, key::UnspecifiedRole> = match algo {
        PublicKeyAlgorithm::RSAEncryptSign =>
            Key4::generate_rsa(bits.unwrap_or(3072))?,
        PublicKeyAlgorithm::EdDSA =>
            Key4::generate_ecc(true, curve.unwrap_or(Curve::Ed25519))?,
        PublicKeyAlgorithm::ECDSA =>
            Key4::generate_ecc(true, curve.unwrap_or(Curve::NistP256))?,
        PublicKeyAlgorithm::ECDH =>
            Key4::generate_ecc(false, curve.unwrap_or(Curve::Cv25519))?,
        PublicKeyAlgorithm::DSA => {
            if bits != Some(1024) {
                config.info(format_args!(
                    "WARNING: some OpenPGP programs can't \
                     handle a DSA key with this digest size"));
            }
            Key4::generate_dsa(bits.unwrap_or(3072))?
        },
        PublicKeyAlgorithm::ElGamalEncrypt =>
            Key4::generate_elgamal(bits.unwrap_or(3072))?,
        _ => return Err(anyhow::anyhow!(
            "Generation of {} not supported", algo)),
    }.into();
    key.set_creation_time(creation_time)?;

    if let Some((cert, primary_signer)) = cert {
        let mut subkey = key.role_into_subordinate();
        let sig = SignatureBuilder::new(SignatureType::SubkeyBinding);
        let sig = signature_common(sig, creation_time)?;
        let mut builder = sig
            .set_key_flags(flags.clone())?
            .set_key_validity_period(validity_period)?;

        if flags.for_certification() || flags.for_signing()
            || flags.for_authentication()
        {
            // We need to create a primary key binding signature.
            let mut subkey_signer = subkey.clone().into_keypair()
                .expect("key generated above has a secret");
            let backsig =
                SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                .set_signature_creation_time(creation_time)?
            // GnuPG wants at least a 512-bit hash for P521 keys.
                .set_hash_algo(HashAlgorithm::SHA512)
                .sign_primary_key_binding(&mut subkey_signer,
                                          &cert.primary_key(),
                                          &subkey)?;
            builder = builder.set_embedded_signature(backsig)?;
        }

        let sig = subkey.bind(primary_signer, &cert, builder)?;

        if let Some(password) = password {
            subkey.secret_mut().encrypt_in_place(password)?;
        }

        Ok((subkey.role_into_unspecified(), sig, None))
    } else {
        let sig = SignatureBuilder::new(SignatureType::DirectKey);
        let sig = signature_common(sig, creation_time)?;
        let sig = add_primary_key_metadata(sig, validity_period, flags,
                                           preferences,
                                           preferred_keyserver,
                                           revoker)?;

        //if let Some(ref revocation_keys) = self.revocation_keys {
        //    sig = sig.set_revocation_key(revocation_keys.clone())?;
        //}

        let mut signer = key.clone().into_keypair()
            .expect("key generated above has a secret");
        let sig = sig.sign_direct_key(
            &mut signer, key.parts_as_public().role_as_primary())?;

        if let Some(password) = password {
            key.secret_mut().encrypt_in_place(password)?;
        }

        Ok((key, sig, Some(Box::new(signer))))
    }
}

/// Common settings for generated signatures.
fn signature_common(builder: SignatureBuilder,
                    creation_time: SystemTime)
                    -> Result<SignatureBuilder>
{
    builder
    // GnuPG wants at least a 512-bit hash for P521 keys.
        .set_hash_algo(HashAlgorithm::SHA512)
        .set_signature_creation_time(creation_time)
}


/// Adds primary key metadata to the signature.
fn add_primary_key_metadata(builder: SignatureBuilder,
                            validity_period: Option<Duration>,
                            flags: KeyFlags,
                            preferences: &Preferences,
                            preferred_keyserver: Option<&KeyserverURL>,
                            revoker: Option<&RevocationKey>)
                            -> Result<SignatureBuilder>
{
    let mut builder = builder
        .set_features(Features::sequoia())?
        .set_key_flags(flags)?
        .set_key_validity_period(validity_period)?
        .set_preferred_hash_algorithms(preferences.hash.clone())?
        .set_preferred_symmetric_algorithms(preferences.symmetric.clone())?
        .set_preferred_compression_algorithms(preferences.compression.clone())?;

    // XXX: Should we honor the MDC preference?  I think not.

    if ! preferences.ks_modify {
        builder = builder.set_key_server_preferences(
            KeyServerPreferences::empty().set_no_modify())?;
    }

    if let Some(ks) = preferred_keyserver {
        builder = builder.set_preferred_key_server(ks.url())?;
    }

    if let Some(r) = revoker {
        builder = builder.set_revocation_key(vec![r.clone()])?;
    }

    Ok(builder)
}
