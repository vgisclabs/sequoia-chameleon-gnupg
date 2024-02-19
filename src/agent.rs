use std::{
    convert::TryFrom,
    collections::BTreeSet,
    sync::Arc,
};
use anyhow::Result;

use sequoia_openpgp as openpgp;
use sequoia_ipc as ipc;
use openpgp::{
    Cert,
    Fingerprint,
    crypto::{
        Password,
        S2K,
        mem::Protected,
        mpi::SecretKeyChecksum,
    },
    packet::{
        Key,
        key::{
            PublicParts,
            SecretParts,
            UnspecifiedRole,
            SecretKeyMaterial,
        },
        SKESK,
    },
    policy::Policy,
};
use ipc::{
    Keygrip,
    gnupg::Agent,
    assuan::{Response, escape},
};

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;

use futures::stream::StreamExt;

use crate::{
    babel,
};

trace_module!(TRACE);

/// Controls how gpg-agent inquires passwords.
pub enum PinentryMode {
    /// Ask using pinentry.  This is the default.
    Ask,
    /// Cancel all inquiries.
    Cancel,
    /// Refuse all inquiries.
    Error,
    /// Ask the frontend (us) for passwords.
    Loopback,
}

impl Default for PinentryMode {
    fn default() -> Self {
        PinentryMode::Ask
    }
}

impl PinentryMode {
    /// Returns a string representation usable with the gpg-agent.
    pub fn as_str(&self) -> &'static str {
        match self {
            PinentryMode::Ask => "ask",
            PinentryMode::Cancel => "cancel",
            PinentryMode::Error => "error",
            PinentryMode::Loopback => "loopback",
        }
    }
}

impl std::str::FromStr for PinentryMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ask" => Ok(PinentryMode::Ask),
            "default" => Ok(PinentryMode::Ask),
            "cancel" => Ok(PinentryMode::Cancel),
            "error" => Ok(PinentryMode::Error),
            "loopback" => Ok(PinentryMode::Loopback),
            _ => Err(anyhow::anyhow!("Unknown pinentry mode {:?}", s)),
        }
    }
}

pub async fn connect(ctx: ipc::gnupg::Context) -> Result<Agent> {
    tracer!(TRACE, "connect");

    async fn transaction(ctx: ipc::gnupg::Context) -> Result<Agent> {
        t!("Starting daemon if not running");

        if false {
            // XXX: Currently, this will invoke gpgconf
            // --create-socketdir, and fail if that fails.  It will
            // also spew all sorts of output to stderr.
            ctx.start("gpg-agent")?;
        } else {
            // In the mean time, manually start the agent.
            let mut c = std::process::Command::new("gpgconf");
            if let Some(h) = ctx.homedir() {
                c.env("GNUPGHOME", h);
                c.arg("--homedir").arg(&h.display().to_string());
            }
            c.arg("--launch").arg("gpg-agent");
            c.status()?;
        }

        t!("Connecting to daemon");
        Ok(ipc::gnupg::Agent::connect(&ctx).await?)
    }

    transaction(ctx).await.map_err(|e| {
        t!("failed: {}", e);
        e
    })
}

/// Returns a convenient Err value for use in the state machines
/// below.
async fn operation_failed<T>(agent: &mut Agent, message: &Option<String>)
                       -> Result<T>
{
    tracer!(TRACE, "operation_failed");

    if let Some(response) = agent.next().await {
        t!("Got unexpected response {:?}", response);
        Err(ipc::gnupg::Error::ProtocolError(
            format!("Got unexpected response {:?}", response))
            .into())
    } else {
        t!("Operation failed: {}",
           message.as_ref().map(|e| e.as_str())
           .unwrap_or_else(|| "Unknown reason"));
        Err(ipc::gnupg::Error::OperationFailed(
            message.as_ref().map(|e| e.to_string())
                .unwrap_or_else(|| "Unknown reason".into()))
            .into())
    }
}

/// Returns a convenient Err value for use in the state machines
/// below.
fn protocol_error<T>(response: &Response) -> Result<T> {
    tracer!(TRACE, "operation_failed");

    t!("Got unexpected response {:?}", response);
    Err(ipc::gnupg::Error::ProtocolError(
        format!("Got unexpected response {:?}", response))
        .into())
}

async fn acknowledge_inquiry(agent: &mut Agent) -> Result<()> {
    agent.send("END")?;
    agent.next().await; // Dummy read to send END.
    Ok(())
}

pub async fn send_simple<C>(agent: &mut ipc::gnupg::Agent, cmd: C)
                            -> Result<Protected>
where
    C: AsRef<str>,
{
    tracer!(TRACE, "send_simple");

    t!("> {}", cmd.as_ref());
    agent.send(cmd.as_ref())?;
    let mut data = Vec::new();
    while let Some(response) = agent.next().await {
        match response? {
            Response::Data { partial } => {
                // Securely erase partial.
                let partial = Protected::from(partial);
                data.extend_from_slice(&partial);
            },
            Response::Ok { .. }
            | Response::Comment { .. }
            | Response::Status { .. } =>
                (), // Ignore.
            Response::Error { ref message, .. } =>
                return operation_failed(agent, message).await,
            response =>
                return protocol_error(&response),
        }
    }

    t!("< {}", String::from_utf8_lossy(&data));
    Ok(data.into())
}

/// Makes the agent ask for a password.
pub async fn get_passphrase<P>(agent: &mut ipc::gnupg::Agent,
                               cache_id: &Option<String>,
                               err_msg: &Option<String>,
                               prompt: Option<String>,
                               desc_msg: Option<String>,
                               newsymkey: bool,
                               repeat: usize,
                               check: bool,
                               qualitybar: bool,
                               mut pinentry_cb: P)
                               -> Result<Password>
where
    P: FnMut(&mut Agent, Response) -> Option<Protected>,
{
    agent.send(format!(
        "GET_PASSPHRASE --data --repeat={}{}{}{} -- {} {} {} {}",
        repeat,
        if (repeat > 0 && check) || newsymkey { " --check" } else { "" },
        if qualitybar { " --qualitybar" } else { "" },
        if newsymkey { " --newsymkey" } else { "" },
        cache_id.as_ref().map(escape).unwrap_or_else(|| "X".into()),
        err_msg.as_ref().map(escape).unwrap_or_else(|| "X".into()),
        prompt.as_ref().map(escape).unwrap_or_else(|| "X".into()),
        desc_msg.as_ref().map(escape).unwrap_or_else(|| "X".into()),
    ))?;

    let mut password = Vec::new();
    while let Some(response) = agent.next().await {
        match response? {
            r @ Response::Ok { .. }
            | r @ Response::Comment { .. }
            | r @ Response::Status { .. } => {
                pinentry_cb(agent, r);
            },
            r @ Response::Inquire { .. } => {
                if let Some(data) = pinentry_cb(agent, r) {
                    agent.data(&data[..])?;
                    // Dummy read to send data.
                    while let Some(r) = agent.next().await {
                        if matches!(r?, Response::Ok { .. }) {
                            break;
                        }
                    }

                    // Sending the data acknowledges the inquiry.
                } else {
                    acknowledge_inquiry(agent).await?;
                }
            },
            Response::Data { partial } => {
                // Securely erase partial.
                let partial = Protected::from(partial);
                password.extend_from_slice(&partial);
            },
            Response::Error { ref message, .. } =>
                return operation_failed(agent, message).await,
        }
    }
    let password = Password::from(password);

    Ok(password)
}

/// Computes the cache id for a SKESK.
///
/// If an S2K algorithm unsupported by the caching id algorithm is
/// given, this function returns `None`.
pub fn cacheid_of(s2k: &S2K) -> Option<String> {
    #[allow(deprecated)]
    let salt = match s2k {
        S2K::Iterated { salt, .. } => &salt[..8],
        S2K::Salted { salt, .. } => &salt[..8],
        _ => return None,
    };

    Some(format!("S{}", openpgp::fmt::hex::encode(&salt)))
}

/// Computes the cache id for a set of SKESKs.
///
/// GnuPG prompts for a password for each SKESK separately, and uses
/// the first eight bytes of salt from the S2K.  We ask for one
/// password and try it with every SKESK.  Therefore, we have to cache
/// that we asked for a set of SKESKs, i.e. this message.  To that
/// end, we xor the first eight bytes of salt from every S2K, matching
/// GnuPG's result in the common case of having just one SKESK.  Xor
/// is also nice because it is commutative, so the order of the SKESKs
/// doesn't matter.
///
/// Unsupported SKESK versions or S2K algorithms unsupported by the
/// caching id algorithm are ignored.  We cannot use them anyway.
///
/// Further, if no SKESKs are given, this function returns `None`.
pub fn cacheid_over_all(skesks: &[SKESK]) -> Option<String> {
    if skesks.is_empty() {
        return None;
    }

    let mut cacheid = [0; 8];

    for skesk in skesks {
        let s2k = match skesk {
            SKESK::V4(skesk) => skesk.s2k(),
            SKESK::V5(skesk) => skesk.s2k(),
            _ => continue,
        };

        #[allow(deprecated)]
        let salt = match s2k {
            S2K::Iterated { salt, .. } => &salt[..8],
            S2K::Salted { salt, .. } => &salt[..8],
            _ => continue,
        };

        cacheid.iter_mut().zip(salt.iter()).for_each(|(p, s)| *p ^= *s);
    }

    Some(format!("S{}", openpgp::fmt::hex::encode(&cacheid)))
}

/// Makes the agent forget a password.
pub async fn forget_passphrase<C, P>(agent: &mut ipc::gnupg::Agent,
                                     cache_id: C,
                                     mut pinentry_cb: P)
                                     -> Result<()>
where
    C: AsRef<str>,
    P: FnMut(Vec<u8>),
{
    agent.send(format!("CLEAR_PASSPHRASE {}", escape(cache_id.as_ref())))?;
    while let Some(response) = agent.next().await {
        match response? {
            Response::Ok { .. }
            | Response::Comment { .. }
            | Response::Status { .. } =>
                (), // Ignore.
            Response::Inquire { keyword, parameters } => {
                match keyword.as_str() {
                    "PINENTRY_LAUNCHED" => {
                        pinentry_cb(parameters.unwrap_or_default());
                    },
                    _ => (),
                }
                acknowledge_inquiry(agent).await?
            },
            Response::Error { ref message, .. } =>
                return operation_failed(agent, message).await,
            response =>
                return protocol_error(&response),
        }
    }
    Ok(())
}

/// Returns whether the agent has a secret key.
pub async fn has_key(agent: &mut Agent,
                     key: &Key<PublicParts, UnspecifiedRole>)
                     -> Result<bool>
{
    let grip = Keygrip::of(key.mpis())?;
    Ok(send_simple(agent, format!("HAVEKEY {}", grip)).await.is_ok())
}

/// Returns the (sub)keys of the given cert that have a secret in the
/// agent.
pub async fn has_keys(agent: &mut Agent,
                      cert: &Arc<LazyCert<'_>>)
                      -> Result<BTreeSet<Fingerprint>>
{
    let mut result = BTreeSet::default();

    for k in cert.keys() {
        if has_key(agent, &k).await.unwrap_or(false) {
            result.insert(k.fingerprint());
        }
    }

    Ok(result)
}

/// Imports a secret key into the agent.
pub async fn import(agent: &mut Agent,
                    policy: &dyn Policy,
                    cert: &Cert,
                    key: &Key<SecretParts, UnspecifiedRole>,
                    unattended: bool)
                    -> Result<bool>
{
    // The gpg-agent shipped with GnuPG 2.4.x calculates the checksum
    // over ECC artifacts differently.  Oddly, this seems to amount to
    // adding 8 to the checksum.  See GnuPG commit
    // 2b118516240b4bddd34c68c23a99bea56682a509.
    use sequoia_openpgp::types::PublicKeyAlgorithm::*;
    let mut r = import_int(agent, policy, cert, key, unattended, 0).await;
    if r.is_err() && (key.pk_algo() == ECDSA
                      || key.pk_algo() == EdDSA
                      || key.pk_algo() == ECDH)
    {
        r = import_int(agent, policy, cert, key, unattended, 8).await;
    }

    if let Err(e) = &r {
        // XXX: use warn()
        eprintln!("gpg: {}", e);
    }
    r
}

async fn import_int(agent: &mut Agent,
                    policy: &dyn Policy,
                    cert: &Cert,
                    key: &Key<SecretParts, UnspecifiedRole>,
                    unattended: bool,
                    csum_offset: u16)
                    -> Result<bool>
{
    use ipc::sexp::*;

    /// Makes a tuple cell, i.e. a *C*ons.
    fn c(name: &str, data: &[u8]) -> Sexp {
        Sexp::List(vec![Sexp::String(name.as_bytes().into()),
                        Sexp::String(data.into())])
    }

    /// Makes a tuple cell with a string value, i.e. a *S*tring cons.
    fn s(name: &str, data: impl ToString) -> Sexp {
        c(name, data.to_string().as_bytes())
    }

    fn add_signed_mpi(list: &mut Vec<Sexp>, v: &[u8]) {
        let mut v = v.to_vec();

        // If the high bit is set, we need to prepend a zero byte,
        // otherwise the agent will interpret the value as signed, and
        // thus negative.
        if v[0] & 0x80 > 0 {
            v.insert(0, 0);
        }

        add_raw(list, "_", &v);
    }

    fn add(list: &mut Vec<Sexp>, mpi: &mpi::MPI) {
        add_signed_mpi(list, mpi.value());
    }
    fn addp(list: &mut Vec<Sexp>, checksum: &mut u16, mpi: &mpi::ProtectedMPI) {
        add_signed_mpi(list, mpi.value());

        use openpgp::serialize::MarshalInto;
        *checksum = checksum.wrapping_add(
            mpi.to_vec().expect("infallible").iter()
                .fold(0u16, |acc, v| acc.wrapping_add(*v as u16)));
    }

    fn add_raw(list: &mut Vec<Sexp>, name: &str, data: &[u8]) {
        list.push(Sexp::String(name.into()));
        list.push(Sexp::String(data.into()));
    }

    use openpgp::crypto::mpi::{self, PublicKey};
    let mut skey = vec![Sexp::String("skey".into())];
    let curve = match key.mpis() {
        PublicKey::RSA { e, n, } => {
            add(&mut skey, n);
            add(&mut skey, e);
            None
        },
        PublicKey::DSA { p, q, g, y, } => {
            add(&mut skey, p);
            add(&mut skey, q);
            add(&mut skey, g);
            add(&mut skey, y);
            None
        },
        PublicKey::ElGamal { p, g, y, } => {
            add(&mut skey, p);
            add(&mut skey, g);
            add(&mut skey, y);
            None
        },
        PublicKey::EdDSA { curve, q, }
        | PublicKey::ECDSA { curve, q, }
        | PublicKey::ECDH { curve, q, .. } => {
            add(&mut skey, q);
            Some(curve.clone())
        },
        PublicKey::Unknown { mpis, rest, } => {
            for m in mpis.iter() {
                add(&mut skey, m);
            }
            add_raw(&mut skey, "_", rest);
            None
        },
        _ => return
            Err(openpgp::Error::UnsupportedPublicKeyAlgorithm(key.pk_algo())
                .into()),
    };

    // Now we append the secret bits.  We also compute a checksum over
    // the MPIs.
    let mut checksum = 0u16;
    let protection = match key.secret() {
        SecretKeyMaterial::Encrypted(e) => {
            let mut p =
                vec![Sexp::String("protection".into())];
            p.push(Sexp::String(match e.checksum() {
                Some(SecretKeyChecksum::SHA1) => "sha1",
                Some(SecretKeyChecksum::Sum16) => "sum",
                None => "none", // XXX: does that happen?
            }.into()));
            p.push(Sexp::String(babel::Fish(e.algo()).to_string().as_str().into()));

            let iv_len = e.algo().block_size().unwrap_or(0);
            let iv = e.ciphertext().map(|c| &c[..iv_len.min(c.len())])
                .unwrap_or(&[]);
            p.push(Sexp::String(iv.into()));

            #[allow(deprecated)]
            match e.s2k() {
                S2K::Iterated { hash, salt, hash_bytes, } => {
                    p.push(Sexp::String("3".into()));
                    p.push(Sexp::String(babel::Fish(*hash).to_string().as_str().into()));
                    p.push(Sexp::String(salt[..].into()));
                    p.push(Sexp::String(
                        crate::utils::s2k_encode_iteration_count(*hash_bytes)
                            .unwrap_or_default().to_string().as_str().into()));
                },
                S2K::Salted { hash, salt } => {
                    p.push(Sexp::String("1".into()));
                    p.push(Sexp::String(babel::Fish(*hash).to_string().as_str().into()));
                    p.push(Sexp::String(salt[..].into()));
                    p.push(Sexp::String("0".into()));
                },
                S2K::Simple { hash } => {
                    p.push(Sexp::String("0".into()));
                    p.push(Sexp::String(babel::Fish(*hash).to_string().as_str().into()));
                    p.push(Sexp::String([][..].into()));
                    p.push(Sexp::String("0".into()));
                },
                S2K::Private { .. } | S2K::Unknown { .. } | _ => {
                    return Err(anyhow::anyhow!("Unsupported protection mode"));
                },
            }

            if let Ok(c) = e.ciphertext() {
                skey.push(Sexp::String("e".into()));
                // We must omit the IV here.
                skey.push(Sexp::String(c[iv_len.min(c.len())..].into()));
            } else {
                return Err(anyhow::anyhow!("Failed to parse ciphertext"));
            }

            Sexp::List(p)
        },
        SecretKeyMaterial::Unencrypted(u) => {
            u.map(|s| match s {
                mpi::SecretKeyMaterial::RSA { d, p, q, u, } => {
                    addp(&mut skey, &mut checksum, d);
                    addp(&mut skey, &mut checksum, p);
                    addp(&mut skey, &mut checksum, q);
                    addp(&mut skey, &mut checksum, u);
                },
                mpi::SecretKeyMaterial::DSA { x, }
                | mpi::SecretKeyMaterial::ElGamal { x, } =>
                    addp(&mut skey, &mut checksum, x),
                mpi::SecretKeyMaterial::EdDSA { scalar, }
                | mpi::SecretKeyMaterial::ECDSA { scalar, }
                | mpi::SecretKeyMaterial::ECDH { scalar, } =>
                    addp(&mut skey, &mut checksum, scalar),
                mpi::SecretKeyMaterial::Unknown { mpis, rest, } => {
                    for m in mpis.iter() {
                        addp(&mut skey, &mut checksum, m);
                    }
                    add_raw(&mut skey, "_", rest);
                    checksum = checksum.wrapping_add(
                        rest.iter()
                            .fold(0u16, |acc, v| acc.wrapping_add(*v as u16)));
                },
                _ => (), // XXX This will fail anyway.
            });
            s("protection", "none")
        },
    };

    let mut transfer_key = vec![
        Sexp::String("openpgp-private-key".into()),
        s("version", key.version()),
        s("algo", babel::Fish(key.pk_algo())), // XXX does that map correctly?
    ];
    if let Some(curve) = curve {
        transfer_key.push(s("curve", curve.to_string()));
    }
    transfer_key.push(Sexp::List(skey));
    transfer_key.push(s("csum", checksum.wrapping_add(csum_offset)));
    transfer_key.push(protection);

    let transfer_key = Sexp::List(transfer_key);

    // Pad to a multiple of 64 bits so that we can AESWRAP it.
    let mut buf = Vec::new();
    transfer_key.serialize(&mut buf)?;
    while buf.len() % 8 > 0 {
        buf.push(0);
    }
    let padded_transfer_key = Protected::from(buf);

    send_simple(agent,
                format!("SETKEYDESC {}",
                        escape(make_import_prompt(policy, cert, key)))).await?;

    // Get the Key Encapsulation Key for transferring the key.
    let kek = send_simple(agent, "KEYWRAP_KEY --import").await?;

    // Now encrypt the key.
    let encrypted_transfer_key = openpgp::crypto::ecdh::aes_key_wrap(
        openpgp::types::SymmetricAlgorithm::AES128,
        &kek,
        &padded_transfer_key)?;
    assert_eq!(padded_transfer_key.len() + 8, encrypted_transfer_key.len());

    // Did we import it?
    let mut imported = false;

    // And send it!
    agent.send(format!("IMPORT_KEY --timestamp={}{}",
                       chrono::DateTime::<chrono::Utc>::from(key.creation_time())
                       .format("%Y%m%dT%H%M%S"),
                      if unattended { " --unattended" } else { "" },
    ))?;
    while let Some(response) = agent.next().await {
        match response? {
            Response::Ok { .. }
            | Response::Comment { .. }
            | Response::Status { .. } =>
                (), // Ignore.
            Response::Inquire { keyword, .. } => {
                match keyword.as_str() {
                    "KEYDATA" => {
                        agent.data(&encrypted_transfer_key)?;
                        // Dummy read to send data.
                        agent.next().await;

                        // Then, handle the inquiry.
                        while let Some(r) = agent.next().await {
                            match r? {
                                // May send CACHE_NONCE
                                Response::Status { .. } =>
                                    (), // Ignore.
                                Response::Ok { .. } => {
                                    imported = true;
                                    break;
                                },
                                // May send PINENTRY_LAUNCHED when
                                // importing locked keys.
                                Response::Inquire { .. } =>
                                    acknowledge_inquiry(agent).await?,
                                Response::Error { code, message } => {
                                    match code {
                                        0x4008023 => // File exists.
                                        // Ignore error, we don't set imported.
                                            (),
                                        _ => {
                                            return operation_failed(agent, &message).await;
                                        },
                                    }
                                    break;
                                },
                                response =>
                                    return protocol_error(&response),
                            }
                        }

                        // Sending the data acknowledges the inquiry.
                    },
                    _ => acknowledge_inquiry(agent).await?,
                }
            },
            Response::Error { ref message, .. } =>
                return operation_failed(agent, message).await,
            response =>
                return protocol_error(&response),
        }
    }

    Ok(imported)
}

fn make_import_prompt(policy: &dyn Policy, cert: &Cert,
                      key: &Key<SecretParts, UnspecifiedRole>)
                      -> String
{
    use openpgp::types::Timestamp;

    let primary_id = cert.keyid();
    let keyid = key.keyid();
    let uid = crate::utils::best_effort_primary_uid(policy, cert);

    match (primary_id == keyid, Some(uid)) {
        (true, Some(uid)) => format!(
            "Please enter the passphrase to \
             unlock the OpenPGP secret key:\n\
             {}\n\
             ID {:X}, created {}.",
            uid,
            keyid,
            Timestamp::try_from(key.creation_time())
                .expect("creation time is representable"),
        ),
        (false, Some(uid)) => format!(
            "Please enter the passphrase to \
             unlock the OpenPGP secret key:\n\
             {}\n\
             ID {:X}, created {} (main key ID {}).",
            uid,
            keyid,
            Timestamp::try_from(key.creation_time())
                .expect("creation time is representable"),
            primary_id,
        ),
        (true, None) => format!(
            "Please enter the passphrase to \
             unlock the OpenPGP secret key:\n\
             ID {:X}, created {}.",
            keyid,
            Timestamp::try_from(key.creation_time())
                .expect("creation time is representable"),
        ),
        (false, None) => format!(
            "Please enter the passphrase to \
             unlock the OpenPGP secret key:\n\
             ID {:X}, created {} (main key ID {}).",
            keyid,
            Timestamp::try_from(key.creation_time())
                .expect("creation time is representable"),
            primary_id,
        ),
    }
}
