use std::convert::TryFrom;

use anyhow::Result;

use sequoia_openpgp as openpgp;
use sequoia_ipc as ipc;
use openpgp::{
    Cert,
    crypto::{
        Password,
        mem::Protected,
    },
    packet::{
        Key,
        key::{
            PublicParts,
            SecretParts,
            UnspecifiedRole,
            SecretKeyMaterial,
        },
    },
    policy::Policy,
};
use ipc::{
    Keygrip,
    gnupg::Agent,
    assuan::{Response, escape},
};
use futures::stream::StreamExt;

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

/// Returns a convenient Err value for use in the state machines
/// below.
async fn operation_failed<T>(agent: &mut Agent, message: &Option<String>)
                       -> Result<T>
{
    if let Some(response) = agent.next().await {
        Err(ipc::gnupg::Error::ProtocolError(
            format!("Got unexpected response {:?}", response))
            .into())
    } else {
        Err(ipc::gnupg::Error::OperationFailed(
            message.as_ref().map(|e| e.to_string())
                .unwrap_or_else(|| "Unknown reason".into()))
            .into())
    }
}

/// Returns a convenient Err value for use in the state machines
/// below.
fn protocol_error<T>(response: &Response) -> Result<T> {
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

    Ok(data.into())
}

/// Makes the agent ask for a password.
pub async fn get_passphrase<C, CS, ES, P>(agent: &mut ipc::gnupg::Agent,
                                          cache_id: C,
                                          err_msg: Option<ES>,
                                          prompt: Option<String>,
                                          desc_msg: Option<String>,
                                          newsymkey: bool,
                                          repeat: usize,
                                          check: bool,
                                          mut pinentry_cb: P)
                                          -> Result<Password>
where
    C: Into<Option<CS>>,
    CS: AsRef<str>,
    ES: AsRef<str>,
    P: FnMut(&mut Agent, Response) -> Option<Protected>,
{
    agent.send(format!(
        "GET_PASSPHRASE --data --repeat={}{}{} -- {} {} {} {}",
        repeat,
        if (repeat > 0 && check) || newsymkey { " --check" } else { "" },
        if newsymkey { " --newsymkey" } else { "" },
        cache_id.into().as_ref().map(escape).unwrap_or_else(|| "X".into()),
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

/// Imports a secret key into the agent.
pub async fn has_key(agent: &mut Agent,
                     key: &Key<PublicParts, UnspecifiedRole>)
                     -> Result<bool>
{
    let grip = Keygrip::of(key.mpis())?;
    Ok(send_simple(agent, format!("HAS_KEY {}", grip)).await.is_ok())
}

/// Imports a secret key into the agent.
pub async fn import(agent: &mut Agent,
                    policy: &dyn Policy,
                    cert: &Cert,
                    key: &Key<SecretParts, UnspecifiedRole>)
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
        SecretKeyMaterial::Encrypted(_e) => {
            unimplemented!()
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
        s("algo", key.pk_algo()), // XXX does that map correctly?
    ];
    if let Some(curve) = curve {
        transfer_key.push(s("curve", curve.to_string()));
    }
    transfer_key.push(Sexp::List(skey));
    transfer_key.push(s("csum", checksum));
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
    agent.send(format!("IMPORT_KEY --timestamp={}",
                       chrono::DateTime::<chrono::Utc>::from(key.creation_time())
                       .format("%Y%m%dT%H%M%S")))?;
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
                                Response::Ok { .. } => {
                                    imported = true;
                                    break;
                                },
                                Response::Error { code, message } => {
                                    match code {
                                        0x4008023 => // File exists.
                                        // Ignore error, we don't set imported.
                                            (),
                                        _ => {
                                            if let Some(m) = message.as_ref() {
                                                // XXX: use warn()
                                                eprintln!("gpg: {}", m);
                                            }
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
