//! This is a re-imagination of the sequoia-net crate.
//!
//! We will move this into sequoia-net at some point.  Do not
//! contribute to this module unless you are fine with that.

use std::io::Cursor;

use reqwest::{
    StatusCode,
    Url,
};

use sequoia_openpgp::{
    armor,
    Cert,
    KeyHandle,
    parse::Parse,
};

/// For accessing keyservers using HKP.
pub struct KeyServer {
    client: reqwest::Client,
    uri: Url,
}

impl Default for KeyServer {
    fn default() -> Self {
	Self::new("hkps://keys.openpgp.org/").unwrap()
    }
}

impl KeyServer {
    /// Returns a handle for the given URI.
    pub fn new(uri: &str) -> Result<Self> {
	Self::with_client(uri, reqwest::Client::new())
    }

    /// Returns a handle for the given URI with a custom `Client`.
    pub fn with_client(uri: &str, client: reqwest::Client) -> Result<Self> {
        let uri = reqwest::Url::parse(uri)?;

        let s = uri.scheme();
        match s {
            "hkp" => (),
            "hkps" => (),
            _ => return Err(Error::MalformedUri.into())
        };
        let uri =
            format!("{}://{}:{}",
                    match s {"hkp" => "http", "hkps" => "https",
                             _ => unreachable!()},
                    uri.host().ok_or(Error::MalformedUri)?,
                    match s {
                        "hkp" => uri.port().or(Some(11371)),
                        "hkps" => uri.port().or(Some(443)),
                        _ => unreachable!(),
                    }.unwrap()).parse()?;

        Ok(KeyServer{client, uri})
    }

    /// Retrieves the certificate with the given handle.
    pub async fn get<H: Into<KeyHandle>>(&self, handle: H)
                                         -> Result<Cert>
    {
        let handle = handle.into();
        let uri = self.uri.join(
            &format!("pks/lookup?op=get&options=mr&search=0x{:X}", handle))?;

        let res = self.client.get(uri).send().await?;
        match res.status() {
            StatusCode::OK => {
                let body = res.bytes().await?;
                let r = armor::Reader::from_reader(
                    Cursor::new(body),
                    armor::ReaderMode::Tolerant(Some(armor::Kind::PublicKey)),
                );
                let cert = Cert::from_reader(r)?;
                // XXX: This test is dodgy.  Passing it doesn't really
                // mean anything.  A malicious keyserver can attach
                // the key with the queried keyid to any certificate
                // they control.  Querying for signing-capable sukeys
                // are safe because they require a primary key binding
                // signature which the server cannot produce.
                // However, if the public key algorithm is also
                // capable of encryption (I'm looking at you, RSA),
                // then the server can simply turn it into an
                // encryption subkey.
                //
                // Returned certificates must be mistrusted, and be
                // carefully interpreted under a policy and trust
                // model.  This test doesn't provide any real
                // protection, and maybe it is better to remove it.
                // That would also help with returning multiple certs,
                // see above.
                if cert.keys().any(|ka| ka.key_handle().aliases(&handle)) {
                    Ok(cert)
                } else {
                    Err(Error::MismatchedKeyHandle(handle, cert).into())
                }
            }
            StatusCode::NOT_FOUND => Err(Error::NotFound.into()),
            e @ _ => Err(Error::HttpsStatusCode(e).into()),
        }
    }
}

/// Results for sequoia-net.
pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

#[derive(thiserror::Error, Debug)]
/// Errors returned from the network routines.
pub enum Error {
    /// A requested key was not found.
    #[error("Key not found")]
    NotFound,
    /// A given keyserver URI was malformed.
    #[error("Malformed URI; expected hkp: or hkps:")]
    MalformedUri,
    /// Mismatched key handle
    #[error("Mismatched key handle, expected {0}")]
    MismatchedKeyHandle(KeyHandle, Cert),
    #[error("HTTPS Status Code: {0}")]
    HttpsStatusCode(StatusCode),
}
