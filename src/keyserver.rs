use std::{
    time::Duration,
};

use anyhow::Result;
use futures::{stream, StreamExt};
use rand::{thread_rng, seq::SliceRandom};
use tokio::sync::mpsc::{channel, Receiver};

use sequoia_openpgp::{
    self as openpgp,
    Cert,
    KeyHandle,
};
use crate::net; // XXX

use crate::{
    common::{
	Common,
	Query,
    },
};

/// How many concurrent requests to send out.
pub const CONCURRENT_REQUESTS: usize = 4;

/// How long to wait for the initial connection.
pub const CONNECT_TIMEOUT: Duration = Duration::new(15, 0);

/// How long to wait for each individual request.
pub const REQUEST_TIMEOUT: Duration = Duration::new(5, 0);

/// Dispatches the --receive-keys command.
pub fn cmd_receive_keys(config: &mut crate::Config, args: &[String])
			-> Result<()>
{
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(keyserver_import(config, args, false))
}

/// Dispatches the --refresh-keys command.
pub fn cmd_refresh_keys(config: &mut crate::Config, args: &[String])
			-> Result<()>
{
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(keyserver_import(config, args, true))
}

/// Dispatches the --receive-keys and --refresh-keys commands.
async fn keyserver_import(config: &mut crate::Config, args: &[String],
			  refresh_keys: bool)
			  -> Result<()>
{
    let mut handles: Vec<KeyHandle> = if args.is_empty() && refresh_keys {
	config.keydb().iter().map(|c| c.fingerprint().into()).collect()
    } else {
	args.iter()
	    .filter_map(|a| match Query::from(a.as_str()) {
		Query::Key(h) | Query::ExactKey(h) => Some(h),
		_ => {
		    config.error(format_args!(
			"{:?} not a key ID: skipping", a));
		    None
		},
	    })
	    .collect()
    };

    handles.shuffle(&mut thread_rng());

    // We start crawling the keyserver for certs, and send them to a
    // concurrent mutator that inserts the certs into the store.
    let (sender, receiver) = channel(CONCURRENT_REQUESTS);

    // Make a send capability for every key handle to crawl for.
    let handles =
	handles.into_iter().map(|h| (sender.clone(), h))
	.collect::<Vec<_>>();
    // Now, it is really important that we drop our sender, otherwise
    // the importer below will never finish.
    drop(sender);

    let servers =
	config.keyserver.iter().map(|k| {
	    let c = config.make_http_client()
                .for_url(k.url())?
                .build()?;

	    net::KeyServer::with_client(k.url(), c)
	})
	.collect::<Result<Vec<_>>>()?;

    let crawler = stream::iter(handles)
        .map(|(sender, handle)| {
            let servers = &servers;
            async move {
		let (ocert, errs) = stream::iter(servers)
		    .map(|server| server.get(handle.clone()))
		    .buffer_unordered(servers.len())
		    .fold((None::<Cert>, vec![]),
			  |(ocert, mut errs), rcert| async { match rcert {
			      Ok(c) => match ocert {
				  Some(b) => (b.merge_public(c).ok(), errs),
				  None => (Some(c), errs),
			      },
			      Err(e) => {
				  errs.push(e);
				  (ocert, errs)
			      }
			  }})
		    .await;

		if let Some(cert) = ocert {
		    if let Err(e) = sender.send(Ok(cert)).await {
			eprintln!("gpg: {}", e); // Should not happen.
		    }
		}
		for e in errs {
		    if let Err(e) = sender.send(Err(e)).await {
			eprintln!("gpg: {}", e); // Should not happen.
		    }
		}
            }
        })
	.buffer_unordered(CONCURRENT_REQUESTS)
	.for_each(|_| async { () });

    // Finally, start the importer.
    let importer = importer(config, receiver);

    // Drive futures, handle errors.
    let (_crawler, importer) = tokio::join!(crawler, importer);
    importer?;

    Ok(())
}

async fn importer(config: &mut crate::Config,
		  mut rx: Receiver<Result<Cert>>)
		  -> Result<()> {
    // We collect stats for the final IMPORT_RES status line.
    let mut s = crate::status::ImportResult::default();

    while let Some(rcert) = rx.recv().await {
	use crate::import;

	match rcert {
            Ok(c) => {
		let c = c.strip_secret_key_material();
		import::do_import_cert(config, &mut s, c).await?;
	    },
            Err(e) =>
		import::do_import_failed(config, &mut s, e, vec![]).await?,
	}
    }

    s.print_results(config)?;
    Ok(())
}

#[derive(Default, Clone)]
pub struct HttpClientBuilder {
    connect_timeout: Duration,
    request_timeout: Duration,
    user_agent: String,
    use_tor: bool,
}

impl HttpClientBuilder {
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = d;
        self
    }

    pub fn request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }

    pub fn use_tor(mut self, v: bool) -> Self {
        self.use_tor = v;
        if v {
            // Cut Tor some slack.
            self.connect_timeout *= 2; // XXX: Essentially random.
            self.request_timeout *= 3; // XXX: Essentially random.
        }
        self
    }

    /// Specializes the client for the given URL.
    ///
    /// If the domain is an onion-address, we switch on tor mode.
    pub fn for_url<U: AsRef<str>>(mut self, u: U) -> Result<Self> {
        let uri = reqwest::Url::parse(u.as_ref())?;
	if uri.domain().map(|d| d.ends_with(".onion")).unwrap_or(false) {
            self = self.use_tor(true);
        }
        Ok(self)
    }

    pub fn build(&self) -> Result<reqwest::Client> {
        let mut c = reqwest::Client::builder()
	    .user_agent(self.user_agent.clone())
	    .connect_timeout(self.connect_timeout)
	    .timeout(self.request_timeout);

        if self.use_tor {
            // Select a fresh circuit by providing a random
            // username/password combination.
            let mut nonce = [0; 4];
            openpgp::crypto::random(&mut nonce[..]);

            // Just randomize the password.
            let nonce = openpgp::fmt::hex::encode(&nonce);
            let url =
                format!("socks5h://anonymous:{}@127.0.0.1:9050", nonce);

            // Use it for all requests, regardless of protocol.
	    c = c.proxy(reqwest::Proxy::all(url)?);
	}

        Ok(c.build()?)
    }
}
