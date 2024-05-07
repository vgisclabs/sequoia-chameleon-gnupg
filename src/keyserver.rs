use std::{
    collections::btree_map::{BTreeMap, Entry},
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
use sequoia_net as net;

use sequoia_cert_store as cert_store;
use cert_store::Store;

use crate::{
    argparse,
    argparse::options::Opt,
    common::{
	Common,
	Query,
    },
};

trace_module!(TRACE);

/// How many concurrent requests to send out.
pub const CONCURRENT_REQUESTS: usize = 4;

/// How long to wait for the initial connection.
pub const CONNECT_TIMEOUT: Duration = Duration::new(15, 0);

/// How long to wait for each individual request.
pub const REQUEST_TIMEOUT: Duration = Duration::new(5, 0);

/// Controls keyserver operations.
pub struct KeyserverOptions {
    /// XXX.
    pub max_cert_size: Option<usize>,

    /// Override proxy options set for dirmngr.
    pub http_proxy: Option<String>,

    /// Override timeout options set for dirmngr.
    pub timeout: bool,

    /// Automatically retrieve keys when verifying signatures.
    pub auto_key_retrieve: bool,

    /// Honor the preferred keyserver URL set on the key.
    pub honor_preferred_keyserver: bool,

    /// Honor the PKA record set on a key when retrieving keys.
    pub honor_pka_record: bool,

    pub import: crate::import::ImportOptions,
    pub export: crate::export::ExportOptions,
}

impl Default for KeyserverOptions {
    fn default() -> Self {
        let mut import = crate::import::ImportOptions::default();
        import.self_sigs_only = true;
        import.clean = true;
        Self {
            max_cert_size: None,
            http_proxy: None,
            timeout: false,
            auto_key_retrieve: false,
            honor_preferred_keyserver: false,
            honor_pka_record: false,
            import,
            export: Default::default(),
        }
    }
}

impl KeyserverOptions {
    const OPTS: [Opt<KeyserverOptions>; 8] = [
        opt_todo! {
            "max-cert-size",
            |o, s, v| Ok({ o.max_cert_size = Some(v.parse()?); }),
            "",
        },

        opt_todo! {
            "http-proxy",
            |o, s, v| Ok({ o.http_proxy = Some(v.to_string()); }),
            "override proxy options set for dirmngr",
        },

        opt_todo! {
            "timeout",
            |o, s, _| Ok({ o.timeout = s; }),
            "override timeout options set for dirmngr",
        },

        opt_todo! {
            "auto-key-retrieve",
            |o, s, _| Ok({ o.auto_key_retrieve = s; }),
            "automatically retrieve keys when verifying signatures",
        },

        opt_todo! {
            "honor-keyserver-url",
            |o, s, _| Ok({ o.honor_preferred_keyserver = s; }),
            "honor the preferred keyserver URL set on the key",
        },

        opt_todo! {
            "honor-pka-record",
            |o, s, _| Ok({ o.honor_pka_record = s; }),
            "honor the PKA record set on a key when retrieving keys",
        },

        // These two are NOPs in GnuPG for documentation purposes.
        opt_todo! {
            "include-revoked",
            |_, _, _| Ok(()),
            "include revoked keys in search results",
        },
        opt_todo! {
            "include-subkeys",
            |_, _, _| Ok(()),
            "include subkeys when searching by key ID",
        },
    ];

    /// Prints the list of keyserver options if requested.
    ///
    /// If `s == "help"`, prints all supported options and returns
    /// `true`.  The caller should then exit the process gracefully.
    pub fn maybe_print_help(s: &str) -> Result<bool> {
        argparse::options::maybe_print_help(&Self::OPTS, s)
    }

    /// Parses the keyserver options.
    ///
    /// All import options and all export options are valid keyserver
    /// options too.
    pub fn parse(&mut self, s: &str) -> Result<()> {
        if let Ok(()) = argparse::options::parse(&Self::OPTS, s, self) {
            return Ok(());
        }

        if let Ok(()) = self.import.parse(s) {
            return Ok(());
        }

        if let Ok(()) = self.export.parse(s) {
            return Ok(());
        }

        // XXX: Warn about obsolete option.
        Ok(())
    }
}

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
async fn keyserver_import(config: &mut crate::Config<'_>, args: &[String],
			  refresh_keys: bool)
			  -> Result<()>
{
    tracer!(TRACE, "keyserver::keyserver_import");

    let mut handles: Vec<KeyHandle> = if args.is_empty() && refresh_keys {
	config.keydb().fingerprints().map(Into::into).collect()
    } else {
	args.iter()
	    .filter_map(|a| match a.parse() {
		Ok(Query::Key(h)) | Ok(Query::ExactKey(h)) => Some(h),
		Ok(_) => {
		    config.error(format_args!(
			"{:?} not a key ID: skipping", a));
		    None
		},
                Err(e) => {
		    config.error(format_args!(
			"{:?} not a key ID, skipping: {}", a, e));
		    None
		}
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
            t!("Using server {}", k.url());

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
		let (certs, errs) = stream::iter(servers)
		    .map(|server| async {
                        let response = server.get(handle.clone()).await;
                        (server.url().clone(), response)
                    })
		    .buffer_unordered(servers.len())
		    .fold((BTreeMap::new(), vec![]),
			  |(mut certs, mut errs), (url, rrcerts)| {
                              async move { match rrcerts {
			          Ok(rcerts) => {
                                      t!("{}: found", url);
                                      for c in rcerts {
                                          match c {
                                              Ok(c) => {
                                                  let fp = c.fingerprint();
                                                  match certs.entry(fp) {
                                                      Entry::Vacant(e) => {
                                                          e.insert(c);
                                                      },
                                                      Entry::Occupied(mut e) => {
                                                          let old = e.get().clone();
                                                          if let Ok(m) = old.merge_public(c) {
                                                              e.insert(m);
                                                          }
                                                      },
                                                  }
                                              },
                                              Err(e) => {
                                                  t!("{}: {}", url, e);
				                  errs.push(e);
                                              },
                                          }
                                      }
                                      (certs, errs)
			          },
			          Err(e) => {
                                      t!("{}: {}", url, e);
				      errs.push(e);
                                      (certs, errs)
			          }
                              }}
			  })
		    .await;

		for cert in certs.into_values() {
		    if let Err(e) = sender.send(Ok(cert)).await {
			safe_eprintln!("gpg: {}", e); // Should not happen.
		    }
		}
		for e in errs {
		    if let Err(e) = sender.send(Err(e)).await {
			safe_eprintln!("gpg: {}", e); // Should not happen.
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

async fn importer(config: &mut crate::Config<'_>,
		  mut rx: Receiver<Result<Cert>>)
		  -> Result<()> {
    // We collect stats for the final IMPORT_RES status line.
    let mut s = crate::status::ImportResult::default();

    while let Some(rcert) = rx.recv().await {
	use crate::import;

	match rcert {
            Ok(c) => {
		let c = c.strip_secret_key_material();
		import::do_import_cert(config, &mut s, c, false).await?;
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
