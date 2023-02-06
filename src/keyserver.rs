use std::{
    time::Duration,
};

use anyhow::Result;
use futures::{stream, StreamExt};
use rand::{thread_rng, seq::SliceRandom};
use tokio::sync::mpsc::{channel, Receiver};

use sequoia_openpgp::{
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
const CONCURRENT_REQUESTS: usize = 4;

/// How long to wait for the initial connection.
const CONNECT_TIMEOUT: Duration = Duration::new(15, 0);

/// How long to wait for each individual request.
const REQUEST_TIMEOUT: Duration = Duration::new(5, 0);

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
	    let c = reqwest::Client::builder()
		.user_agent(concat!(
		    "gpg-sq/",
		    env!("CARGO_PKG_VERSION"),
		))
		.connect_timeout(CONNECT_TIMEOUT)
		.timeout(REQUEST_TIMEOUT)
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
