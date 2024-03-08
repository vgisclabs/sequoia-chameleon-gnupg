use std::{
    collections::BTreeMap,
    io::{self, Write},
    sync::Arc,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::amalgamation::{ValidateAmalgamation, ValidAmalgamation},
    packet::{UserID, signature::subpacket::SubpacketTag},
    types::*,
};
use sequoia_ipc as ipc;
use ipc::Keygrip;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::Store;
use cert_store::store::StoreError;

use crate::{
    argparse,
    argparse::options::Opt,
    common::{Common, Query},
    compliance::KeyCompliance,
    colons::*,
    trust::{*, cert::*},
    utils::best_effort_primary_uid,
};

/// Controls key list operations.
pub struct ListOptions {
    /// Display photo IDs during key listings.
    pub photos: bool,

    /// Show key usage information during key listings.
    pub key_usage: bool,

    /// Show policy URLs during signature listings.
    pub policy_urls: bool,

    /// Show IETF standard notations during signature listings.
    pub ietf_notations: bool,

    /// Show user standard notations during signature listings.
    pub user_notations: bool,

    /// Show preferred keyserver URLs during signature listings.
    pub preferred_keyserver: bool,

    /// Show user ID validity during key listings.
    pub uid_validity: bool,

    /// Show revoked and expired user IDs in key listings.
    pub unusable_uids: bool,

    /// Show revoked and expired subkeys in key listings.
    pub unusable_subkeys: bool,

    /// Show the keyring name in key listings.
    pub keyring_name: bool,

    /// Show expiration dates during signature listings.
    pub signature_expiration: bool,

    /// XXX
    pub signature_subpackets: bool,

    /// XXX.
    pub only_fpr_mbox: bool,

    /// Show third-party certifications (without verifying them).
    pub list_sigs: bool,

    /// Fast-list mode, disables third-party cert lookups while listing.
    pub fast_list: bool,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            photos: false,
            key_usage: true,
            policy_urls: false,
            ietf_notations: false,
            user_notations: false,
            preferred_keyserver: false,
            uid_validity: true,
            unusable_uids: false,
            unusable_subkeys: false,
            keyring_name: false,
            signature_expiration: false,
            signature_subpackets: false,
            only_fpr_mbox: false,
            list_sigs: false,
            fast_list: false,
        }
    }
}

impl ListOptions {
    const OPTS: [Opt<ListOptions>; 15] = [
        opt_todo! {
            "show-photos",
            |o, s, _| Ok({ o.photos = s; }),
            "display photo IDs during key listings",
        },

        opt_todo! {
            "show-usage",
            |o, s, _| Ok({ o.key_usage = s; }),
            "show key usage information during key listings",
        },

        opt_todo! {
            "show-policy-urls",
            |o, s, _| Ok({ o.policy_urls = s; }),
            "show policy URLs during signature listings",
        },

        opt_todo! {
            "show-notations",
            |o, s, _| Ok({ o.ietf_notations = s; o.user_notations = s; }),
            "show all notations during signature listings",
        },

        opt_todo! {
            "show-std-notations",
            |o, s, _| Ok({ o.ietf_notations = s; }),
            "show IETF standard notations during signature listings",
        },

        opt_todo! {
            "show-standard-notations",
            |o, s, _| Ok({ o.ietf_notations = s; }),
            "",
        },

        opt_todo! {
            "show-user-notations",
            |o, s, _| Ok({ o.user_notations = s; }),
            "show user-supplied notations during signature listings",
        },

        opt_todo! {
            "show-keyserver-urls",
            |o, s, _| Ok({ o.preferred_keyserver = s; }),
            "show preferred keyserver URLs during signature listings",
        },

        opt! {
            "show-uid-validity",
            |o, s, _| Ok({ o.uid_validity = s; }),
            "show user ID validity during key listings",
        },

        opt! {
            "show-unusable-uids",
            |o, s, _| Ok({ o.unusable_uids = s; }),
            "show revoked and expired user IDs in key listings",
        },

        opt_todo! {
            "show-unusable-subkeys",
            |o, s, _| Ok({ o.unusable_subkeys = s; }),
            "show revoked and expired subkeys in key listings",
        },

        opt_todo! {
            "show-keyring",
            |o, s, _| Ok({ o.keyring_name = s; }),
            "show the keyring name in key listings",
        },

        opt_todo! {
            "show-sig-expire",
            |o, s, _| Ok({ o.signature_expiration = s; }),
            "show expiration dates during signature listings",
        },

        opt_todo! {
            "show-sig-subpackets",
            // XXX: this takes an argument that has to be parsed.
            |o, s, _| Ok({ o.signature_subpackets = s; }),
            "",
        },

        opt_todo! {
            "show-only-fpr-mbox",
            |o, s, _| Ok({ o.only_fpr_mbox = s; }),
            "",
        },
    ];

    /// Prints the list of key list options if requested.
    ///
    /// If `s == "help"`, prints all supported options and returns
    /// `true`.  The caller should then exit the process gracefully.
    pub fn maybe_print_help(s: &str) -> Result<bool> {
        argparse::options::maybe_print_help(&Self::OPTS, s)
    }

    /// Parses the key list options.
    pub fn parse(&mut self, s: &str) -> Result<()> {
        argparse::options::parse(&Self::OPTS, s, self)
    }
}

/// Dispatches the --list-keys command (and similar ones).
pub fn cmd_list_keys(config: &crate::Config, args: &[String], list_secret: bool)
                     -> Result<()>
{
    let mut sink = io::stdout(); // XXX

    // First, emit a header on --list-keys --with-colons.
    if config.with_colons && ! list_secret {
        let v = config.trustdb.version(config);
        Record::TrustDBInformation {
            old: false,
            changed_model: false,
            model: v.model,
            creation_time: v.creation_time,
            expiration_time: v.expiration_time,
            marginals_needed: v.marginals_needed,
            completes_needed: v.completes_needed,
            max_cert_depth: v.max_cert_depth,
        }.emit(config, &mut sink)?;
    }

    let certs: Box<dyn Iterator<Item = Arc<LazyCert>>> = if args.is_empty() {
        // We filter out the trust root.  Not only does including it
        // mess up the tests, it is also likely surprising and
        // confusing for users.
        let trust_root_fp =
            if let Ok(overlay) = config.keydb().get_certd_overlay()
        {
            if let Ok(trust_root) = overlay.trust_root() {
                // As prior versions of the Chameleon generated a
                // trust root but didn't insert it into the certd, do
                // it now.  We have already loaded and parsed the
                // trust root, and listing all certs is an expensive
                // operation, so we don't mind the overhead here.
                if let Some(certd) =
                    overlay.cert_store.certd().map(|c| c.certd())
                {
                    use openpgp::{
                        Cert,
                        parse::Parse,
                        serialize::SerializeInto,
                    };
                    use sequoia_cert_store::store::openpgp_cert_d::MergeResult;
                    if certd.get(&trust_root.fingerprint().to_string())?
                        .is_none()
                    {
                        certd.insert(
                            &trust_root.fingerprint().to_string(),
                            trust_root.to_cert()?, false,
                            |new, old| {
                                let d = if let Some(old) = old
                                    .and_then(|b| Cert::from_bytes(b).ok())
                                {
                                    old.merge_public(new.clone())?.to_vec()?
                                } else {
                                    new.to_vec()?
                                };
                                Ok(MergeResult::Data(d))
                            })?;
                    }
                }

                Some(trust_root.fingerprint())
            } else {
                None // No trust root.
            }
        } else {
            None // No overlay, no trust root.
        };

        Box::new(
            config.keydb().certs()
                .filter(move |c| trust_root_fp.as_ref()
                        .map(|fp| &c.fingerprint() != fp)
                        .unwrap_or(true)))
    } else {
        let mut certs = BTreeMap::new();
        for query in args.iter().map(|a| Query::from(&a[..])) {
            let r = match query {
                Query::Key(h) | Query::ExactKey(h) =>
                    config.keydb().lookup_by_cert_or_subkey(&h),
                Query::Email(e) =>
                    config.keydb().lookup_by_email(&e),
                Query::UserIDFragment(f) =>
                    config.keydb().grep_userid(&f),
            };

            let r = match r {
                Ok(certs) => certs,
                Err(err) => {
                    match err.downcast_ref::<StoreError>() {
                        Some(&StoreError::NotFound(_)) => vec![],
                        Some(&StoreError::NoMatches(_)) => vec![],
                        _ => return Err(err),
                    }
                }
            };
            r.into_iter().for_each(|c| {
                certs.insert(c.fingerprint(), c);
            });
        }

        if certs.is_empty() {
            return Err(anyhow::anyhow!(
                "error reading key: No public key"));
        }

        Box::new(certs.into_values())
    };

    list_keys(config, certs, list_secret,
              args.is_empty(), // Are we listing all certs?
              sink)
}

pub fn list_keys<'a, 'store: 'a, S>(config: &'a crate::Config<'store>,
                                    certs: impl Iterator<Item = Arc<LazyCert<'store>>>,
                                    list_secret: bool,
                                    list_all: bool,
                                    sink: S)
    -> Result<()>
where
    S: Write,
{
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_list_keys(config, certs,
                                list_secret, list_secret,
                                config.list_options.uid_validity,
                                list_all,
                                sink))
}

pub async fn async_list_keys<'a, 'store: 'a, S>(
    config: &'a crate::Config<'store>,
    certs: impl Iterator<Item = Arc<LazyCert<'store>>>,
    list_secret: bool,
    // Tunes behavior for gpg --list-secret-keys.
    list_secret_keys_mode: bool,
    list_uid_validity: bool,
    list_all: bool,
    mut sink: S)
    -> Result<()>
where
    S: Write,
{
    let vtm = config.trust_model_impl.with_policy(config, Some(config.now()))?;
    let p = vtm.policy();

    let mut agent =
        if list_secret || (config.with_secret && config.with_colons) {
            config.connect_agent().await.ok()
        } else {
            None
        };

    // We emit the location header for humans only if we actually list
    // at least one key.
    let mut emitted_header = false;

    for cert in certs {
        let mut has_secret = if let Some(a) = agent.as_mut() {
            crate::gpg_agent::has_keys(a, &cert).await?
        } else {
            Default::default()
        };

        // When we are importing secret keys, we may have the secret
        // while the agent does not yet have it.  Nevertheless, we
        // want to list the secrets.
        for skb in cert.to_cert()?.keys().secret() {
            has_secret.insert(skb.fingerprint());
        }

        if list_secret_keys_mode && has_secret.is_empty() {
            // No secret (sub)key, don't list this key in --list-secret-keys.
            continue;
        }

        let cert = if let Ok(cert) = cert.to_cert() {
            cert
        } else {
            continue;
        };

        // For humans, we print the location of the store if the user
        // requested all keys (i.e. no pattern was given) and we list
        // at least one key.
        if list_all && ! emitted_header && ! config.with_colons {
            emitted_header = true;

            let path =
                config.keydb().get_certd_overlay()?.path().display().to_string();
            writeln!(&mut sink, "{}", path)?;
            sink.write_all(crate::utils::undeline_for(&path))?;
            writeln!(&mut sink)?;
        }

        let acert = AuthenticatedCert::new(vtm.as_ref(), &cert)?;
        let vcert = cert.with_policy(p, config.now()).ok();
        let cert_fp = cert.fingerprint();
        let cert_kh = cert.key_handle();
        let have_secret = has_secret.contains(&cert_fp);
        let ownertrust = config.trustdb.get_ownertrust(&cert_fp)
            .unwrap_or_else(|| OwnerTrustLevel::Undefined.into());
        let best_effort_primary_userid: UserID =
            best_effort_primary_uid(config.policy(), &cert).into();

        Record::Key {
            key: cert.primary_key().key(),
            have_secret: have_secret && list_secret,
            validity: acert.cert_validity(),
            expiration_date:  vcert.as_ref()
                .and_then(|v| v.keys().next().expect("primary key")
                          .key_expiration_time()),
            revocation_date: vcert.as_ref()
                .and_then(|v| if let RevocationStatus::Revoked(sigs)
                          = v.primary_key().revocation_status()
                          {
                              sigs[0].signature_creation_time()
                          } else {
                              None
                          }),
            ownertrust,
            primary_key_flags: vcert.as_ref()
                .and_then(|v| v.keys().next().expect("primary key").key_flags())
                .unwrap_or_else(|| KeyFlags::empty()),
            sum_key_flags: {
                let mut kf = KeyFlags::empty();
                if acert.cert_validity().expired {
                    // Expired certs don't list their subkeys' flags.
                } else if acert.cert_validity().revoked {
                    // Revoked certs don't list their subkeys' flags.
                } else if let Some(vcert) = vcert.as_ref() {
                    if vcert.keys().alive().for_signing().next().is_some() {
                        kf = kf.set_signing();
                    }
                    if vcert.keys().alive().for_certification().next().is_some() {
                        kf = kf.set_certification();
                    }
                    if vcert.keys().alive().for_authentication().next().is_some() {
                        kf = kf.set_authentication();
                    }
                    if vcert.keys().alive().for_transport_encryption().next().is_some() {
                        kf = kf.set_transport_encryption();
                    }
                    if vcert.keys().alive().for_storage_encryption().next().is_some() {
                        kf = kf.set_storage_encryption();
                    }
                }
                kf
            },
            token_sn: have_secret.then(|| TokenSN::SecretAvaliable),
            compliance: cert.primary_key().compliance(config),
        }.emit(config, &mut sink)?;

        for r in cert.revocation_keys(config.policy()) {
            let (algo, fp) = r.revoker();
            Record::RevocationKey {
                pk_algo: algo,
                revoker: fp.clone(),
                class: r.class(),
                sensitive: r.sensitive(),
            }.emit(config, &mut sink)?;
        }

        Record::Fingerprint(cert_fp)
            .emit(config, &mut sink)?;
        if config.with_keygrip
            || (config.with_colons && (list_secret_keys_mode || have_secret))
        {
            if let Ok(grip) = Keygrip::of(cert.primary_key().mpis()) {
                Record::Keygrip(grip).emit(config, &mut sink)?;
            }
        }

        if config.list_options.list_sigs {
            for s in cert.primary_key().signatures() {
                let is_self_sig =
                    s.get_issuers().iter().any(|i| i.aliases(&cert_kh));

                let (issuer_uid, validity) =
                    if config.list_options.fast_list {
                        (Some("".into()), None)
                    } else if is_self_sig {
                        (Some(best_effort_primary_userid.clone()), None)
                    } else {
                        if let Some(signer) =
                            s.get_issuers().into_iter().find_map(
                                |k| config.keydb().lookup_by_cert_or_subkey(&k).ok())
                            .and_then(|certs| certs.into_iter().next())
                            .and_then(|cert| cert.to_cert().ok().cloned())
                        {
                            (Some(best_effort_primary_uid(config.policy(), &signer).into()),
                             None)
                        } else {
                            (None, Some(SignatureValidity::MissingKey))
                        }
                    };

                Record::Signature {
                    issuer: s.issuers().cloned().next().or_else(
                        || s.issuer_fingerprints().cloned().next().map(Into::into)),
                    issuer_fp: s.issuer_fingerprints().cloned().next(),
                    issuer_uid,
                    validity,
                    pk_algo: s.pk_algo(),
                    hash_algo: s.hash_algo(),
                    creation_time: s.signature_creation_time()
                        .expect("valid signatures have a creation time"),
                    typ: s.typ(),
                    exportable: s.exportable().is_ok(),
                    trust: s.trust_signature(),
                    has_notations: s.subpackets(SubpacketTag::NotationData)
                        .next().is_some(),
                }.emit(config, &mut sink)?;
            }
        }

        // Sort the userids so that the primary user id is first.
        let mut userids: Vec<_> = acert.userids().collect();
        let primary_userid = vcert
            .and_then(|vcert| {
                vcert.primary_userid().ok().map(|u| u.userid())
            });
        userids.sort_by_key(|(_validity, userid)| {
            Some(userid.userid()) != primary_userid
        });
        for (validity, uid) in userids.into_iter() {
            let vuid = uid.clone().with_policy(p, config.now()).ok();

            // Unless explicitly requested, we don't list unusable
            // user ids.
            if ! config.list_options.unusable_uids {
                // We never list user ids without any self signatures.
                if uid.self_signatures().count() == 0 {
                    continue;
                }

                // In human readable mode, we don't list expired user
                // ids, or those that are revoked (unless the whole
                // cert is revoked).
                if ! config.with_colons
                    && ((validity.revoked && ! acert.cert_validity().revoked)
                        || vuid.is_none())
                {
                    continue;
                }
            }

            Record::UserID {
                amalgamation: uid.clone(),
                validity: (list_uid_validity
                           // For some reason, in the machine readable
                           // output, GnuPG disregards
                           // no-show-uid-validity if the validity is
                           // revoked, expired, or the ownertrust
                           // marks the cert as disabled.
                           || (config.with_colons
                               && (validity.revoked
                                   || validity.expired
                                   || ownertrust.disabled())))
                    .then_some(validity),
            }.emit(config, &mut sink)?;

            if config.list_options.list_sigs {
                for s in uid.signatures() {
                    let is_self_sig =
                        s.get_issuers().iter().any(|i| i.aliases(&cert_kh));

                    let (issuer_uid, validity) =
                        if config.list_options.fast_list {
                            (Some("".into()), None)
                        } else if is_self_sig {
                            (Some(best_effort_primary_userid.clone()), None)
                        } else {
                            if let Some(signer) =
                                s.get_issuers().into_iter().find_map(
                                    |k| config.keydb().lookup_by_cert_or_subkey(&k).ok())
                                .and_then(|certs| certs.into_iter().next())
                                .and_then(|cert| cert.to_cert().ok().cloned())
                            {
                                (Some(best_effort_primary_uid(config.policy(), &signer).into()),
                                 None)
                            } else {
                                (None, Some(SignatureValidity::MissingKey))
                            }
                        };

                    Record::Signature {
                        issuer: s.issuers().cloned().next().or_else(
                            || s.issuer_fingerprints().cloned().next().map(Into::into)),
                        issuer_fp: s.issuer_fingerprints().cloned().next(),
                        issuer_uid,
                        validity,
                        pk_algo: s.pk_algo(),
                        hash_algo: s.hash_algo(),
                        creation_time: s.signature_creation_time()
                            .expect("valid signatures have a creation time"),
                        typ: s.typ(),
                        exportable: s.exportable().is_ok(),
                        trust: s.trust_signature(),
                        has_notations: s.subpackets(SubpacketTag::NotationData)
                            .next().is_some(),
                    }.emit(config, &mut sink)?;
                }
            }
        }

        for (validity, subkey) in acert.subkeys() {
            // Don't display expired or revoked subkeys.
            if ! config.with_colons && (validity.expired || validity.revoked) {
                continue;
            }

            let vsubkey = subkey.clone().with_policy(p, config.now()).ok();
            let subkey_fp = subkey.fingerprint();
            let have_secret = has_secret.contains(&subkey_fp);

            Record::Subkey {
                key: subkey.key(),
                have_secret: have_secret && list_secret,
                validity: validity,
                expiration_date:  vsubkey.as_ref()
                    .and_then(|v| v.key_expiration_time()),
                revocation_date: vsubkey.as_ref()
                    .and_then(|v| if let RevocationStatus::Revoked(sigs)
                              = v.revocation_status()
                              {
                                  sigs[0].signature_creation_time()
                              } else {
                                  None
                              }),
                key_flags: vsubkey.as_ref()
                    .and_then(|v| v.key_flags())
                    .unwrap_or_else(|| KeyFlags::empty()),
                token_sn: have_secret.then(|| TokenSN::SecretAvaliable),
                compliance: subkey.compliance(config),
            }.emit(config, &mut sink)?;

            if config.with_colons || config.with_subkey_fingerprint {
                Record::Fingerprint(subkey_fp)
                    .emit(config, &mut sink)?;
            }
            if config.with_keygrip
                || (config.with_colons &&
                    (list_secret_keys_mode || have_secret))
            {
                if let Ok(grip) = Keygrip::of(subkey.mpis()) {
                    Record::Keygrip(grip).emit(config, &mut sink)?;
                }
            }


            if config.list_options.list_sigs {
                for s in subkey.signatures() {
                    let is_self_sig =
                        s.get_issuers().iter().any(|i| i.aliases(&cert_kh));

                    let (issuer_uid, validity) =
                        if config.list_options.fast_list {
                            (Some("".into()), None)
                        } else if is_self_sig {
                            (Some(best_effort_primary_userid.clone()), None)
                        } else {
                            if let Some(signer) =
                                s.get_issuers().into_iter().find_map(
                                    |k| config.keydb().lookup_by_cert_or_subkey(&k).ok())
                                .and_then(|certs| certs.into_iter().next())
                                .and_then(|cert| cert.to_cert().ok().cloned())
                            {
                                (Some(best_effort_primary_uid(config.policy(), &signer).into()),
                                 None)
                            } else {
                                (None, Some(SignatureValidity::MissingKey))
                            }
                        };

                    Record::Signature {
                        issuer: s.issuers().cloned().next().or_else(
                            || s.issuer_fingerprints().cloned().next().map(Into::into)),
                        issuer_fp: s.issuer_fingerprints().cloned().next(),
                        issuer_uid,
                        validity,
                        pk_algo: s.pk_algo(),
                        hash_algo: s.hash_algo(),
                        creation_time: s.signature_creation_time()
                            .expect("valid signatures have a creation time"),
                        typ: s.typ(),
                        exportable: s.exportable().is_ok(),
                        trust: s.trust_signature(),
                        has_notations: s.subpackets(SubpacketTag::NotationData)
                            .next().is_some(),
                    }.emit(config, &mut sink)?;
                }
            }
        }

        // Print a separating newline for humans.
        if ! config.with_colons {
            writeln!(sink)?;
        }
    }

    Ok(())
}
