//! Automatic retrieval of OpenPGP certificates.

use std::fmt;

use anyhow::Context;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoKeyLocate {
    NoDefault,
    Local,
    Ldap,
    KeyServer,
    Cert,
    PKa,
    Dane,
    Wkd,
    Ntds,
    KeyServerUri(reqwest::Url),
}

impl std::str::FromStr for AutoKeyLocate {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "nodefault" => Ok(AutoKeyLocate::NoDefault),
            "local" => Ok(AutoKeyLocate::Local),
            "ldap" => Ok(AutoKeyLocate::Ldap),
            "keyserver" => Ok(AutoKeyLocate::KeyServer),
            "cert" => Ok(AutoKeyLocate::Cert),
            "pka" => Ok(AutoKeyLocate::PKa),
            "dane" => Ok(AutoKeyLocate::Dane),
            "wkd" => Ok(AutoKeyLocate::Wkd),
            "ntds" => Ok(AutoKeyLocate::Ntds),
            url => match reqwest::Url::parse(&url) {
                Ok(url) => Ok(AutoKeyLocate::KeyServerUri(url)),
                Err(e) => Err(anyhow::anyhow!(
                    "This is not a keyserver url either: {}", e
                )).with_context(
                    || format!("Unknown --auto-key-locate mode {:?}.", s)),
            },
        }
    }
}

impl fmt::Display for AutoKeyLocate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AutoKeyLocate::*;
        match self {
            NoDefault => f.write_str("nodefault"),
            Local => f.write_str("local"),
            Ldap => f.write_str("ldap"),
            KeyServer => f.write_str("keyserver"),
            Cert => f.write_str("cert"),
            PKa => f.write_str("pka"),
            Dane => f.write_str("dane"),
            Wkd => f.write_str("wkd"),
            Ntds => f.write_str("ntds"),
            KeyServerUri(url) => write!(f, "{}", url),
        }
    }
}
