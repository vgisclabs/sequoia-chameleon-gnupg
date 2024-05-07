//! Trust models and associated machinery.

/// The default value for the --marginals-needed option.
pub const DEFAULT_MARGINALS_NEEDED: u8 = 3;

/// The default value for the --completes-needed option.
pub const DEFAULT_COMPLETES_NEEDED: u8 = 1;

/// The default value for the --max-cert-depth option.
pub const DEFAULT_MAX_CERT_DEPTH: u8 = 5;

pub use crate::common::{
    cert,
    Common,
    Model,
    ModelViewAt,
    OwnerTrust,
    OwnerTrustLevel,
    Query,
    TrustModel,
    Validity,
    ValidityLevel,
};

pub mod db;
mod pgp;
pub use pgp::WoT;
mod always;
pub use always::Always;

/// Controls tracing in this module.
pub fn trace(enable: bool) {
    pgp::trace(enable);
}

impl TrustModel {
    pub fn build(&self, config: &crate::Config) -> crate::Result<Box<dyn Model>>
    {
        use TrustModel::*;
        let mut model = self.clone();

        // Read the trust model information from the arguments,
        // falling back to information from the trust db, falling back
        // to the defaults.
        let trust_config = config.trustdb.version(config);

        if let Auto = model {
            // Sanity checks.
            model = match trust_config.model {
                GnuPG | Classic | PGP | TofuPGP | Sequoia | SequoiaGnuPG
                    => trust_config.model,
                Auto => Default::default(),
                m => {
                    let n = Default::default();
                    config.info(format_args!(
                        "unable to use unknown trust model {:?} - \
		         assuming {:?} trust model\n", m, n));
                    n
                },
            };

            assert_ne!(model, Auto);  // The buck stops here.
        }

        match model {
            Auto => unreachable!(),
            SequoiaGnuPG | PGP | TofuPGP =>
                WoT::new().with_sequoia_roots()
                .with_gnupg_roots(trust_config.marginals_needed,
                                  trust_config.completes_needed)
                .build(),
            Sequoia =>
                WoT::new().with_sequoia_roots().build(),
            GnuPG =>
                WoT::new()
                .with_gnupg_roots(trust_config.marginals_needed,
                                  trust_config.completes_needed)
                .build(),
            Always => Ok(Box::new(always::Always::default())),
            _ => Err(anyhow::anyhow!("Trust model {:?} not implemented", self))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TofuPolicy {
    Auto,
    Good,
    Unknown,
    Bad,
    Ask,
}

impl Default for TofuPolicy {
    fn default() -> Self {
        TofuPolicy::Auto // XXX
    }
}

impl std::str::FromStr for TofuPolicy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(TofuPolicy::Auto),
            "good" => Ok(TofuPolicy::Good),
            "unknown" => Ok(TofuPolicy::Unknown),
            "bad" => Ok(TofuPolicy::Bad),
            "ask" => Ok(TofuPolicy::Ask),
            _ => Err(anyhow::anyhow!("Unknown TOFU policy {:?}", s)),
        }
    }
}
