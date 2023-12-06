use std::{
    collections::HashSet,
};

use anyhow::Result;

use sequoia_openpgp::{
    self as openpgp,
    cert::prelude::*,
    packet::{
	key::PublicParts,
	Packet,
	Signature,
    },
    policy::{HashAlgoSecurity, Policy, StandardPolicy},
    types::*,
};
use sequoia_policy_config::ConfiguredStandardPolicy;

#[derive(Debug, Clone)]
pub struct GPGPolicy {
    /// The standard policy that we refine.
    policy: StandardPolicy<'static>,

    /// Additional weak hash algorithms.
    ///
    /// The value indicates whether a warning has been printed for
    /// this algorithm.
    weak_digests: HashSet<HashAlgorithm>,
}

impl GPGPolicy {
    /// Creates a new policy object based upon a global configuration
    /// file.
    ///
    /// Uses
    /// [`sequoia_policy_config::ConfiguredStandardPolicy::parse_default_config`]
    /// as a basis for later refinement using the GnuPG configuration.
    pub fn new() -> Result<Self> {
	let mut policy = ConfiguredStandardPolicy::new();
	policy.parse_default_config()?;
	let policy = policy.build();

	Ok(GPGPolicy {
	    policy,
	    weak_digests: Default::default(),
	})
    }

    /// Marks the given algorithm as weak.
    pub fn weak_digest(&mut self, algo: HashAlgorithm) {
        self.weak_digests.insert(algo);
    }
}

impl Policy for GPGPolicy {
    fn signature(&self, sig: &Signature, sec: HashAlgoSecurity)
                 -> openpgp::Result<()>
    {
        // First, consult the standard policy.
        self.policy.signature(sig, sec)?;


        // Then, consult our set.
        if self.weak_digests.contains(&sig.hash_algo()) {
            return Err(openpgp::Error::PolicyViolation(
                sig.hash_algo().to_string(), None).into());
        }

        Ok(())
    }

    fn key(&self, ka: &ValidErasedKeyAmalgamation<'_, PublicParts>)
           -> openpgp::Result<()>
    {
        self.policy.key(ka)
    }

    fn symmetric_algorithm(&self, algo: SymmetricAlgorithm)
                           -> openpgp::Result<()>
    {
        self.policy.symmetric_algorithm(algo)
    }

    fn aead_algorithm(&self, algo: AEADAlgorithm)
                      -> openpgp::Result<()>
    {
        self.policy.aead_algorithm(algo)
    }

    fn packet(&self, packet: &Packet)
              -> openpgp::Result<()>
    {
        self.policy.packet(packet)
    }
}
