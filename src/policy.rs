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
    weak_digests: HashSet<HashAlgorithm>,

    /// Disabled public key algorithms.
    public_key_algo_badlist: HashSet<PublicKeyAlgorithm>,
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
            public_key_algo_badlist: Default::default(),
	})
    }

    /// Marks the given algorithm as weak.
    pub fn weak_digest(&mut self, algo: HashAlgorithm) {
        self.weak_digests.insert(algo);
    }

    /// Disables the given symmetric algorithm.
    pub fn reject_symmetric_algo(&mut self, a: SymmetricAlgorithm) {
        self.policy.reject_symmetric_algo(a);
    }

    /// Disables the given public key algorithm.
    ///
    /// There is a bit of an impedance mismatch between Sequoia's
    /// Policy (which considers `AsymmetricAlgorithm`s,
    /// i.e. algorithms and key sizes, and curves), and GnuPG's
    /// --disable-pubkey-algo (which considers `PublicKeyAlgorithm`s.
    /// This interface bridges that semantic gap.
    pub fn reject_public_key_algo(&mut self, a: PublicKeyAlgorithm) {
        use openpgp::policy::AsymmetricAlgorithm;

        // Keep track of the rejected `PublicKeyAlgorithm`s...
        self.public_key_algo_badlist.insert(a);

        // ... and also tweak the policy.
        match a {
            PublicKeyAlgorithm::RSAEncryptSign => {
                self.policy.reject_asymmetric_algo(
                    AsymmetricAlgorithm::RSA1024);
                self.policy.reject_asymmetric_algo(
                    AsymmetricAlgorithm::RSA2048);
                self.policy.reject_asymmetric_algo(
                    AsymmetricAlgorithm::RSA3072);
                self.policy.reject_asymmetric_algo(
                    AsymmetricAlgorithm::RSA4096);
            },

            PublicKeyAlgorithm::DSA => {
                self.policy.reject_asymmetric_algo(
                    AsymmetricAlgorithm::DSA1024);
                self.policy.reject_asymmetric_algo(
                    AsymmetricAlgorithm::DSA2048);
                self.policy.reject_asymmetric_algo(
                    AsymmetricAlgorithm::DSA3072);
                self.policy.reject_asymmetric_algo(
                    AsymmetricAlgorithm::DSA4096);
            },

            PublicKeyAlgorithm::ElGamalEncrypt => {
                self.policy.reject_asymmetric_algo(
                    AsymmetricAlgorithm::ElGamal1024);
                self.policy.reject_asymmetric_algo(
                    AsymmetricAlgorithm::ElGamal2048);
                self.policy.reject_asymmetric_algo(
                    AsymmetricAlgorithm::ElGamal3072);
                self.policy.reject_asymmetric_algo(
                    AsymmetricAlgorithm::ElGamal4096);
            },

            _ => (),
        }

        if self.public_key_algo_badlist.contains(&PublicKeyAlgorithm::ECDH)
            && self.public_key_algo_badlist.contains(&PublicKeyAlgorithm::EdDSA)
        {
            self.policy.reject_asymmetric_algo(
                AsymmetricAlgorithm::Cv25519);
        }

        if self.public_key_algo_badlist.contains(&PublicKeyAlgorithm::ECDH)
            && self.public_key_algo_badlist.contains(&PublicKeyAlgorithm::ECDSA)
        {
            self.policy.reject_asymmetric_algo(
                AsymmetricAlgorithm::NistP256);
            self.policy.reject_asymmetric_algo(
                AsymmetricAlgorithm::NistP384);
            self.policy.reject_asymmetric_algo(
                AsymmetricAlgorithm::NistP521);
            self.policy.reject_asymmetric_algo(
                AsymmetricAlgorithm::BrainpoolP256);
            self.policy.reject_asymmetric_algo(
                AsymmetricAlgorithm::BrainpoolP384);
            self.policy.reject_asymmetric_algo(
                AsymmetricAlgorithm::BrainpoolP512);
        }
    }

    /// Checks whether the given public key algorithm is okay to use.
    pub fn public_key_algorithm(&self, a: PublicKeyAlgorithm) -> Result<()> {
        if self.public_key_algo_badlist.contains(&a) {
            Err(openpgp::Error::PolicyViolation(a.to_string(), None).into())
        } else {
            Ok(())
        }
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
