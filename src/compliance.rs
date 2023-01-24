use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    crypto::mpi,
    Error,
    packet::{
        prelude::*,
        key::{PublicParts},
        Signature,
    },
    policy::{HashAlgoSecurity, Policy, StandardPolicy},
    types::*,
};

pub use crate::common::Compliance;

const STANDARD_POLICY: &dyn Policy = &StandardPolicy::new();

#[derive(Debug, Default)]
pub struct DeVSProducer {
    min_rsa_bits: usize,
}

impl DeVSProducer {
    pub fn new(min_rsa_bits: usize) -> Self {
        Self {
            min_rsa_bits,
        }
    }

    /// Returns an error if the key violates the policy.
    fn public_key<P, R>(&self, key: &Key<P, R>) -> openpgp::Result<()>
    where
        P: key::KeyParts,
        R: key::KeyRole,
    {
        use mpi::PublicKey::*;
        match key.mpis() {
            RSA { n, .. } => {
                let l = n.bits();
                if (l == 2048 || l == 3072 || l == 4096)
                    || l >= self.min_rsa_bits
                {
                    Ok(())
                } else {
                    Err(Error::PolicyViolation(format!(
                        "{}-bit RSA key", l), None).into())
                }
            },
            DSA { p , q, .. } => {
                let l = p.bits();
                if q.bits() == 256
                    && (l == 2048 || l == 3072)
                    && l >= self.min_rsa_bits
                {
                    Ok(())
                } else {
                    Err(Error::PolicyViolation(format!(
                        "DSA key with {}-bit P and {}-bit Q",
                        l, q.bits()), None).into())
                }
            },
            EdDSA { curve, .. }
            | ECDSA { curve, .. }
            | ECDH { curve, .. } => {
                use Curve::*;
                match curve {
                    BrainpoolP256
                    // XXX: | BrainpoolP384
                        | BrainpoolP512 => Ok(()),
                    a => return
                        Err(Error::PolicyViolation(a.to_string(), None).into()),
                }
            },
            _ => return Err(Error::PolicyViolation(key.fingerprint().to_string(),
                                                   None).into()),
        }
    }
}

impl Policy for DeVSProducer {
    fn signature(&self, sig: &Signature, _sec: HashAlgoSecurity)
                 -> openpgp::Result<()>
    {
        use HashAlgorithm::*;
        match sig.hash_algo() {
            SHA256 | SHA384 | SHA512 => (),
            a => return Err(Error::PolicyViolation(a.to_string(), None).into()),
        }

        Ok(())
    }

    fn key(&self, ka: &ValidErasedKeyAmalgamation<'_, PublicParts>)
           -> openpgp::Result<()>
    {
        self.public_key(ka.key())
    }

    fn symmetric_algorithm(&self, algo: SymmetricAlgorithm)
                           -> openpgp::Result<()>
    {
        use SymmetricAlgorithm::*;
        match algo {
            AES128 | AES192 | AES256 | TripleDES => Ok(()),
            a => Err(Error::PolicyViolation(a.to_string(), None).into()),
        }
    }

    fn aead_algorithm(&self, algo: AEADAlgorithm)
                      -> openpgp::Result<()>
    {
        STANDARD_POLICY.aead_algorithm(algo)
    }

    fn packet(&self, packet: &Packet)
              -> openpgp::Result<()>
    {
        STANDARD_POLICY.packet(packet)
    }
}

#[derive(Debug, Default)]
pub struct DeVSConsumer {
    min_rsa_bits: usize,
}

impl DeVSConsumer {
    pub fn new(min_rsa_bits: usize) -> Self {
        Self {
            min_rsa_bits,
        }
    }
}

impl Policy for DeVSConsumer {
    fn signature(&self, sig: &Signature, _sec: HashAlgoSecurity)
                 -> openpgp::Result<()>
    {
        use HashAlgorithm::*;
        match sig.hash_algo() {
            SHA256 | SHA384 | SHA512 => (),
            SHA1 | SHA224 | RipeMD => (),
            a => return Err(Error::PolicyViolation(a.to_string(), None).into()),
        }

        Ok(())
    }

    fn key(&self, ka: &ValidErasedKeyAmalgamation<'_, PublicParts>)
           -> openpgp::Result<()>
    {
        use mpi::PublicKey::*;
        match ka.mpis() {
            RSA { n, .. } => {
                let l = n.bits();
                if (l == 2048 || l == 3072 || l == 4096)
                    || l >= self.min_rsa_bits
                {
                    Ok(())
                } else {
                    Err(Error::PolicyViolation(format!(
                        "{}-bit RSA key", l), None).into())
                }
            },
            DSA { p , q, .. } => {
                let l = p.bits();
                if q.bits() == 256
                    && (l == 2048 || l == 3072)
                    && l >= self.min_rsa_bits
                {
                    Ok(())
                } else {
                    Err(Error::PolicyViolation(format!(
                        "DSA key with {}-bit P and {}-bit Q",
                        l, q.bits()), None).into())
                }
            },
            EdDSA { curve, .. }
            | ECDSA { curve, .. }
            | ECDH { curve, .. } => {
                use Curve::*;
                match curve {
                    BrainpoolP256
                    // XXX: | BrainpoolP384
                        | BrainpoolP512 => Ok(()),
                    a => return
                        Err(Error::PolicyViolation(a.to_string(), None).into()),
                }
            },
            _ => return Err(Error::PolicyViolation(ka.fingerprint().to_string(),
                                                   None).into()),
        }
    }

    fn symmetric_algorithm(&self, algo: SymmetricAlgorithm)
                           -> openpgp::Result<()>
    {
        use SymmetricAlgorithm::*;
        match algo {
            AES128 | AES192 | AES256 | TripleDES => Ok(()),
            Blowfish | Camellia128 | Camellia192 | Camellia256
                | CAST5 | IDEA | Twofish => Ok(()),
            a => Err(Error::PolicyViolation(a.to_string(), None).into()),
        }
    }

    fn aead_algorithm(&self, algo: AEADAlgorithm)
                      -> openpgp::Result<()>
    {
        STANDARD_POLICY.aead_algorithm(algo)
    }

    fn packet(&self, packet: &Packet)
              -> openpgp::Result<()>
    {
        STANDARD_POLICY.packet(packet)
    }
}

/// Computes the compliance flags for a key.
pub trait KeyCompliance {
    fn compliance(&self, config: &crate::Config) -> Vec<Compliance>;
}

impl<P, R> KeyCompliance for Key<P, R>
where
    P: key::KeyParts,
    R: key::KeyRole,
{
    fn compliance(&self, config: &crate::Config) -> Vec<Compliance> {
        let mut c = Vec::with_capacity(2);

        if self.version() == 5 {
            c.push(Compliance::GnuPG);
        }

        if config.de_vs_producer.public_key(self).is_ok() {
            c.push(Compliance::DeVs);
        }

        c
    }
}
