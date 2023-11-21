//! Translates GnuPG-speak from and to Sequoia-speak.

use std::{
    fmt,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    types::*,
    packet::Tag,
};

use crate::{
    common::BRAINPOOL_P384_OID,
};

/// Translates values to and from human-readable forms.
pub struct Fish<T>(pub T);

impl fmt::Display for Fish<std::time::SystemTime> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}",
               chrono::DateTime::<chrono::Local>::from(self.0)
               .format("%a %b %e %H:%M:%S %Y %Z"))
    }
}

impl fmt::Display for Fish<openpgp::types::Duration> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut value = self.0.as_secs();
        value /= 60;
        let minutes = value % 60;
        value /= 60;
        let hours = value % 24;
        value /= 24;
        let days = value % 365;
        value /= 365;
        let years = value;

        if days == 0 && years == 0 {
            write!(f, "{}h{}m", hours, minutes)
        } else if years == 0 {
            write!(f, "{}d{}h{}m", days, hours, minutes)
        } else {
            write!(f, "{}y{}d{}h{}m", years, days, hours, minutes)
        }
    }
}

impl fmt::Display for Fish<PublicKeyAlgorithm> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match self.0 {
            RSAEncryptSign => f.write_str("RSA"),
            RSAEncrypt => f.write_str("RSA"),
            RSASign => f.write_str("RSA"),
            ElGamalEncrypt => f.write_str("ELG"),
            DSA => f.write_str("DSA"),
            ECDSA => f.write_str("ECDSA"),
            ElGamalEncryptSign => f.write_str("ELG"),
            ECDH => f.write_str("ECDH"),
            EdDSA => f.write_str("EDDSA"),
            Private(u) => write!(f, "Private({})", u),
            Unknown(u) => write!(f, "Unknown({})", u),
            catchall => write!(f, "{:?}", catchall),
        }
    }
}

impl fmt::Display for Fish<&Curve> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Curve::*;
        match self.0 {
            NistP256 => f.write_str("nistp256"),
            NistP384 => f.write_str("nistp384"),
            NistP521 => f.write_str("nistp521"),
            BrainpoolP256 => f.write_str("brainpoolP256r1"),
            Unknown(oid) if &oid[..] == BRAINPOOL_P384_OID =>
                f.write_str("brainpoolP384r1"),
            BrainpoolP512 => f.write_str("brainpoolP512r1"),
            Ed25519 => f.write_str("ed25519"),
            Cv25519 => f.write_str("cv25519"),
            Unknown(ref oid) => write!(f, "Unknown curve {:?}", oid),
        }
    }
}

impl fmt::Display for Fish<(PublicKeyAlgorithm, usize, &Option<Curve>)> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            (_, _, Some(curve)) => Fish(curve).fmt(f),
            (algo, size, _) => write!(f, "{}{}",
                                      Fish(algo).to_string().to_lowercase(),
                                      size),
        }
    }
}

impl fmt::Display for Fish<SymmetricAlgorithm> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SymmetricAlgorithm::*;
        #[allow(deprecated)]
        match self.0 {
            Unencrypted => f.write_str("Unencrypted"),
            IDEA => f.write_str("IDEA"),
            TripleDES => f.write_str("3DES"),
            CAST5 => f.write_str("CAST5"),
            Blowfish => f.write_str("BLOWFISH"),
            AES128 => f.write_str("AES"),
            AES192 => f.write_str("AES192"),
            AES256 => f.write_str("AES256"),
            Twofish => f.write_str("TWOFISH"),
            Camellia128 => f.write_str("CAMELLIA128"),
            Camellia192 => f.write_str("CAMELLIA192"),
            Camellia256 => f.write_str("CAMELLIA256"),
            Private(u) => write!(f, "Private({})", u),
            Unknown(u) => write!(f, "Unknown({})", u),
            catchall => write!(f, "{:?}", catchall),
        }
    }
}

impl fmt::Display for Fish<AEADAlgorithm> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AEADAlgorithm::*;
        #[allow(deprecated)]
        match self.0 {
            EAX => f.write_str("EAX"),
            OCB => f.write_str("OCB"),
            GCM => f.write_str("GCM"),
            catchall => write!(f, "{:?}", catchall),
        }
    }
}

impl fmt::Display for Fish<HashAlgorithm> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use HashAlgorithm::*;
        #[allow(deprecated)]
        match self.0 {
            MD5 => f.write_str("MD5"),
            SHA1 => f.write_str("SHA1"),
            RipeMD => f.write_str("RIPEMD160"),
            SHA256 => f.write_str("SHA256"),
            SHA384 => f.write_str("SHA384"),
            SHA512 => f.write_str("SHA512"),
            SHA224 => f.write_str("SHA224"),
            Private(u) => write!(f, "Private({})", u),
            Unknown(u) => write!(f, "Unknown({})", u),
            catchall => write!(f, "{:?}", catchall),
        }
    }
}

impl fmt::Display for Fish<CompressionAlgorithm> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CompressionAlgorithm::*;
        #[allow(deprecated)]
        match self.0 {
            Uncompressed => f.write_str("Uncompressed"),
            Zip => f.write_str("ZIP"),
            Zlib => f.write_str("ZLIB"),
            BZip2 => f.write_str("BZIP2"),
            Private(u) => write!(f, "Private({})", u),
            Unknown(u) => write!(f, "Unknown({})", u),
            catchall => write!(f, "{:?}", catchall),
        }
    }
}

impl fmt::Display for Fish<&KeyFlags> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // We use the alternate flag to differentiate between
        // displaying flags for key listing for machine-readable
        // output (alternate on), and displaying flags for key listing
        // for human consumption (alternate ff).
        if f.alternate()
            && (self.0.for_storage_encryption()
                || self.0.for_transport_encryption())
        {
            f.write_str("e")?;
        }

        if self.0.for_signing() {
            f.write_str("s")?;
        }

        if self.0.for_certification() {
            f.write_str("c")?;
        }

        if ! f.alternate()
            && (self.0.for_storage_encryption()
                || self.0.for_transport_encryption())
        {
            f.write_str("e")?;
        }

        if self.0.for_authentication() {
            f.write_str("a")?;
        }

        // XXX unknown flags

        Ok(())
    }
}

impl fmt::Display for Fish<ReasonForRevocation> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ReasonForRevocation::*;
        match self.0 {
            Unspecified =>
                f.write_str("No reason specified"),
            KeySuperseded =>
                f.write_str("Key is superseded"),
            KeyCompromised =>
                f.write_str("Key has been compromised"),
            KeyRetired =>
                f.write_str("Key is no longer used"),
            UIDRetired =>
                f.write_str("User ID is no longer valid"),
            Private(u) =>
                write!(f, "Private/Experimental revocation reason {}", u),
            Unknown(u) =>
                write!(f, "Unknown revocation reason {}", u),
            u => write!(f, "{}", u),
        }
    }
}

impl fmt::Display for Fish<Tag> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Tag::Reserved =>
                f.write_str("Reserved - a packet tag MUST NOT have this value"),
            Tag::PKESK =>
                f.write_str("pubkey enc packet"),
            Tag::Signature =>
                f.write_str("signature packet"),
            Tag::SKESK =>
                f.write_str("symkey enc packet"),
            Tag::OnePassSig =>
                f.write_str("onepass_sig packet"),
            Tag::SecretKey =>
                f.write_str("secret key packet"),
            Tag::PublicKey =>
                f.write_str("public key packet"),
            Tag::SecretSubkey =>
                f.write_str("secret sub key packet"),
            Tag::CompressedData =>
                f.write_str("compressed packet"),
            Tag::SED =>
                f.write_str("encrypted data packet"),
            Tag::Marker =>
                f.write_str("marker packet"),
            Tag::Literal =>
                f.write_str("literal data packet"),
            Tag::Trust =>
                f.write_str("trust packet"),
            Tag::UserID =>
                f.write_str("user ID packet"),
            Tag::PublicSubkey =>
                f.write_str("public sub key packet"),
            Tag::UserAttribute =>
                f.write_str("attribute packet"),
            Tag::SEIP =>
                f.write_str("encrypted data packet"),
            Tag::MDC =>
                f.write_str("mdc packet"),
            Tag::AED =>
                f.write_str("encrypted data packet"),
            Tag::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental Packet {}", u)),
            Tag::Unknown(u) =>
                f.write_fmt(format_args!("Unknown Packet {}", u)),
        }
    }
}
