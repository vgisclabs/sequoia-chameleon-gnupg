use std::{
    io,
    time::SystemTime,
};

use chrono::{DateTime, Utc};

use sequoia_openpgp::{
    self as openpgp,
    Fingerprint,
    KeyID,
    crypto::mpi::{self, SecretKeyChecksum},
    serialize::MarshalInto,
    parse::{
        PacketParserResult,
        Parse,
        map::Map,
        stream::DecryptionHelper,
    },
    types::{
        AEADAlgorithm,
        HashAlgorithm,
        SymmetricAlgorithm,
        Timestamp,
    },
};
use self::openpgp::fmt::hex;
use self::openpgp::{Packet, Result};
use self::openpgp::packet::prelude::*;
use self::openpgp::packet::header::CTB;
use self::openpgp::packet::{Header, header::BodyLength};
use self::openpgp::packet::signature::subpacket::{Subpacket, SubpacketValue};
use self::openpgp::crypto::S2K;

use crate::{
    babel,
    common::Common,
    status::Status,
    utils,
};

#[allow(clippy::redundant_pattern_matching)]
/// Dispatches the --list-packets command.
pub fn cmd_list_packets(config: &crate::Config, args: &[String])
                        -> Result<()>
{
    let input =
        utils::open(config, args.get(0).map(|s| s.as_str()).unwrap_or("-"))?;
    let mut output = io::stdout(); // XXX

    let mut dumper = PacketDumper::new();

    let mut ppr
        = self::openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(true).build()?;

    // In case we encounter a decryption container, we'll need a
    // decryption helper.
    let mut helper = crate::decrypt::DHelper::new(
        config, crate::verify::VHelper::new(config, 1));

    // This roughly tracks the offset in the stream.
    let mut offset = 0;

    // Encrypted session keys for potential decryption.
    let mut pkesks = Vec::new();
    let mut skesks = Vec::new();

    // Tracks nested containers and their type.
    let mut in_container = Vec::new();

    while let PacketParserResult::Some(mut pp) = ppr {
        let mut body_length = 0;
        let additional_fields = match pp.packet {
            Packet::Literal(_) => {
                body_length = io::copy(&mut pp, &mut io::sink())?;
                vec![
                    format!("raw data: {} bytes", body_length),
                ]
            },
            Packet::CompressedData(_) => {
                in_container.push(pp.packet.tag());
                vec![]
            },
            Packet::SEIP(_) | Packet::AED(_) => {
                in_container.push(pp.packet.tag());
                helper.uses_mdc();
                let r = helper.decrypt(&pkesks, &skesks, None,
                                       |algo, sk| pp.decrypt(algo, sk).is_ok());
                if r.is_ok() {
                    config.status().emit(Status::DecryptionOkay)?;
                    // For compatibility reasons we issue GOODMDC also
                    // for AEAD messages.
                    config.status().emit(Status::GoodMDC)?;
                }
                config.status().emit(Status::EndDecryption)?;
                vec![]
            },
            _ => Vec::new(),
        };

        let header = pp.header().clone();
        let map = pp.take_map().expect("we turned mapping on");

        let packet_len: u64 = match &pp.packet {
            Packet::CompressedData(_) =>
                u64::try_from(header.serialized_len())? + 1,
            _ =>
                u64::try_from(header.serialized_len())?
                + match header.length() {
                    BodyLength::Full(l) => (*l).into(),
                    BodyLength::Partial(_) => body_length,
                    BodyLength::Indeterminate => body_length,
                },
        };

        let old_recursion_depth = pp.recursion_depth();
        let (packet, ppr_) = match pp.recurse() {
            Ok(v) => v,
            Err(_) => {
                break;
            },
        };
        ppr = ppr_;

        // See if we ascended from a container, and if that was a SEIP
        // one.
        let just_ascended =
            ppr.as_ref()
            .map(|pp| pp.recursion_depth() < old_recursion_depth)
            .unwrap_or(true); // End of stream.
        let just_ascended_from_seip = if just_ascended {
            in_container.pop() == Some(Tag::SEIP)
        } else {
            false
        };

        // GnuPG does not display the MDC packet in SEIPDv1 packets.
        if ! (just_ascended_from_seip && packet.tag() == Tag::MDC) {
            dumper.packet(&mut output, offset,
                          header, &packet, map, additional_fields)?;
        }

        // Adjust offset.
        offset += packet_len;
        // XXX: The offset inside of encryption containers is wrong,
        // but that is a nonsensical value in GnuPG anyways, so for
        // now I don't bother.

        match packet {
            Packet::PKESK(p) => pkesks.push(p),
            Packet::SKESK(p) => skesks.push(p),
            Packet::Unknown(u) => {
                config.error(format_args!(
                    "invalid {}", babel::Fish(u.tag())));
            },
            _ => (),
        }
    }

    Ok(())
}

pub struct PacketDumper {
}

impl PacketDumper {
    pub fn new() -> Self {
        PacketDumper {
        }
    }

    pub fn packet(&mut self, output: &mut dyn io::Write,
                  offset: u64,
                  header: Header, p: &Packet, map: Map,
                  additional_fields: Vec<String>)
                  -> Result<()> {
        use self::openpgp::Packet::*;

        writeln!(output, "# off={} ctb={:02x} tag={} hlen={} plen={}{}",
                 offset,
                 map.iter().nth(0).unwrap().as_bytes()[0],
                 u8::from(p.tag()),
                 1 + map.iter().nth(1).unwrap().as_bytes().len(),
                 match header.length() {
                     BodyLength::Full(l) => l.to_string(),
                     BodyLength::Partial(l) => format!("partial {}", l),
                     BodyLength::Indeterminate => "indeterminate".into(),
                 },
                 if let CTB::Old(_) = header.ctb() { "" } else { " new-ctb" })?;

        write!(output, ":{}:", babel::Fish(p.tag()))?;

        match p {
            Unknown(_) =>
                writeln!(output, " [invalid]")?,

            PublicKey(k) => self.dump_key(output, &k)?,
            PublicSubkey(k) => self.dump_key(output, &k)?,
            SecretKey(k) => self.dump_key(output, &k)?,
            SecretSubkey(k) => self.dump_key(output, &k)?,

            Signature(s) => {
                writeln!(output, " algo {}, keyid {:X}", u8::from(s.pk_algo()),
                         KeyID::from(s.get_issuers().get(0).cloned()
                                     .unwrap_or_else(|| KeyID::wildcard().into())))?;

                writeln!(output,
                         "\tversion {}, created {}, md5len 0, sigclass 0x{:02x}",
                         s.version(),
                         s.signature_creation_time()
                         .and_then(|t| Timestamp::try_from(t).ok())
                         .map(u32::from).unwrap_or_default(),
                         u8::from(s.typ()))?;
                writeln!(output,
                         "\tdigest algo {}, begin of digest {:02x} {:02x}",
                         u8::from(s.hash_algo()),
                         s.digest_prefix()[0],
                         s.digest_prefix()[1])?;

                if s.hashed_area().iter().count() > 0 {
                    for pkt in s.hashed_area().iter() {
                        self.dump_subpacket(output, true, pkt)?;
                    }
                }
                if s.unhashed_area().iter().count() > 0 {
                    for pkt in s.unhashed_area().iter() {
                        self.dump_subpacket(output, false, pkt)?;
                    }
                }

                match s.mpis() {
                    mpi::Signature::RSA { s } =>
                        self.dump_mpis(output,
                                       &[s.bits()],
                                       &[])?,
                    mpi::Signature::DSA { r, s } =>
                        self.dump_mpis(output,
                                       &[r.bits(), s.bits()],
                                       &[])?,
                    mpi::Signature::ElGamal { r, s } =>
                        self.dump_mpis(output,
                                       &[r.bits(), s.bits()],
                                       &[])?,
                    mpi::Signature::EdDSA { r, s } =>
                        self.dump_mpis(output,
                                       &[r.bits(), s.bits()],
                                       &[])?,
                    mpi::Signature::ECDSA { r, s } =>
                        self.dump_mpis(output,
                                       &[r.bits(), s.bits()],
                                       &[])?,
                    mpi::Signature::Unknown { mpis, rest } =>
                        self.dump_mpis(
                            output,
                            &mpis.iter().map(|m| m.bits())
                                .chain(std::iter::once(rest.len() * 8))
                                .collect::<Vec<_>>(),
                            &[])?,

                    // crypto::mpi::Signature is non-exhaustive.
                    _ => {
                        // XXX: Not sure what to do.
                        0
                    },
                };
            },

            OnePassSig(o) => {
                writeln!(output, " keyid {:X}", o.issuer())?;
                writeln!(output, "\tversion {}, sigclass 0x{:02x}, \
                                  digest {}, pubkey {}, last={}",
                         o.version(),
                         u8::from(o.typ()),
                         u8::from(o.hash_algo()),
                         u8::from(o.pk_algo()),
                         o.last_raw())?;
            },

            Trust(t) => {
                writeln!(output, " sig flag={:02x} sigcache={:02x}",
                         t.value().get(0).unwrap_or(&0),
                         0, // XXX
                )?;
            },

            UserID(u) => {
                write!(output, " \"")?;
                for b in u.value() {
                    if (b' '..=b'z').contains(b) {
                        write!(output, "{}", char::from(*b))?;
                    } else {
                        write!(output, "\\x{:02x}", b)?;
                    }
                }
                writeln!(output, "\"")?;
            },

            UserAttribute(u) => {
                use self::openpgp::packet::user_attribute::{Subpacket, Image};
                for subpacket in u.subpackets() {
                    match subpacket {
                        Ok(Subpacket::Image(image)) => match image {
                            Image::JPEG(data) =>
                                writeln!(output, " [jpeg image of size {}]",
                                         data.len())?,
                            Image::Private(_, data) |
                            Image::Unknown(_, data) =>
                                writeln!(output, " [unknown image of size {}]",
                                         data.len())?,
                        },
                        Ok(Subpacket::Unknown(_, data)) =>
                            writeln!(output, " [unknown attribute of size {}]",
                                     data.len())?,
                        Err(_) =>
                            writeln!(output, "[invalid image]")?,
                    }
                }
            },

            Marker(_) => {
                writeln!(output, " PGP")?;
            },

            Literal(l) => {
                writeln!(output)?;
                writeln!(output, "\tmode {} ({:2x}), created {}, name={:?},",
                         u8::from(l.format()) as char, u8::from(l.format()),
                         l.date().and_then(|t| Timestamp::try_from(t).ok())
                         .map(|t| u32::from(t)).unwrap_or_default(),
                         l.filename().map(String::from_utf8_lossy)
                         .unwrap_or_default())?;
            },

            CompressedData(c) => {
                writeln!(output, " algo={}", u8::from(c.algo()))?;
            },

            PKESK(p) => {
                writeln!(output, " version {}, algo {}, keyid {:X}",
                         p.version(),
                         u8::from(p.pk_algo()),
                         p.recipient())?;
                match p.esk() {
                    mpi::Ciphertext::RSA { c } =>
                        self.dump_mpis(output,
                                       &[c.bits()],
                                       &[])?,
                    mpi::Ciphertext::ElGamal { e, c } =>
                        self.dump_mpis(output,
                                       &[e.bits(), c.bits()],
                                       &[])?,
                    mpi::Ciphertext::ECDH { e, key } =>
                        self.dump_mpis(output,
                                       &[e.bits(), key.len() * 8],
                                       &[])?,
                    mpi::Ciphertext::Unknown { mpis, rest } =>
                        self.dump_mpis(
                            output,
                            &mpis.iter().map(|m| m.bits())
                                .chain(std::iter::once(rest.len() * 8))
                                .collect::<Vec<_>>(),
                            &[])?,

                    // crypto::mpi::Ciphertext is non-exhaustive.
                    _ => 0, // Just ignore.
                };
            },

            SKESK(openpgp::packet::SKESK::V4(s)) => {
                let write_parameters =
                    |o: &mut dyn io::Write, hash: &HashAlgorithm, salt, count| -> Result<()>
                {
                    #[allow(deprecated)]
                    writeln!(o, " version {}, cipher {}, aead {},\
                                 s2k {}, hash {}, seskey {} bits",
                             4, // XXX
                             u8::from(s.symmetric_algo()),
                             0, // XXX
                             match s.s2k() {
                                 S2K::Simple { .. } => 1,
                                 S2K::Salted { .. } => 2,
                                 S2K::Iterated { .. } => 3,
                                 S2K::Private { tag, .. } |
                                 S2K::Unknown { tag, .. } => *tag,
                                 _ => 0,
                             },
                             u8::from(*hash),
                             s.symmetric_algo().key_size().unwrap_or(0) * 8)?;
                    if let Some(salt) = salt {
                        write!(o, "\tsalt {}", hex::encode(salt))?;
                        if let Some(count) = count {
                            write!(o, ", count {} ({})",
                                   count,
                                   utils::s2k_encode_iteration_count(count)
                                   .unwrap_or_default())?;
                        }
                        writeln!(o)?;
                    }

                    // XXX: What to do about AEAD?

                    Ok(())
                };

                #[allow(deprecated)]
                match s.s2k() {
                    S2K::Simple { hash } =>
                        write_parameters(output, hash, None, None)?,
                    S2K::Salted { hash, salt } =>
                        write_parameters(output, hash, Some(salt), None)?,
                    S2K::Iterated { hash, salt, hash_bytes } =>
                        write_parameters(output, hash, Some(salt),
                                         Some(*hash_bytes))?,
                    S2K::Private { .. } | S2K::Unknown { .. } | _ => (),
                }
            },

            SEIP(_) => {
                writeln!(output)?;
                match header.length() {
                    BodyLength::Full(l) =>
                        writeln!(output, "\tlength: {}", l)?,
                    _ => (), // XXX: What happens in the other cases?
                }
                // XXX: What to do for SEIPDv2?
                writeln!(output, "\tmdc_method: {}", 2)?;
            },

            MDC(_) => {
                writeln!(output, " length=20")?;
            },

            AED(a) => {
                writeln!(output, "\tVersion: {}", a.version())?;
                writeln!(output, "\tSymmetric algo: {}", a.symmetric_algo())?;
                writeln!(output, "\tAEAD: {}", a.aead())?;
                writeln!(output, "\tChunk size: {}", a.chunk_size())?;
                writeln!(output, "\tIV: {}", hex::encode(a.iv()))?;
            },

            // openpgp::Packet is non-exhaustive.
            _ => writeln!(output, " [invalid]")?,
        }

        for field in additional_fields {
            writeln!(output, "\t{}", field)?;
        }

        Ok(())
    }

    fn dump_subpacket(&self, output: &mut dyn io::Write,
                      hashed: bool, s: &Subpacket)
                      -> Result<()> {
        use self::SubpacketValue::*;

        write!(output, "\t")?;
        if s.critical() {
            write!(output, "critical ")?;
        }

        if hashed {
            write!(output, "hashed ")?;
        }
        write!(output, "subpkt {} len {}",
               u8::from(s.tag()), s.value().serialized_len())?;

        let i = "";
        match s.value() {
            Unknown { .. } =>
                writeln!(output, " (?)")?,
            SignatureCreationTime(t) =>
                writeln!(output, " (sig created {})",
                         DateTime::<Utc>::from(SystemTime::from(*t))
                         .format("%Y-%m-%d"))?,
            SignatureExpirationTime(t) =>
                if t.as_secs() == 0 {
                    writeln!(output, " (sig does not expire)")?;
                } else {
                    writeln!(output, " (sig expires after {})",
                             babel::Fish(*t))?
                },
            ExportableCertification(e) =>
                writeln!(output, " ({}exportable)",
                         if *e { "" } else { "not " })?,
            TrustSignature { level, trust } =>
                writeln!(output, " (trust signature of depth {}, value {})",
                         level, trust)?,
            RegularExpression(r) =>
                writeln!(output, " (regular expression: \"{}\\0\")",
                         utils::sanitize_ascii_str(r, b"\""))?,
            Revocable(r) =>
                writeln!(output, " ({}revocable)",
                         if *r { "" } else { "not " })?,
            KeyExpirationTime(t) =>
                if t.as_secs() == 0 {
                    writeln!(output, " (key does not expire)")?;
                } else {
                    writeln!(output, " (key expires after {})",
                             babel::Fish(*t))?;
                },
            PreferredSymmetricAlgorithms(a) =>
                writeln!(output, " (pref-sym-algos: {})",
                         a.iter().map(|a| u8::from(*a).to_string())
                         .collect::<Vec<String>>().join(" "))?,
            RevocationKey(rk) => {
                let (pk_algo, fp) = rk.revoker();
                writeln!(output, " (revocation key: c={:02X} a={} f={:X})",
                         rk.class(), u8::from(pk_algo), fp)?;
            },
            Issuer(is) =>
                writeln!(output, " (issuer key ID {:X})", is)?,
            NotationData(n) =>
                writeln!(output, " (notation: {}={})",
                         n.name(),
                         if n.flags().human_readable() {
                             utils::sanitize_ascii_str(n.value(), b")")
                         } else {
                             "[not human readable]".into()
                         })?,
            PreferredHashAlgorithms(a) =>
                writeln!(output, " (pref-hash-algos: {})",
                         a.iter().map(|a| u8::from(*a).to_string())
                         .collect::<Vec<String>>().join(" "))?,
            PreferredCompressionAlgorithms(a) =>
                writeln!(output, " (pref-zip-algos: {})",
                         a.iter().map(|a| u8::from(*a).to_string())
                         .collect::<Vec<String>>().join(" "))?,
            KeyServerPreferences(p) =>
                writeln!(output, " (keyserver preferences: {:02X})",
                         // XXX: Use as_bytes in the future.
                         (0..8).into_iter()
                         .map(|a| if p.get(a) { 1 << a } else { 0 })
                         .sum::<u8>(),
                )?,
            PreferredKeyServer(k) =>
                writeln!(output, "{}    Preferred keyserver: {}", i,
                       String::from_utf8_lossy(k))?,
            PrimaryUserID(_) =>
                writeln!(output, " (primary user ID)")?,
            PolicyURI(p) =>
                writeln!(output, " (policy: {})",
                         utils::sanitize_ascii_str(p, b")"))?,
            KeyFlags(f) =>
                writeln!(output, " (key flags: {:02X})",
                         // XXX: Use as_bytes in the future.
                         (0..8).into_iter()
                         .map(|a| if f.get(a) { 1 << a } else { 0 })
                         .sum::<u8>())?,
            SignersUserID(_) =>
                writeln!(output, " (signer's user ID)")?,
            ReasonForRevocation{code, reason} =>
                writeln!(output, " (revocation reason 0x{:02x} ({}))",
                         u8::from(*code),
                         utils::sanitize_ascii_str(reason, b")"))?,
            Features(f) =>
                writeln!(output, " (features: {:02X})",
                         // XXX: Use as_bytes in the future.
                         (0..8).into_iter()
                         .map(|a| if f.get(a) { 1 << a } else { 0 })
                         .sum::<u8>())?,
            SignatureTarget { .. } =>
                writeln!(output, " (?)")?,
            EmbeddedSignature(s) =>
                writeln!(output, " (signature: v{}, class 0x{:02x}, \
                                  algo {}, digest algo {})",
                         s.version(), u8::from(s.typ()),
                         u8::from(s.pk_algo()), u8::from(s.hash_algo()))?,
            IssuerFingerprint(fp) =>
                writeln!(output, " (issuer fpr v{} {:X})",
                         match fp {
                             Fingerprint::V4(_) => '4',
                             _ => '?',
                         },
                         fp)?,
            PreferredAEADAlgorithms(c) =>
                writeln!(output, "{}    AEAD preferences: {}", i,
                       c.iter().map(|c| format!("{:?}", c))
                       .collect::<Vec<String>>().join(", "))?,
            IntendedRecipient(_) =>
                writeln!(output, " (?)")?,
            AttestedCertifications(_) =>
                writeln!(output, " (?)")?,

            // SubpacketValue is non-exhaustive.
            _ => writeln!(output, " (?)")?,
        }

        Ok(())
    }

    fn dump_s2k(&self,
                output: &mut dyn io::Write,
                cipher: SymmetricAlgorithm,
                aead: Option<AEADAlgorithm>,
                checksum: Option<SecretKeyChecksum>,
                s2k: &S2K)
                -> Result<()> {
        use self::S2K::*;

        let write_parameters = |o: &mut dyn io::Write, hash: &HashAlgorithm, salt| -> Result<()>
        {
            write!(o, ", algo: {}, {}, hash: {}",
                   u8::from(cipher),
                   match checksum {
                       Some(SecretKeyChecksum::SHA1) => "SHA1 protection",
                       Some(SecretKeyChecksum::Sum16) => "simple checksum",
                       None => "no checksum",
                   },
                   u8::from(*hash))?;
            if let Some(s) = salt {
                write!(o, ", salt: {}", openpgp::fmt::hex::encode(s))?;
            }

            // XXX: What to do about AEAD?
            let _ = aead;

            Ok(())
        };

        #[allow(deprecated)]
        match s2k {
            Simple { hash } => {
                write!(output, "\tsimple S2K")?;
                write_parameters(output, hash, None)?;
            },
            Salted { hash, salt } => {
                write!(output, "\tsalted S2K")?;
                write_parameters(output, hash, Some(salt))?;
            },
            Iterated { hash, salt, hash_bytes } => {
                write!(output, "\titer+salt S2K")?;
                write_parameters(output, hash, Some(salt))?;
                write!(output, "\n\tprotect count: {} ({})",
                       hash_bytes,
                       utils::s2k_encode_iteration_count(*hash_bytes)
                       .unwrap_or_default())?;
            },
            Private { .. } => {
                write!(output, "\tunknown")?;
            },
            Unknown { .. } => {
                write!(output, "\tunknown")?;
            },

            // S2K is non-exhaustive
            _ => write!(output, "\tunknown")?,
        }

        writeln!(output)?;
        Ok(())
    }

    fn dump_mpis(&self, output: &mut dyn io::Write,
                 mpis: &[usize], keys: &[&str]) -> Result<usize> {
        let mut count = 0;
        for (mpi, key) in mpis.iter()
            .zip(keys.iter().chain(std::iter::repeat(&"data")))
        {
            writeln!(output, "\t{}: [{} bits]", key, mpi)?;
            count += 1;
        }

        Ok(count)
    }

    fn dump_key<P, R>(&self,
                      output: &mut dyn io::Write,
                      k: &Key<P, R>)
                      -> Result<()>
    where P: key::KeyParts,
          R: key::KeyRole,
    {
        writeln!(output)?;
        writeln!(output,
                 "\tversion {}, algo {}, created {}, expires 0",
                 k.version(),
                 u8::from(k.pk_algo()),
                 Timestamp::try_from(k.creation_time())
                 .map(|t| u32::from(t)).unwrap_or_default())?;

        const NAMES: &[&str] = &[
            "pkey[0]",
            "pkey[1]",
            "pkey[2]",
            "pkey[3]",
            "pkey[4]",
            "pkey[5]",
            "pkey[6]",
            "pkey[7]",
        ];
        let pkeys = match k.mpis() {
            mpi::PublicKey::RSA { e, n } =>
                self.dump_mpis(output,
                               &[n.bits(), e.bits()],
                               NAMES)?,
            mpi::PublicKey::DSA { p, q, g, y } =>
                self.dump_mpis(output,
                               &[p.bits(), q.bits(), g.bits(),
                                 y.bits()],
                               NAMES)?,
            mpi::PublicKey::ElGamal { p, g, y } =>
                self.dump_mpis(output,
                               &[p.bits(), g.bits(), y.bits()],
                               NAMES)?,
            mpi::PublicKey::EdDSA { curve, q } => {
                writeln!(output, "\t{}: [{} bits] {} ({})",
                         NAMES[0], (1 + curve.oid().len()) * 8,
                         babel::Fish(curve), dot_encode(curve.oid()))?;
                1 + self.dump_mpis(output, &[q.bits()], &NAMES[1..])?
            },
            mpi::PublicKey::ECDSA { curve, q } => {
                writeln!(output, "\t{}: [{} bits] {} ({})",
                         NAMES[0], (1 + curve.oid().len()) * 8,
                         babel::Fish(curve), dot_encode(curve.oid()))?;
                1 + self.dump_mpis(output, &[q.bits()], &NAMES[1..])?
            },
            mpi::PublicKey::ECDH { curve, q, .. } => {
                writeln!(output, "\t{}: [{} bits] {} ({})",
                         NAMES[0], (1 + curve.oid().len()) * 8,
                         babel::Fish(curve), dot_encode(curve.oid()))?;
                1 + self.dump_mpis(output, &[q.bits(), 32], &NAMES[1..])?
            },
            mpi::PublicKey::Unknown { mpis, rest } =>
                self.dump_mpis(
                    output,
                    &mpis.iter().map(|m| m.bits())
                        .chain(std::iter::once(rest.len() * 8))
                        .collect::<Vec<_>>(),
                    NAMES)?,

            // crypto::mpi:Publickey is non-exhaustive
            _ => {
                // XXX: Not sure what to do.
                0
            },
        };

        if let Some(secrets) = k.optional_secret() {
            let names = &[
                "skey[0]",
                "skey[1]",
                "skey[2]",
                "skey[3]",
                "skey[4]",
                "skey[5]",
                "skey[6]",
                "skey[7]",
            ][pkeys..];

            match secrets {
                SecretKeyMaterial::Unencrypted(u) => {
                    u.map(|mpis| -> Result<()> {
                        match mpis
                        {
                            mpi::SecretKeyMaterial::RSA { d, p, q, u } =>
                                self.dump_mpis(output,
                                               &[d.bits(), p.bits(),
                                                 q.bits(), u.bits()],
                                               names)?,
                            mpi::SecretKeyMaterial::DSA { x } =>
                                self.dump_mpis(output, &[x.bits()],
                                               names)?,
                            mpi::SecretKeyMaterial::ElGamal { x } =>
                                self.dump_mpis(output, &[x.bits()],
                                               names)?,
                            mpi::SecretKeyMaterial::EdDSA { scalar } =>
                                self.dump_mpis(output,
                                               &[scalar.bits()],
                                               names)?,
                            mpi::SecretKeyMaterial::ECDSA { scalar } =>
                                self.dump_mpis(output,
                                               &[scalar.bits()],
                                               names)?,
                            mpi::SecretKeyMaterial::ECDH { scalar } =>
                                self.dump_mpis(output,
                                               &[scalar.bits()],
                                               names)?,
                            mpi::SecretKeyMaterial::Unknown { mpis, rest } =>
                                self.dump_mpis(
                                    output,
                                    &mpis.iter().map(|m| m.bits())
                                        .chain(std::iter::once(rest.len() * 8))
                                        .collect::<Vec<_>>(),
                                    names)?,

                            // crypto::mpi::SecretKeyMaterial is non-exhaustive.
                            _ => {
                                // XXX: Not sure what to do.
                                0
                            },
                        };

                        let checksum = mpis.to_vec()?.iter()
                            .fold(0u16, |acc, v| acc.wrapping_add(*v as u16))
                            .to_be_bytes();
                        writeln!(output, "\tchecksum: {}",
                                 openpgp::fmt::hex::encode(&checksum)
                                 .to_lowercase())?;

                        Ok(())
                    })?;
                },

                SecretKeyMaterial::Encrypted(e) => {
                    self.dump_s2k(output, e.algo(), None, e.checksum(), e.s2k())?;
                    if let (Ok(c), Ok(bs))
                        = (e.ciphertext(), e.algo().block_size())
                    {
                        write!(output, "\tprotect IV: ")?;
                        for b in c.iter().take(bs) {
                            write!(output, " {:02x}", b)?;
                        }
                        writeln!(output)?;
                    }
                    writeln!(output, "\t{}: [v4 protected]", names[0])?;
                },
            }
        }

        writeln!(output, "\tkeyid: {:X}", k.keyid())?;

        Ok(())
    }
}

fn dot_encode(mut oid: &[u8]) -> String {
    // The first octet encodes two values.
    let first = oid[0] / 40;
    let second = oid[0] % 40;
    oid = &oid[1..];

    // Start building it up.
    let mut s = format!("{}.{}", first, second);

    let mut acc: usize = 0;
    for b in oid {
        if b & 0x80 > 0 {
            acc *= 0x80;
            acc += (b & 0x7f) as usize;
        } else {
            acc *= 0x80;
            acc += (b & 0x7f) as usize;
            s.push_str(&format!(".{}", acc));
            acc = 0;
        }
    }

    s
}
