//! Implements `--assert-pubkey-algo`.
//!
//! GnuPG 2.4.5 introduced a command-line option
//! `--assert-pubkey-algo` that can be used to specify a policy to
//! evaluate data signatures.
//!
//! When data signatures are verified, a status message is emitted
//! containing the result of the evaluation.  If a signature fails to
//! pass a policy, the program is guaranteed to return a non-zero exit
//! status.

use std::{
    fmt,
    str::FromStr,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    packet::{Key, key},
    types::{Curve, PublicKeyAlgorithm},
};

use crate::{
    babel,
    common::{
        BRAINPOOL_P384_OID,
        Common,
        PublicKeyAlgorithmAndSize
    },
    status::Status,
};

/// A policy is a collection of rules.
#[derive(Debug, Default)]
pub struct Policy {
    rules: Vec<Rule>,
}

impl Policy {
    /// Parses the rules given in `s` and adds them to the policy.
    pub fn handle_cmdline_arg(&mut self, s: &str) -> Result<()> {
        for r in s.split(',').map(str::trim).filter(|s| ! s.is_empty()) {
            self.rules.push(
                r.parse().with_context(
                    || format!("While parsing rule {:?}", r))?);
        }
        Ok(())
    }

    /// Given a public key algorithm, return whether it matches the policy.
    ///
    /// The algorithm matches the policy if it matches any of its rules.
    pub fn check<P, R>(&self, config: &dyn Common, key: &Key<P, R>) -> Result<()>
    where
        P: key::KeyParts,
        R: key::KeyRole,
    {
        if self.rules.is_empty() {
            return Ok(());
        }

        let algo = if let Some(c) = crate::common::get_curve(key.mpis()) {
            PublicKeyAlgorithmAndSize::Ecc(c)
        } else {
            PublicKeyAlgorithmAndSize::VariableLength(
                key.pk_algo(), key.mpis().bits().unwrap_or(0))
        };

        let accepted = self.check_intern(&algo);

        config.status().emit(Status::AssertPubkeyAlgo {
            fp: key.fingerprint(),
            accepted,
            policy: {
                self.rules.iter().map(ToString::to_string).collect::<Vec<_>>()
                    .join(",")
            },
        })?;

        if ! accepted {
            config.fail(); // Fail later...
        }

        Ok(())
    }

    // Entry point used by the unit test.
    fn check_intern(&self, algo: &PublicKeyAlgorithmAndSize) -> bool {
        self.rules.iter().any(|r| r.check(algo))
    }
}

/// A rule is a constraint and a reference algorithm.
#[derive(Debug)]
pub struct Rule {
    constraint: Constraint,
    reference: PublicKeyAlgorithmAndSize,
}

impl Rule {
    /// Given a public key algorithm, return whether it matches this
    /// rule.
    pub fn check(&self, algo: &PublicKeyAlgorithmAndSize) -> bool {
        use PublicKeyAlgorithmAndSize::*;
        match (algo, &self.reference) {
            (VariableLength(a, n), VariableLength(b, m)) if a == b =>
                self.constraint.check(*n, *m),

            (FixedLength(a), FixedLength(b)) =>
                a == b && self.constraint.eq_is_ok(),

            (Ecc(Curve::Ed25519), Ecc(Curve::Ed25519)) =>
                self.constraint.eq_is_ok(),

            (Ecc(Curve::Cv25519), Ecc(Curve::Cv25519)) =>
                self.constraint.eq_is_ok(),

            (Ecc(a), Ecc(b)) if matches!(a, Curve::NistP256
                                         | Curve::NistP384
                                         | Curve::NistP521)
                && matches!(b, Curve::NistP256
                            | Curve::NistP384
                            | Curve::NistP521) =>
                self.constraint.check(a.bits().unwrap_or(0),
                                      b.bits().unwrap_or(0)),

            (Ecc(a), Ecc(b)) if (matches!(a, Curve::BrainpoolP256
                                          | Curve::BrainpoolP512)
                                 || matches!(a,
                                             Curve::Unknown(oid) if oid.as_ref() == BRAINPOOL_P384_OID))
                && (matches!(b, Curve::BrainpoolP256
                             | Curve::BrainpoolP512)
                    || matches!(&b,
                                Curve::Unknown(oid) if oid.as_ref() == BRAINPOOL_P384_OID)) =>
                self.constraint.check(a.bits().unwrap_or(0),
                                      b.bits().unwrap_or(0)),

            _ => false,
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.constraint, babel::Fish(&self.reference))
    }
}

impl FromStr for Rule {
    type Err = anyhow::Error;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        // Trim leading spaces and commas.
        while s.chars().next().map(|c| c.is_whitespace() || c == ',')
            .unwrap_or(false)
        {
            s = &s[1..];
        }

        // Parse the policy.
        use Constraint::*;
        let (s, constraint) = if s.starts_with("<=") {
            (&s[2..], LesserOrEqual)
        } else if s.starts_with("<") {
            (&s[1..], Lesser)
        } else if s.starts_with(">=") {
            (&s[2..], GreaterOrEqual)
        } else if s.starts_with(">") {
            (&s[1..], Greater)
        } else if s.starts_with("=") {
            (&s[1..], Equal)
        } else {
            // The default.
            (s, Equal)
        };

        if let Ok(curve) = babel::Fish::<Curve>::from_str(s.trim()) {
            Ok(Rule {
                constraint,
                reference: PublicKeyAlgorithmAndSize::Ecc(curve.0),
            })
        } else {
            // Parse the algorithm name.
            let name: String =
                s.chars().take_while(|c| c.is_alphabetic()).collect();
            let algo: babel::Fish::<PublicKeyAlgorithm> = name.parse()?;

            // Parse the key length.  GnuPG ignores anything after the
            // number, but we are stricter.
            let length: usize = {
                let s = s[name.len()..].chars()
                    .skip_while(|&c| c == '+' || c == '-') // GnuPG skips those.
                    .collect::<String>();
                s.parse()?
            };

            Ok(Rule {
                constraint,
                reference: PublicKeyAlgorithmAndSize::VariableLength(
                    algo.0, length),
            })
        }
    }
}

/// An operator to compare a signatures algorithm against the
/// reference algorithm.
#[derive(Debug)]
pub enum Constraint {
    Lesser,
    LesserOrEqual,
    Equal,
    GreaterOrEqual,
    Greater,
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Constraint::*;
        match self {
            Lesser => f.write_str("<"),
            LesserOrEqual => f.write_str("<="),
            Equal => f.write_str("="),
            GreaterOrEqual => f.write_str(">="),
            Greater => f.write_str(">"),
        }
    }
}

impl Constraint {
    /// Returns `a OP b` where `OP` is the operator denoted by `self`.
    fn check(&self, a: usize, b: usize) -> bool {
        use Constraint::*;
        match self {
            Lesser => a < b,
            LesserOrEqual => a <= b,
            Equal => a == b,
            GreaterOrEqual => a >= b,
            Greater => a > b,
        }
    }

    /// Returns `a OP b` where `OP` is the operator denoted by `self`
    /// given that `a == b`.
    fn eq_is_ok(&self) -> bool {
        use Constraint::*;
        matches!(self, LesserOrEqual | Equal | GreaterOrEqual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors from g10/t-keyid.c.
    #[test]
    fn compare_pubkey_string() {
        const T: &[(&'static str, &'static str, bool)] = &[
            ("rsa2048", "rsa2048", true),
            ("rsa2048", ">=rsa2048", true),
            ("rsa2048", ">rsa2048", false),
            ("ed25519", ">rsa1024", false),
            ("ed25519", "ed25519", true),
            ("ed25519", ",,,=ed25519", true),
            ("nistp384", ">nistp256", true),
            ("nistp521", ">=rsa3072, >nistp384", true),
            (" nistp521", ">=rsa3072, >nistp384   ", true),
            ("  nistp521  ", "  >=rsa3072, >nistp384   ", true),
            ("  =nistp521  ", "  >=rsa3072, >nistp384,,", true),
            ("nistp384", ">nistp384", false),
            ("nistp384", ">=nistp384", true),
            ("brainpoolP384", ">=brainpoolp256", true),
            ("brainpoolP384", ">brainpoolp384", false),
            ("brainpoolP384", ">=brainpoolp384", true),
            ("brainpoolP256r1", ">brainpoolp256r1", false),
            ("brainpoolP384r1", ">brainpoolp384r1", false),
            ("brainpoolP384r1", ">=brainpoolp384r1", true),
            ("brainpoolP384r1", ">=brainpoolp384", true),
        ];

        for (a, b, expectation) in T {
            let mut a_ = Policy::default();
            a_.handle_cmdline_arg(a).unwrap();
            let a = a_.rules.into_iter().next().unwrap().reference;
            let mut p = Policy::default();
            p.handle_cmdline_arg(b).unwrap();
            let r = p.check_intern(&a);
            assert_eq!(r, *expectation,
                       "doesn't match expectation on ({:?}, {:?}, {:?})",
                       a, b, expectation);
        }
    }
}
