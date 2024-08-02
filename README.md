# Sequoia's reimplementation of the GnuPG interface

This is a re-implementation and drop-in replacement of `gpg` and
`gpgv` using the Sequoia OpenPGP implementation.

## Try it out, it is safe!

If you are a power user, you can try out the Chameleon today to see if
it covers your use cases.  The Chameleon does not directly modify any
of GnuPG's data structures, so it is safe to try it out with your
existing GnuPG installation and keys.

There are two ways the Chameleon will change your `$GNUPGHOME`:

  - It will create an openpgp-cert-d overlay in
    `$GNUPGHOME/pubring.cert.d` (GnuPG will ignore this), unless you
    are using the default `$GNUPGHOME`, in which case the default
    location for the openpgp-cert-d is used.  This provides seamless
    integration with other tools using the common certificate store,
    such as Sequoia's native [sq] frontend.

  - If you create or import secret keys, the Chameleon will interact
    with `gpg-agent` the same way GnuPG would, and `gpg-agent` will in
    turn modify `$GNUPGHOME`.

[sq]: https://gitlab.com/sequoia-pgp/sequoia-sq

The Chameleon is compatible with the state of and `gpg-agent` from
GnuPG 2.2.x and 2.4.x.  If it discovers state of GnuPG < 2.1.x
(i.e. with `secring.gpg`), it will convert it to 2.2.x state the same
way GnuPG would (i.e. import the secret keys into the `gpg-agent` and
add a flag file).

### Switching to Sequoia's gpg-sq

To use the Chameleon, you need to install it, and then make sure that
it is invoked either directly by you or indirectly by programs instead
of GnuPG.  There are three ways to do that.

#### Direct invocation

If you only interact with GnuPG via the command line, then invoking
`gpg-sq` instead of `gpg` is enough to use the Chameleon instead of
g10code's GnuPG.

#### Replace /bin/gpg

To globally replace g10code's `gpg` with the Chameleon, install it as
`/bin/gpg` (or `/usr/bin/gpg`, or wherever `gpg` is installed on your
system; hint: try `type gpg` in your shell) replacing g10code's `gpg`,
for example using `dpkg-divert` or a similar mechanism.  This is more
convenient and robust than invoking it using `gpg-sq`, but has the
downside of being a system-wide all-or-nothing switch.

#### Take precedence using PATH

If the Chameleon can be found under the name `gpg` in your `$PATH`
before g10code's `gpg` is found, it takes precedence.  This has the
advantage of being more convenient and robust than invoking it using
`gpg-sq`, while allowing a more fine-grained replacement method (for
example per-shell if the `$PATH` is manipulated on a per-shell basis,
or per-user if that is done in the shell's startup files).

If you go down this route, you also need to make sure that `gpgconf`
points to the Chameleon, because many programs invoke `gpgconf` to
find the location of `gpg`, notably those that use GPGME.  To that
end, we have a shim that can be used from the build directory (if you
want to install the Chameleon, or your cargo target directory is
different, you need to adapt it accordingly):

```sh
$ export PATH=$(pwd)/shim-release:$PATH
$ gpg --version | head -n1
gpg (GnuPG-compatible Sequoia Chameleon) 2.2.40
$ gpgconf | head -n1
gpg:OpenPGP:.../sequoia-chameleon-gnupg/shim-release/gpg
```

### Switching back to g10code's gpg

You can at any point switch back to using g10code's gpg by undoing the
replacement method discussed in the previous section.

However, a consequence of not modifying GnuPG's state but using an
overlay is that changes made using the Chameleon will not be picked up
by GnuPG.  Therefore, you need to sync all the changes you made using
the Chameleon back to g10code's GnuPG.

For example, if you import a certificate using the Chameleon, it will
only be inserted into the overlay, and g10code's GnuPG will not see
it.  This is also true if you generate a key using the Chameleon:
while the secret bits will be known to the `gpg-agent`, the public
certificate will not.  Similarly, if you modify the trust database,
the changes will only be written to our overlay.

To sync the changes to the certificate store and trust database back,
export changes from the Chameleon and import them into g10code's
GnuPG:

```sh
$ gpg-sq --export | gpg-g10code --import
$ gpg-sq --export-ownertrust | gpg-g10code --import-ownertrust
```

If you are using the Chameleon and GnuPG side-by-side, it is
recommended to either do state changing actions using GnuPG, or sync
the changes, either manually or periodically in a cron job.

## How to build the Chameleon

First, you need to install Sequoia's [build dependencies], as well as
the SQLite3 library.  Then build the Chameleon from a checkout of this
repository:

```sh
$ git clone https://gitlab.com/sequoia-pgp/sequoia-chameleon-gnupg.git
$ cd sequoia-chameleon-gnupg
$ cargo build --release
[...]
```

  [build dependencies]: https://gitlab.com/sequoia-pgp/sequoia#requirements-and-msrv

Alternatively, you can change the cryptographic library that is used.
Note that this will change the [build dependencies].  Currently,
`crypto-openssl` and `crypto-cng` are supported, which select OpenSSL
and Windows CNG, respectively.  To select a different backend, disable
the default features and activate the corresponding feature:

```sh
$ git clone https://gitlab.com/sequoia-pgp/sequoia-chameleon-gnupg.git
$ cd sequoia-chameleon-gnupg
$ cargo build --release --no-default-features --features=crypto-openssl
[...]
```

#### Running the tests

To run the tests, you also need Sequoia's command-line frontend `sq`.
Then, you can run the tests using `cargo`:

```sh
$ cargo test
```

### How to trace invocations of the Chameleon

If you have a program that uses GnuPG, and you want to see whether it
works with the Chameleon, a good way to do that is to run the test
suite (or if there is none, just use the program as usual) with a
debug build of the Chameleon, and enable the invocation log.  The log
will log every invocation of the Chameleon with all the arguments
given, and whether an error occurred or not.

```sh
$ cargo build
[...]
$ export PATH=$(pwd)/shim-debug:$PATH
$ # WARNING: this only works with a debug build!
$ export SEQUOIA_GPG_CHAMELEON_LOG_INVOCATIONS=/tmp/invocation.log
$ # Run your test suite here.  This is an example:
$ (gpg --version ; gpg --lsign-key) >/dev/null 2>&1
$ cat $SEQUOIA_GPG_CHAMELEON_LOG_INVOCATIONS
814360: "gpg" "--version"
814360: success
814359: "gpg" "--lsign-key"
814359:            Command aLSignKey is not implemented.
```

# Status

## gpgv-sq

`gpgv-sq` is feature-complete.  Please report any problems you
encounter when replacing `gpgv` with `gpgv-sq`.  `gpgv-sq` is
stateless, you can switch to it by invoking `gpgv-sq` instead of
`gpgv`, and switch between the implementations without further
considerations.

## gpg-sq

`gpg-sq` is not feature-complete.  It currently implements a growing
subset of commonly used commands and options.  Most of the signature
creation and verification commands, the encryption and decryption
commands, the key listing commands, and some miscellaneous commands
are implemented.

Currently, we rely on GnuPG's `gpg-agent` to handle secret key
operations.  This is very convenient for users who are already using
GnuPG, but it means that you have to have `gpg-agent` installed.
Further, we don't have our own implementation of `gpgconf`, and we
rely on it to start the `gpg-agent` and downstream users, such as
GPGME, also require `gpgconf` to function.

### Trust Models

The Chameleon implements a subset of the trust models implemented by
GnuPG, and some specific to Sequoia.  The following table shows how
the Chameleon and GnuPG interpret different values given to the
"--trust-model" parameter.

| Name            | Chameleon     | GnuPG      |
|-----------------|---------------|------------|
| `auto`          | Auto          | Auto       |
| `sequoia`       | Sequoia       | ✗          |
| `sequoia+gnupg` | Sequoia+Gnupg | ✗          |
| `pgp`           | Sequoia+GnuPG | GnuPG      |
| `gnupg`         | GnuPG         | ✗          |
| `tofu`          | ✗             | Tofu       |
| `tofu+pgp`      | Sequoia+Gnupg | Tofu+GnuPG |
| `classic`       | Sequoia+Gnupg | Classic    |
| `direct`        | ✗             | Direct     |
| `external`      | ✗             | External   |

The trust models are described below.

#### Auto

The trust model is read from the trust database.  If there is no trust
database, defaults to `pgp`.

#### Sequoia

This is how Sequoia manages the trust roots.  Under Sequoia's trust
model, only the `trust-root` from the certificate directory is used as
trust root.  Trust is managed using the `sq pki` commands.

This model combines well with GnuPG's native trust model.  This is
implemented in the `sequoia+gnupg` trust model, which is the default.
However, if you are comfortable with using `sq pki` to manage trust,
you can explicitly select the `sequoia` trust model to deactivate the
`gnupg` trust model, which is a little bit cheaper, and is easier to
reason about.

#### Sequoia+GnuPG

Combines the Sequoia trust model and the GnuPG trust model.

#### GnuPG

GnuPG uses the owner trust databases to select trust roots. In
addition to ultimately trusted certs, also fully and marginally
trusted certs are used as trust roots **if** they can be
authenticated.  This is the trust model used in PGP6.

Currently, we don't honor the constraint on the lengths of
certification chains (parameter `--max-cert-depth`), but this will be
implemented at some point.

#### Tofu

Trust-On-First-Use provides asymptotic trust, i.e. as the time goes
on, and the observed binding between user IDs and certificates doesn't
change, trust into the binding increases.

#### Tofu+PGP

Combines the Tofu trust model with the GnuPG trust model.

#### Classic

Like the GnuPG trust model, but disregards trust delegations via trust
signatures.  This is the trust model of PGP2.

#### Direct

Uses owner trust values to validate authenticity of user IDs on
certificates.

#### External

Uses the trust database, but refrains from modifying it.  This is left
to an external program.

### Known deliberate divergences

Some features of g10code's GnuPG are deliberately not implemented to
improve security, or to reduce complexity in the reimplementation.

This is a non-exhaustive list.  If you note a divergence that is not
listed here, please open an issue, so that we can either align with
GnuPG's behavior, or add the divergence to this list.

Conversely, if you take issue with a divergence listed here, and have
good arguments not mentioned here that support aligning with GnuPG on
that aspect, please also open an issue.

#### Weak algorithms are rejected

We reject more weak algorithms than GnuPG by default, notably SHA-1
(see also [this section](#sha-1-mitigations)).

#### Short key IDs are not supported

Short key IDs, aka 32-bit key IDs, are not supported.  Creating keys
with colliding short key IDs is trivial, so using them to refer to
keys is insecure.  See https://evil32.com .

When a short key ID is used in an command line argument or
configuration file, an error is printed and the operation fails.

#### We don't use dirmngr

We don't use GnuPG's `dirmngr` to connect to network services to
discover certificates.  Instead, we read its configuration file and do
the requests ourselves.  This is more robust and offers more features,
for example, if you have more than one `keyserver` directive in
`dirmngr.conf`, we will query all keyservers simultaneously.

#### We don't use keyboxd

We don't use GnuPG's `keyboxd` to access keybox databases.  Instead,
we read the certificates directly from the keybox database if we
discover one.

#### We reject --use-embedded-filename

This flag is insecure and may overwrite arbitrary files with
attacker-controlled content on decryption.  We reject the flag by
making the invocation fail.  Do not use this flag.

#### No translation, no localization beyond date and time formats

GnuPG translates all messages and error messages, and even some
command-line arguments (`LANGUAGE=de gpg --compression-algo
unkomprimiert`...).  We may translate strings in the future, but will
never do locale-dependent argument parsing.

#### Algorithms may be specified by OID in GnuPG

Algorithms may be only be specified using their OpenPGP algorithm IDs
and the symbolic identifiers as used by GnuPG.  If you absolutely need
this, please open an issue.

# Non-Functional Advantages

The Chameleon has a number of non-functional advantages relative to
GnuPG.

## Automatic discovery of certificate updates

The Chameleon includes a component called Parcimonie (after the
venerable [Parcimonie](https://salsa.debian.org/intrigeri/parcimonie))
that will keep your certificates up-to-date, trying to do so in a
privacy preserving fashion.

It will periodically use any enabled auto-key-locate methods to search
for updates in the local certificate store using randomized delays
trying to de-correlate them.  It will use Tor if available.

To enable the Parcimonie component, run `gpg-sq
--x-sequoia-parcimonie`, either manually or using a service manager (a
systemd unit file with the name `gpg-sq-parcimonie.service` is
included in this repository).  Alternatively, you can use the
`x-sequoia-autostart-parcimonie` option in your configuration file to
start it on-demand if `gpg-sq` is invoked.

## OpenPGP Conformance

Sequoia implements [nearly all] of the OpenPGP RFC4880.  The missing
bits are either obsolete or insecure.  Furthermore, we engage with the
[IETF OpenPGP working group], and wrote an extensive [OpenPGP
Interoperability Test Suite] to improve interoperability between
various implementations.  In short, if you use Sequoia to encrypt your
data, you can be sure that you can decrypt it with any other OpenPGP
implementation.

   [nearly all]: https://sequoia-pgp.org/status/
   [IETF OpenPGP working group]: https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/
   [OpenPGP Interoperability Test Suite]: https://tests.sequoia-pgp.org/

## No more waiting for Trust Database checks

The Chameleon uses a very fast implementation of the [Web-of-Trust],
and we calculate the trust on the fly without relying on a cache like
GnuPG.  That means that `gpg --check-trustdb` is a no-operation for
the Chameleon, whereas GnuPG is known to take [a long time].

  [Web-of-Trust]: https://crates.io/crates/sequoia-wot
  [a long time]: https://lists.gnupg.org/pipermail/gnupg-users/2017-February/057650.html

## SHA-1 Mitigations

[SHA-1 is broken].  Unfortunately, [SHA-1 is still widely used].  To
deal with this Sequoia implements a number of countermeasures:

  - Sequoia uses [SHA1-CD], a variant of SHA-1 that detects and
    mitigates collision attacks.  This protection is also used by
    [GitHub], among others.

  - Sequoia rejects all signatures using SHA-1 by default.

  [SHA-1 is broken]: https://sha-mbles.github.io/
  [SHA-1 is still widely used]: https://gitlab.com/sequoia-pgp/sequoia/-/issues/595
  [SHA1-CD]: https://github.com/cr-marcstevens/sha1collisiondetection
  [GitHub]: https://github.blog/2017-03-20-sha-1-collision-detection-on-github-com/

On the other hand, GnuPG [accepts] SHA-1 everywhere without any
additional protections.

  [accepts]: https://tests.sequoia-pgp.org/#Signature_over_the_shattered_collision

## Collision Protection

Sequoia includes a salt in signatures and self-signatures to defend
against collision attacks, among others.  [OpenSSH does the same
thing].  Should the collision resistance of another hash be broken,
this will frustrate attackers trying to perform a Shambles-style
attack.

  [OpenSSH does the same thing]: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys#L151

## Multi-threading

Thanks to Rust's [safer concurrency paradigms], it is less dangerous
and less complicated for the Chameleon to use threads than
implementations written in other languages.  The Chameleon uses this,
for instance, to [parse keyrings faster].

  [safer concurrency paradigms]: https://doc.rust-lang.org/book/ch16-00-concurrency.html
  [parse keyrings faster]: https://crates.io/crates/sequoia-openpgp-mt

# Testing methodology

There are two ways we test the Chameleon: we run the Chameleon and
GnuPG side-by-side and compare the results, and we use test suites of
programs that use GnuPG.

## Using GnuPG as Test Oracle

We run experiments that invoke the Chameleon and record human-readable
and machine-readable output and side-effects, and compare that to what
GnuPG emits.  These tests are run when you invoke `cargo test`, and
hence need GnuPG to be installed.

## Downstream Test Suites

We use test suites of programs that directly or indirectly use GnuPG
to verify that we support the required functionality.

A reoccurring problem when running these test suites is that they may
include cryptographic artifacts such as OpenPGP certificates, keys,
signatures, and messages.  Those are rarely updated, and hence are
stuck in time using old packet formats or insecure algorithms.

If you are maintaining a software package that includes cryptographic
artifacts in the test suite, please help by regularly updating the
artifacts.  Further, try to reduce the amount of checked-in artifacts
in the first place.  Where possible, try to generate the required
artifacts in the test.

- notmuch: passes (patches applied: https://nmbug.notmuchmail.org/nmweb/show/20220909161250.715226-1-justus%40sequoia-pgp.org)
- emacs: passes (patches applied: https://lists.gnu.org/archive/html/bug-gnu-emacs/2022-10/msg00443.html)
- pass: passes (patches applied: https://lists.zx2c4.com/pipermail/password-store/2022-September/004647.html)

## Bugs discovered in the process

- gpg(v) prints the human-readable form of notations to the status-fd,
  https://dev.gnupg.org/T5667, fixed
- When encrypting, gpg claims DE_VS compliance with non-compliant
  gcrypt, https://dev.gnupg.org/T6221, fixed
- gpg --faked-system-time "$(date +%s)!" doesn't work,
  https://dev.gnupg.org/T6222, wont-fix
- GPGME incorrectly parses the signature class in SIG_CREATED status
  lines, https://dev.gnupg.org/T6223

# License

Sequoia GnuPG Chameleon is free software: you can redistribute it
and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.  See
[`LICENSE.txt`](LICENSE.txt).

Sequoia GnuPG Chameleon is a derived work of GnuPG.  It is not a
clean-room reimplementation, and it does include parts of GnuPG either
literally, or transcribed to Rust.  Therefore, parties who claim
copyright to GnuPG also have a claim on parts of the Chameleon.  See
[`AUTHORS.GnuPG`](AUTHORS.GnuPG) for a list.
