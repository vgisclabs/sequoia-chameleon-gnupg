//! A re-implementation of GnuPG's command-line parser.

use std::{
    io::{self, BufRead, BufReader},
    path::Path,
};

pub mod flags;
use flags::*;
pub mod utils;

/// A command or option with long option, flags, and description.
pub struct Opt<T> {
    pub short_opt: T,
    pub long_opt: &'static str,
    pub flags: u32,
    pub description: &'static str,
}

pub enum Argument<T> {
    Option(T, Value),
    Positional(String),
}

/// Some arguments take a value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value {
    Int(i64),
    String(String),
    UInt(u64),
    None,
}

impl Value {
    // Returns the integer value, if applicable.
    pub fn as_int(&self) -> Option<i64> {
        if let Value::Int(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    // Returns the string value, if applicable.
    pub fn as_str(&self) -> Option<&str> {
        if let Value::String(v) = self {
            Some(v)
        } else {
            None
        }
    }

    // Returns the unsigned integer value, if applicable.
    pub fn as_uint(&self) -> Option<u64> {
        if let Value::UInt(v) = self {
            Some(*v)
        } else {
            None
        }
    }
}

/// Arguments can be read from the command line or a file.
pub struct Parser<T: Copy + PartialEq + Eq + Into<isize> + 'static> {
    name: &'static str,
    synopsis: &'static str,
    options: &'static [Opt<T>],
}

impl<T: Copy + PartialEq + Eq + Into<isize> + 'static> Parser<T> {
    /// Creates a new parser for the given options.
    pub fn new(name: &'static str,
               synopsis: &'static str,
               options: &'static [Opt<T>]) -> Parser<T> {
        Parser {
            name,
            synopsis,
            options,
        }
    }

    /// Parses the command-line arguments.
    pub fn parse_command_line(&self) -> Iter<T>
    {
        let mut args = std::env::args();
        args.next(); // swallow argv[0]

        self.parse(
            true,
            Box::new(std::iter::once(
                Box::new(args.map(|arg| arg.to_string()))
                    as Box<dyn Iterator<Item = _>>)))
    }

    /// Tries to parse the given file.
    ///
    /// If the file does not exist, an empty iterator is returned.
    pub fn try_parse_file<P>(&self, path: P)
                             -> io::Result<Box<dyn Iterator<Item = Result<Argument<T>>>>>
    where
        P: AsRef<Path>,
    {
        match std::fs::File::open(path) {
            Ok(f) => {
                let args = Box::new(
                    BufReader::new(f)
                        .lines()
                        .filter_map(|rl| rl.ok())
                    // Trim whitespace.
                        .map(|l| l.trim().to_string())
                    // Ignore comments.
                        .filter(|l| ! l.starts_with('#'))
                    // Ignore empty lines.
                        .filter(|l| ! l.is_empty())
                    // Split into argument and value, taking care
                    // of quoting.
                        .map(|l| -> Box<dyn Iterator<Item = String>> {
                            Box::new(l.splitn(2, |c: char| c.is_ascii_whitespace())
                                     .map(|w| if w.starts_with('"') && w.ends_with('"') {
                                         w[1..w.len()-1].into()
                                     } else {
                                         w.into()
                                     })
                                     .collect::<Vec<_>>()
                                     .into_iter())
                        }));
                Ok(Box::new(self.parse(false, args)))
            },
            Err(e) => if e.kind() == io::ErrorKind::NotFound {
                Ok(Box::new(std::iter::empty()))
            } else {
                Err(e)
            }
        }
    }

    /// Parses the arguments.
    fn parse(&self,
             cmdline: bool,
             args: Box<dyn Iterator<Item = Box<dyn Iterator<Item = String>>>>)
             -> Iter<T>
    {
        Iter {
            options: self.options,
            line: args,
            current: None,
            current_short: None,
            cmdline,
            seen_positional: false,
            quiet: false,
        }
    }

    /// Displays version information.
    pub fn version(&self) {
        println!("{} (GnuPG-compatible Sequoia Chameleon) {}",
                 self.name, env!("CARGO_PKG_VERSION"));
        println!("sequoia-openpgp {}", sequoia_openpgp::VERSION);
        println!("Copyright (C) 2021 p≡p foundation");
        println!("License GNU GPL-3.0-or-later \
                  <https://gnu.org/licenses/gpl.html>");
        println!("This is free software: \
                  you are free to change and redistribute it.");
        println!("There is NO WARRANTY, \
                  to the extent permitted by law.");
    }

    /// Displays help.
    pub fn help(&self) {
        self.version();
        println!();
        println!("Syntax: {} [options] [files]", self.name);
        println!("{}", self.synopsis);
        println!();

        for o in self.options {
            if o.description == "@" {
                // Hidden from the help.
                continue;
            }

            if o.description == "@\n" {
                // Empty line.
                println!();
            } else if o.description.starts_with("@") {
                // Caption.
                println!("{}", &o.description[1..]);
            } else {
                let (meta, description) =
                    if o.description.starts_with("|") {
                        let mut f = o.description.split('|');
                        f.next();
                        (Some(f.next().unwrap()), f.next().unwrap())
                    } else {
                        (None, o.description)
                    };

                if o.long_opt.is_empty() {
                    let short_opt = if let Some(m) = meta {
                        format!("{} {}", o.short_opt.into() as u8 as char, m)
                    } else {
                        format!("{}", o.short_opt.into() as u8 as char)
                    };

                    println!(" -{:<26} {}",
                             short_opt,
                             description);
                } else {
                    let long_opt = if let Some(m) = meta {
                        format!("{} {}", o.long_opt, m)
                    } else {
                        o.long_opt.to_string()
                    };

                    if o.short_opt.into() <= 0x7f {
                        println!(" -{}, --{:<21} {}",
                                 o.short_opt.into() as u8 as char,
                                 long_opt,
                                 description);
                    } else {
                        println!("     --{:<21} {}",
                                 long_opt,
                                 description);
                    }
                }
            }
        }

        println!("Please report bugs to \
                  <https://gitlab.com/sequoia-pgp/sequoia-chameleon-gnupg>");
    }

    /// Displays a message about warranty, or the lack there of.
    pub fn warranty(&self) {
        println!("\
            This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.");
    }

    /// Displays all options.
    pub fn dump_options(&self) {
        for o in self.options {
            if ! o.long_opt.is_empty() {
                println!("--{}", o.long_opt);
            }
        }
    }

    /// Displays all options in tabular form.
    pub fn dump_options_table(&self) {
        for o in self.options {
            if ! o.long_opt.is_empty() {
                println!("{}:{}:{}:{}:",
                         o.long_opt, o.short_opt.into(), o.flags, o.description);
            }
        }
    }
}

/// Iterator over the command line arguments.
pub struct Iter<T: Copy + PartialEq + Eq + Into<isize> + 'static> {
    options: &'static [Opt<T>],
    line: Box<dyn Iterator<Item = Box<dyn Iterator<Item = String>>>>,
    current: Option<Box<dyn Iterator<Item = String>>>,
    current_short: Option<String>,
    cmdline: bool,
    seen_positional: bool,

    // Whether to emit warnings on stderr.
    quiet: bool,
}

impl<T: Copy + PartialEq + Eq + Into<isize> + 'static> Iter<T> {
    /// Don't emit warnings on stderr.
    pub fn quietly(mut self) -> Self {
        self.quiet = true;
        self
    }

    fn maybe_get_value(&mut self, opt: &Opt<T>) -> Result<Argument<T>> {
        let typ = flags_type(opt.flags);
        if typ == TYPE_NONE {
            return Ok(Argument::Option(opt.short_opt, Value::None));
        }

        let value = match self.current_short.take()
            .or_else(|| self.current.as_mut().and_then(|i| i.next()))
        {
            Some(v) => v,
            None if opt.flags & OPT_OPTIONAL > 0 =>
                return Ok(Argument::Option(opt.short_opt, Value::None)),
            None =>
                return Err(Error::Missing(opt.long_opt.into())),
        };

        // Handle OPT_PREFIX.
        let (value, radix) = if opt.flags & OPT_PREFIX > 0
            && (value.starts_with("0x") || value.starts_with("0X"))
        {
            (&value[2..], 16)
        } else {
            (&value[..], 10)
        };

        match typ {
            TYPE_NONE => unreachable!("handled above"),
            TYPE_INT | TYPE_LONG => match i64::from_str_radix(value, radix) {
                Ok(v) => Ok(Argument::Option(opt.short_opt, Value::Int(v))),
                Err(_) => Err(Error::BadValue(opt.long_opt.into(),
                                              "integer",
                                              value.into())),
            },
            TYPE_ULONG => match u64::from_str_radix(value, radix) {
                Ok(v) => Ok(Argument::Option(opt.short_opt, Value::UInt(v))),
                Err(_) => Err(Error::BadValue(opt.long_opt.into(),
                                              "unsigned integer",
                                              value.into())),
            },
            TYPE_STRING =>
                Ok(Argument::Option(opt.short_opt, Value::String(value.into()))),
            n => unreachable!("bad type {}", n),
        }
    }
}

impl<T: Copy + PartialEq + Eq + Into<isize> + 'static> Iterator for Iter<T> {
    type Item = Result<Argument<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Handle leftover short options.
        if let Some(rest) = self.current_short.take() {
            let mut chars = rest.chars();
            let a0 = match chars.next() {
                Some(c) => c,
                None => unreachable!("current_short is not empty"),
            };

            // See if there are more short arguments after this one.
            let rest = chars.collect::<String>();
            self.current_short =
                if rest.is_empty() { None } else { Some(rest) };

            let matches = self.options.iter()
                .filter(|o| o.short_opt.into() == a0 as isize)
                .collect::<Vec<_>>();

            let m = match matches.len() {
                0 => return Some(Err(Error::Unkown(a0.into()))),
                _ => matches[0],
            };

            return Some(self.maybe_get_value(m));
        }

        // Once we saw a positional argument, all remaining arguments
        // are positional.
        if self.seen_positional {
            assert!(self.cmdline);
            if let Some(c) = self.current.as_mut() {
                if let Some(arg) = c.next() {
                    if arg != "-" && arg.starts_with('-') && ! self.quiet {
                        eprintln!("gpg: Note: {:?} is not considered an option",
                                  arg);
                    }
                    return Some(Ok(Argument::Positional(arg)));
                } else {
                    // We're done.
                    return None;
                }
            } else {
                // We're done.
                return None;
            }
        }

        if self.current.is_none() {
            self.current = self.line.next();
        }

        if self.current.is_none() {
            // Exhausted top-level iterator, we're done.
            return None;
        }

        let mut current = self.current.take().unwrap();
        let arg = match current.next() {
            Some(a) => {
                self.current = Some(current);
                a
            },
            None => {
                // Exhausted iterator, see if there is a next line.
                return self.next();
            },
        };

        let (long, mut a) = if self.cmdline {
            if ! arg.starts_with("-") {
                // A positional argument.
                self.seen_positional = true;
                return Some(Ok(Argument::Positional(arg.into())));
            }

            if arg.starts_with("--") {
                // Long option.
                (true, &arg[2..])
            } else {
                // Short option.
                (false, &arg[1..])
            }
        } else {
            // Config file.  All options are long options.
            (true, &arg[..])
        };

        let m = if long {
            // See if we have a value in this argument.
            let mut split = a.splitn(2, "=");
            a = split.next().unwrap();
            let value = split.next();

            let matches = self.options.iter().filter(|o| o.long_opt.starts_with(a))
                .collect::<Vec<_>>();

            let matched = match matches.len() {
                0 => return Some(Err(Error::Unkown(a.into()))),
                1 => matches[0],
                n => {
                    // See if there is an *exact* match.
                    let exact = self.options.iter().filter(|o| o.long_opt == a)
                        .collect::<Vec<_>>();

                    // See if all matches refer to the same CmdOrOpt.
                    if matches.iter()
                        .all(|m| m.short_opt == matches[0].short_opt)
                    {
                        matches[0]
                    } else if ! exact.is_empty() {
                        exact[0]
                    } else {
                        let mut also = String::new();
                        for (i, c) in matches.iter().enumerate() {
                            match i {
                                0 => (),
                                x if x == n - 1 => also.push_str(", and "),
                                _ => also.push_str(", "),
                            }

                            also.push_str("--");
                            also.push_str(c.long_opt);
                        }
                        return Some(Err(Error::Ambiguous(a.into(), also)))
                    }
                },
            };

            if let Some(value) = value {
                if flags_type(matched.flags) != TYPE_NONE {
                    // This long argument takes a value.  If we have a
                    // value from this very argument (--foo=value), stash
                    // that into `current_short` for `maybe_get_value` to
                    // find.
                    self.current_short = Some(value.into());
                } else {
                    // This argument does not take a value, but the GnuPG
                    // argument parser silently ignores that.
                    if ! self.quiet {
                        eprintln!("gpg: Note: Ignoring value {:?} \
                                   for option \"--{}\"",
                                  value, a);
                    }
                }
            }

            matched
        } else {
            let mut chars = a.chars();
            let a0 = match chars.next() {
                Some(c) => c,
                None => return Some(Err(Error::Malformed(a.into()))),
            };

            // See if there are more short arguments after this one.
            let rest = chars.collect::<String>();
            self.current_short =
                if rest.is_empty() { None } else { Some(rest) };

            let matches = self.options.iter()
                .filter(|o| o.short_opt.into() == a0 as isize)
                .collect::<Vec<_>>();

            match matches.len() {
                0 => return Some(Err(Error::Unkown(a0.into()))),
                _ => matches[0],
            }
        };

        Some(self.maybe_get_value(m))
    }
}

/// Errors during argument parsing.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Malformed argument {:?}", _0)]
    Malformed(String),
    #[error("Unknown argument {:?}", _0)]
    Unkown(String),
    #[error("Ambiguous argument: {:?} matches {}", _0, _1)]
    Ambiguous(String, String),
    #[error("Missing parameter for {:?}", _0)]
    Missing(String),
    #[error("Parameter for {:?} is not a {}: {}", _0, _1, _2)]
    BadValue(String, &'static str, String),
}

/// Result specialization.
pub type Result<T> = std::result::Result<T, Error>;
