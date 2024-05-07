//! Safe variants for `print!` and friends.
//!
//! `print!` and friends panic when the stream is closed.  This is
//! unexpected for our users, and panicking makes us deviate from
//! GnuPG's behavior, which would just continue.
//!

// XXX: This is what rustc does.  If they start using a nicer
// interface, adapt.

use std::fmt;
use std::io::{self, Write as _};

/// Use this instead of `print!` throughout this crate.
macro_rules! safe_print {
    ($($arg:tt)*) => {{
        $crate::print::print(std::format_args!($($arg)*));
    }};
}

/// Use this instead of `println!` throughout this crate.
macro_rules! safe_println {
    () => {
        safe_print!("\n")
    };
    ($($arg:tt)*) => {
        safe_print!("{}\n", std::format_args!($($arg)*))
    };
}

#[doc(hidden)]
pub(crate) fn print(args: fmt::Arguments<'_>) {
    let _ = io::stdout().write_fmt(args);
}

/// Use this instead of `eprint!` throughout this crate.
macro_rules! safe_eprint {
    ($($arg:tt)*) => {{
        $crate::print::eprint(std::format_args!($($arg)*));
    }};
}

/// Use this instead of `eprintln!` throughout this crate.
macro_rules! safe_eprintln {
    () => {
        safe_eprint!("\n")
    };
    ($($arg:tt)*) => {
        safe_eprint!("{}\n", std::format_args!($($arg)*))
    };
}

#[doc(hidden)]
pub(crate) fn eprint(args: fmt::Arguments<'_>) {
    let _ = io::stderr().write_fmt(args);
}
