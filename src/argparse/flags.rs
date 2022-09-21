//! Flags for each option (ARGPARSE_OPTS).  The type code may be ORed
//! with the OPT flags.

/// Does not take an argument.
pub const TYPE_NONE    : u32 =     0;
/// Takes an int argument.
pub const TYPE_INT     : u32 =     1;
/// Takes a string argument.
pub const TYPE_STRING  : u32 =     2;
/// Takes a long argument.
pub const TYPE_LONG    : u32 =     3;
/// Takes an unsigned long argument.
pub const TYPE_ULONG   : u32 =     4;
/// Argument is optional.
pub const OPT_OPTIONAL : u32 = 1<< 3;
/// Allow 0x etc. prefixed values.
pub const OPT_PREFIX   : u32 = 1<< 4;

/// Ignore command or option.
pub const OPT_IGNORE   : u32 = 1<< 6;
/// The argument is a command.
pub const OPT_COMMAND  : u32 = 1<< 7;
/// The value is a conffile.
pub const OPT_CONFFILE : u32 = 1<< 8;
/// The value is printed as a header.
pub const OPT_HEADER   : u32 = 1<< 9;

// Unused flags:

//pub const OPT_VERBATIM : u32 = 1<<10; // The value is printed verbatim.
//pub const ATTR_FORCE   : u32 = 1<<14; // Attribute force is set.
//pub const ATTR_IGNORE  : u32 = 1<<15; // Attribute ignore is set.

/// Returns the type bits for the given flags.
pub fn flags_type(flags: u32) -> u32 {
    flags & 0b111
}
