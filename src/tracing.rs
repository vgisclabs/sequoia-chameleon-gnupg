//! Controls tracing via --debug flags.

/// Parses command line arguments for --debug flags.
pub fn parse_command_line() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    for (i, arg) in args.iter().enumerate()  {
        if arg == "--debug-all" {
            enable_all();
            return;
        }

        if arg == "--debug" {
            if let Some(v) = args.get(i + 1) {
                handle_command_line_flag(v);
            }
            continue;
        }

        if arg.starts_with("--debug=") {
            handle_command_line_flag(&arg["--debug=".len()..]);
        }
    }
}

/// Dispatches the flag given on the command line.
fn handle_command_line_flag(f: &str) {
    match f {
        "help" => {
            eprintln!("gpg: available debug flags:");
            eprintln!("gpg:        all");
            eprintln!("gpg:        dirmngr");
            eprintln!("gpg:        ipc");
            eprintln!("gpg:        keydb");
            eprintln!("gpg:        keyserver");
            eprintln!("gpg:        parcimonie");
            std::process::exit(0);
        },
        "all" => enable_all(),
        _ => enable(f),
    }
}

/// Enables tracing in all modules.
pub fn enable_all() {
    enable("ipc");
    enable("dirmngr");
    enable("keydb");
    enable("keyserver");
    enable("parcimonie");
}

/// Enables tracing in the given module.
///
/// If the module is unknown, nothing happens.
pub fn enable(module: &str) {
    // Decode numerical flags.
    if let Ok(n) = module.parse::<u32>() {
        if n == !0 {
            enable_all();
        } else if n & DBG_IPC > 0 {
            enable("ipc");
        }
        return;
    }

    match module {
        "ipc" => crate::gpg_agent::trace(true),
        "dirmngr" => crate::dirmngr::trace(true),
        "keydb" => crate::keydb::trace(true),
        "keyserver" => crate::keyserver::trace(true),
        "parcimonie" => crate::parcimonie::trace(true),
        _ => eprintln!("gpg: unknown debug flag '{}' ignored", module),
    }
}

/// Returns the list of modules in which tracing is enabled.
///
/// This can be passed as-is to a child process to enable tracing in
/// the same modules.
pub fn enabled_modules() -> Option<String> {
    let mut r = vec![];

    if crate::gpg_agent::traced() { r.push("ipc"); }
    if crate::dirmngr::traced() { r.push("dirmngr"); }
    if crate::keydb::traced() { r.push("keydb"); }
    if crate::keyserver::traced() { r.push("keyserver"); }
    if crate::parcimonie::traced() { r.push("parcimonie"); }

    if r.is_empty() {
        None
    } else {
        Some(r.join(","))
    }
}

// The debugging flags.
pub const DBG_PACKET:  u32 = 1     /* debug packet reading/writing */;
pub const DBG_MPI:     u32 = 2     /* debug mpi details */;
pub const DBG_CRYPTO:  u32 = 4     /* debug crypto handling */;
                                   /* (may reveal sensitive data) */
pub const DBG_FILTER:  u32 = 8     /* debug internal filter handling */;
pub const DBG_IOBUF:   u32 = 16    /* debug iobuf stuff */;
pub const DBG_MEMORY:  u32 = 32    /* debug memory allocation stuff */;
pub const DBG_CACHE:   u32 = 64    /* debug the caching */;
pub const DBG_MEMSTAT: u32 = 128   /* show memory statistics */;
pub const DBG_TRUST:   u32 = 256   /* debug the trustdb */;
pub const DBG_HASHING: u32 = 512   /* debug hashing operations */;
pub const DBG_IPC:     u32 = 1024  /* debug assuan communication */;
pub const DBG_CLOCK:   u32 = 4096;
pub const DBG_LOOKUP:  u32 = 8192  /* debug the key lookup */;
pub const DBG_EXTPROG: u32 = 16384 /* debug external program calls */;
