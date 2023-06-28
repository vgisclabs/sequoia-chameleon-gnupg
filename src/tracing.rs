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
                enable(v);
            }
            continue;
        }

        if arg.starts_with("--debug=") {
            enable(&arg["--debug=".len()..]);
        }
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
    match module {
        "ipc" => crate::agent::trace(true),
        "dirmngr" => crate::dirmngr::trace(true),
        "keydb" => crate::keydb::trace(true),
        "keyserver" => crate::keyserver::trace(true),
        "parcimonie" => crate::parcimonie::trace(true),
        _ => (),
    }
}

/// Returns the list of modules in which tracing is enabled.
///
/// This can be passed as-is to a child process to enable tracing in
/// the same modules.
pub fn enabled_modules() -> Option<String> {
    let mut r = vec![];

    if crate::agent::traced() { r.push("ipc"); }
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
