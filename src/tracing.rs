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
    enable("dirmngr");
    enable("keydb");
    enable("parcimonie");
}

pub fn enable(module: &str) {
    match module {
        "dirmngr" => crate::dirmngr::trace(true),
        "keydb" => crate::keydb::trace(true),
        "parcimonie" => crate::parcimonie::trace(true),
        _ => (),
    }
}
