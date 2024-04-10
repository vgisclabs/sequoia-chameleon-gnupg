#![allow(dead_code, unused_macros)]

macro_rules! trace_module {
    ( $I:ident ) => {
        /// Controls tracing in this module.
        pub fn trace(enable: bool) {
            $I.store(enable, std::sync::atomic::Ordering::Relaxed);
        }

        /// Returns whether tracing is enabled in this module.
        pub fn traced() -> bool {
            $I.load(std::sync::atomic::Ordering::Relaxed)
        }

        static $I: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
    };
}

macro_rules! trace {
    ( $TRACE:expr, $fmt:expr, $($pargs:expr),* ) => {
        if $TRACE.load(std::sync::atomic::Ordering::Relaxed) {
            let m = format!($fmt, $($pargs),*);
            eprintln!("gpg: DBG: {}", m);
            crate::with_invocation_log(|w| Ok(writeln!(w, "{}", m)?));
        }
    };
    ( $TRACE:expr, $fmt:expr ) => {
        trace!($TRACE, $fmt, );
    };
}

// Converts an indentation level to whitespace.
pub(crate) fn indent(i: isize) -> &'static str {
    let s = "                                                  ";
    &s[0..std::cmp::min(usize::try_from(i).unwrap_or(0), s.len())]
}

macro_rules! tracer {
    // Make tracer!(true, ...) work
    ( true, $func:expr ) => {
        tracer!(std::sync::atomic::AtomicBool::new(true), $func, 0)
    };
    // as well as tracer!(false, ...).
    ( false, $func:expr ) => {
        tracer!(std::sync::atomic::AtomicBool::new(false), $func, 0)
    };
    ( $TRACE:expr, $func:expr ) => {
        tracer!($TRACE, $func, 0)
    };
    ( $TRACE:expr, $func:expr, $indent:expr ) => {
        // Currently, Rust doesn't support $( ... ) in a nested
        // macro's definition.  See:
        // https://users.rust-lang.org/t/nested-macros-issue/8348/2
        macro_rules! t {
            ( $fmt:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, $fmt) };
            ( $fmt:expr, $a:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a)) };
            ( $fmt:expr, $a:expr, $b:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e, $f)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr ) =>
            { trace!($TRACE, "{}{}: {}", crate::macros::indent($indent), $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k)) };
        }
    }
}

macro_rules! platform {
    { unix => { $($unix:tt)* }, windows => { $($windows:tt)* }, } => {
        if cfg!(unix) {
            #[cfg(unix)] { $($unix)* }
            #[cfg(not(unix))] { unreachable!() }
        } else if cfg!(windows) {
            #[cfg(windows)] { $($windows)* }
            #[cfg(not(windows))] { unreachable!() }
        } else {
            #[cfg(not(any(unix, windows)))] compile_error!("Unsupported platform");
            unreachable!()
        }
    }
}
