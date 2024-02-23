use crate::{
    Result,
    argparse::Error,
};

pub struct Opt<T> {
    pub name: &'static str,
    pub factory: fn(&mut T, bool, Option<&str>) -> Result<()>,
    pub value: bool,
    pub help: &'static str,
    pub enabled: bool,
}

/// Option taking no value.
#[allow(unused_macros)]
macro_rules! opt {
    { $name: expr, $factory: expr, $help: expr, } => {
        Opt {
            name: $name,
            factory: $factory,
            value: false,
            help: $help,
            enabled: true,
        }
    };
}

/// Option taking an argument.
#[allow(unused_macros)]
macro_rules! opt_with_arg {
    { $name: expr, $factory: expr, $help: expr, } => {
        Opt {
            name: $name,
            factory: $factory,
            value: true,
            help: $help,
            enabled: true,
        }
    };
}

/// Option that does nothing.
///
/// These will be hidden in help listings, and do nothing.
#[allow(unused_macros)]
macro_rules! opt_nop {
    ( $name: expr ) => {
        Opt {
            name: $name,
            factory: |_, _, _| Ok(()),
            value: false,
            help: "",
            enabled: true,
        }
    };
}

/// Option that is not yet implemented.
///
/// These will be hidden in help listings, and will not be matched
/// when parsing arguments.
#[allow(unused_macros)]
macro_rules! opt_todo {
    { $name: expr, $factory: expr, $help: expr, } => {
        Opt {
            name: $name,
            factory: |_, _, _| Ok(()),
            value: false,
            help: "",
            enabled: false,
        }
    };
}

/// Prints the list of import options if requested.
///
/// If `s == "help"`, prints all supported options and returns `true`.
/// The caller should then exit the process gracefully.
pub fn maybe_print_help<T>(opts: &[Opt<T>], s: &str) -> Result<bool> {
    if s != "help" {
        return Ok(false);
    }

    let width = opts.iter()
        .filter(|o| o.enabled && ! o.help.is_empty())
        .map(|o| o.name.len()).max().unwrap_or(0);
    for opt in opts.iter().filter(|o| ! o.help.is_empty()) {
        eprintln!("{:<width$}  {}", opt.name, opt.help);
    }

    Ok(true)
}

/// Parses the options `s` described by `opts`, mutating `o`.
pub fn parse<T>(opts: &[Opt<T>], s: &str, o: &mut T) -> Result<()> {
    let mut rest = Some(s);
    'parsing: while let Some(v) = rest {
        let (token, r) = optsep(v);
        rest = r;

        let (original_key, value) = argsplit(token);

        let reversed = original_key.starts_with("no-");
        let key = if reversed {
            &original_key[3..]
        } else {
            &original_key[..]
        };

        for (i, opt) in opts.iter().filter(|o| o.enabled).enumerate() {
            if opt.name.starts_with(key) {
                if opt.name != key {
                    if let Some(other) = opts[i + 1..].iter()
                        .filter(|o| o.enabled)
                        .find(|o| o.name.starts_with(key))
                    {
                        return Err(Error::Ambiguous(
                            key.into(), other.name.into()).into());
                    }
                }

                (opt.factory)(o, ! reversed, value)?;
                continue 'parsing;
            }
        }

        return Err(Error::Unknown(original_key.into()).into());
    }

    Ok(())
}

/// Break a string into successive option pieces.  Accepts single word
/// options and key=value argument options.
fn optsep(s: &str) -> (&str, Option<&str>) {
    assert!(! s.is_empty());

    if let Some(mut end) = s.find(&[' ', ',', '=']) {
	// what we need to do now is scan along starting with *end, If
	// the next character we see (ignoring spaces) is an = sign,
	// then there is an argument.
        let argument =
            if let Some(equals) = s[end..].find('=') {
                if s[end..end + equals].chars().all(|c| c == ' ') {
                    Some(&s[end + equals + 1..])
                } else {
                    None
                }
            } else {
                None
            };

        let mut rest = &s[end + 1..];
        if let Some(arg) = argument {
	    // There is an argument, so grab that too.  At this point,
	    // ptr points to the first character of the argument.
            if arg.starts_with('"') {
                if let Some(closing) = arg[1..].find('"') {
                    rest = &rest[1 + closing + 1..];
                    end += 1 + closing + 1 + 1;
                } else {
                    // GnuPG ignores missing closing quotes, so we do
                    // too.
                    rest = "";
                    end += arg.len() + 1;
                }
            } else {
                if let Some(eoa) = arg.find(&[' ', ',']) {
                    rest = &rest[eoa + 1..];
                    end += eoa + 1;
                } else {
                    rest = "";
                    end += arg.len() + 1;
                }
            }
        }
        if rest.starts_with(",") {
            rest = &rest[1..];
        }
        let rest = rest.trim_start();
        (&s[..end], if rest.is_empty() { None } else { Some(rest) })
    } else {
        (s, None)
    }
}

/// Breaks an option into key and value.
fn argsplit(s: &str) -> (&str, Option<&str>) {
    let mut split = s.splitn(2, "=");
    let mut key = split.next().unwrap();
    let value = if let Some(mut value) = split.next() {
        if value.starts_with("\"") {
            value = &value[1..];
            if value.ends_with("\"") {
                value = &value[..value.len() - 1];
            }
        } else {
            value = value.trim_start();
        }

        key = key.trim_end();
        Some(value)
    } else {
        None
    };

    (key, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_options() {
        #[derive(Default)]
        struct ImportOptions {
            import_show: bool,
            http_proxy: Option<String>,
        }


        let import_opts: [Opt<ImportOptions>; 2] = [
            opt! {
                "import-show",
                |o, selected, _| {
                    o.import_show = selected;
                    Ok(())
                },
                "show key during import",
            },
            opt_with_arg! {
                "http-proxy",
                |o, selected, v| {
                    o.http_proxy = if selected {
                        v.map(Into::into)
                    } else {
                        None
                    };
                    Ok(())
                },
                "show key during import",
            },
        ];

        let mut i = ImportOptions::default();
        parse(&import_opts, "import-show", &mut i).unwrap();
        assert_eq!(i.import_show, true);
        assert_eq!(i.http_proxy, None);

        let mut i = ImportOptions::default();
        i.import_show = true;
        parse(&import_opts, "no-import-show", &mut i).unwrap();
        assert_eq!(i.import_show, false);
        assert_eq!(i.http_proxy, None);

        let mut i = ImportOptions::default();
        parse(&import_opts, "http-proxy=http://localhost:8080", &mut i).unwrap();
        assert_eq!(i.import_show, false);
        assert_eq!(i.http_proxy, Some("http://localhost:8080".into()));

        let mut i = ImportOptions::default();
        parse(&import_opts, "http-proxy=\"http://localhost:8080\"", &mut i).unwrap();
        assert_eq!(i.import_show, false);
        assert_eq!(i.http_proxy, Some("http://localhost:8080".into()));

        let mut i = ImportOptions::default();
        parse(&import_opts, "import-show,http-proxy=http://localhost:8080", &mut i).unwrap();
        assert_eq!(i.import_show, true);
        assert_eq!(i.http_proxy, Some("http://localhost:8080".into()));

        let mut i = ImportOptions::default();
        parse(&import_opts, "import-sho", &mut i).unwrap();
        assert_eq!(i.import_show, true);
        assert_eq!(i.http_proxy, None);

        let mut i = ImportOptions::default();
        assert!(parse(&import_opts, "import-short", &mut i).is_err());
    }

    #[test]
    fn tokenizing() {
        fn t(mut s: &str, t: &[&str]) {
            let mut tokens = Vec::new();

            loop {
                let (arg, rest) = optsep(s);
                tokens.push(arg);
                if let Some(r) = rest {
                    s = r;
                } else {
                    break;
                }
            }

            assert_eq!(&tokens, t);
        }

        t("foo", &["foo"]);
        t("foo=arg", &["foo=arg"]);
        t("foo=\"arg\"", &["foo=\"arg\""]);
        t("foo,bar", &["foo", "bar"]);
        t("foo, bar", &["foo", "bar"]);
        t("foo bar", &["foo", "bar"]);
        t("foo=arg,bar", &["foo=arg", "bar"]);
        t("foo=arg, bar", &["foo=arg", "bar"]);
        t("foo=arg bar", &["foo=arg", "bar"]);
        t("foo,bar=arg", &["foo", "bar=arg"]);
        t("foo, bar=arg", &["foo", "bar=arg"]);
        t("foo bar=arg", &["foo", "bar=arg"]);
        t("foo=\"arg\",bar", &["foo=\"arg\"", "bar"]);
        t("foo=\"arg\", bar", &["foo=\"arg\"", "bar"]);
        t("foo=\"arg\" bar", &["foo=\"arg\"", "bar"]);
        t("foo,bar=\"arg\"", &["foo", "bar=\"arg\""]);
        t("foo, bar=\"arg\"", &["foo", "bar=\"arg\""]);
        t("foo bar=\"arg\"", &["foo", "bar=\"arg\""]);
        t("foo,bar=\"arg", &["foo", "bar=\"arg"]);
        t("foo, bar=\"arg", &["foo", "bar=\"arg"]);
        t("foo bar=\"arg", &["foo", "bar=\"arg"]);
    }

    #[test]
    fn splitting() {
        assert_eq!(argsplit("foo"), ("foo", None));
        assert_eq!(argsplit("foo=bar"), ("foo", Some("bar")));
        assert_eq!(argsplit("foo=\"bar\""), ("foo", Some("bar")));
        assert_eq!(argsplit("foo=\"bar"), ("foo", Some("bar")));
        assert_eq!(argsplit("foo =bar"), ("foo", Some("bar")));
        assert_eq!(argsplit("foo =\"bar\""), ("foo", Some("bar")));
        assert_eq!(argsplit("foo =\"bar"), ("foo", Some("bar")));
        assert_eq!(argsplit("foo= bar"), ("foo", Some("bar")));
        assert_eq!(argsplit("foo=\" bar\""), ("foo", Some(" bar")));
        assert_eq!(argsplit("foo=\" bar"), ("foo", Some(" bar")));
    }
}
