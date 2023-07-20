use anyhow::Result;

use super::super::*;

#[test]
#[ntest::timeout(600000)]
fn print_md_md5() -> Result<()> {
    let e = make_experiment!()?;
    print_md(e, "md5")
}

#[test]
#[ntest::timeout(600000)]
fn print_md_sha1() -> Result<()> {
    let e = make_experiment!()?;
    print_md(e, "sha1")
}

#[test]
#[ntest::timeout(600000)]
fn print_md_ripemd160() -> Result<()> {
    let e = make_experiment!()?;
    print_md(e, "ripemd160")
}

#[test]
#[ntest::timeout(600000)]
fn print_md_sha224() -> Result<()> {
    let e = make_experiment!()?;
    print_md(e, "sha224")
}

#[test]
#[ntest::timeout(600000)]
fn print_md_sha256() -> Result<()> {
    let e = make_experiment!()?;
    print_md(e, "sha256")
}

#[test]
#[ntest::timeout(600000)]
fn print_md_sha384() -> Result<()> {
    let e = make_experiment!()?;
    print_md(e, "sha384")
}

#[test]
#[ntest::timeout(600000)]
fn print_md_sha512() -> Result<()> {
    let e = make_experiment!()?;
    print_md(e, "sha512")
}

#[test]
#[ntest::timeout(600000)]
fn print_md_star() -> Result<()> {
    let e = make_experiment!()?;
    print_md(e, "*")
}

fn print_md<A: Into<Option<&'static str>>>(mut e: Experiment, arg: A) -> Result<()>
{
    // Create the keyring stores.  Reduces the noise in the upcoming
    // experiments.
    e.invoke(&["--list-keys"])?.assert_success();

    let arg = arg.into();
    let foo = e.store("foo", "foo")?;
    let bar = e.store("bar", "bar")?;

    for with_colons in [false, true] {
        let mut args = vec![];

        if with_colons {
            args.push("--with-colons");
        }

        args.push("--print-md");
        if let Some(arg) = &arg {
            args.push(arg);
        }

        args.push(&foo);
        let mut diff = e.invoke(&args)?;
        diff.canonicalize_with(trim_start)?;
        diff.assert_success();
        diff.assert_equal_up_to(20, 0);

        args.push(&bar);
        let mut diff = e.invoke(&args)?;
        diff.canonicalize_with(trim_start)?;
        diff.assert_success();
        diff.assert_equal_up_to(20, 0);
    }

    Ok(())
}

#[test]
#[ntest::timeout(600000)]
fn print_mds() -> Result<()> {
    let mut e = make_experiment!()?;

    // Create the keyring stores.  Reduces the noise in the upcoming
    // experiments.
    e.invoke(&["--list-keys"])?.assert_success();

    let foo = e.store("foo", "foo")?;
    let bar = e.store("bar", "bar")?;

    for with_colons in [false, true] {
        let mut args = vec![];

        if with_colons {
            args.push("--with-colons");
        }

        args.push("--print-mds");

        args.push(&foo);
        let mut diff = e.invoke(&args)?;
        diff.canonicalize_with(trim_start)?;
        diff.assert_success();
        diff.assert_equal_up_to(20, 0);

        args.push(&bar);
        let mut diff = e.invoke(&args)?;
        diff.canonicalize_with(trim_start)?;
        diff.assert_success();
        diff.assert_equal_up_to(20, 0);
    }

    Ok(())
}

fn trim_start(o: &mut crate::Output) -> Result<()> {
    let s = regex::bytes::Regex::new("\n *").unwrap();
    o.stdout = s.replace_all(&o.stdout, &b"\n"[..]).to_vec();
    Ok(())
}
