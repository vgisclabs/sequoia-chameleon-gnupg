//! Reads dirmngr's configuration.

use anyhow::Context;

use crate::{
    argparse::{Parser, Argument, Opt, flags::*},
    Result,
};

/// Controls tracing.
const TRACE: bool = false;

/// Commands and options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum CmdOrOpt {
    aNull = 0,
    o1 = 1,
    oCsh          = 'c' as isize,
    oQuiet        = 'q' as isize,
    oSh           = 's' as isize,
    oVerbose      = 'v' as isize,
    o300 = 300,
    o301,
    o302,
    o303,
    oNoVerbose = 500,

    aServer,
    aDaemon,
    aSupervised,
    aListCRLs,
    aLoadCRL,
    aFetchCRL,
    aShutdown,
    aFlush,
    aGPGConfList,
    aGPGConfTest,
    aGPGConfVersions,

    oOptions,
    oDebug,
    oDebugAll,
    oDebugWait,
    oDebugLevel,
    oGnutlsDebug,
    oDebugCacheExpiredCerts,
    oNoGreeting,
    oNoOptions,
    oHomedir,
    oNoDetach,
    oLogFile,
    oBatch,
    oDisableHTTP,
    oDisableLDAP,
    oDisableIPv4,
    oDisableIPv6,
    oIgnoreLDAPDP,
    oIgnoreHTTPDP,
    oIgnoreOCSPSvcUrl,
    oHonorHTTPProxy,
    oHTTPProxy,
    oLDAPProxy,
    oOnlyLDAPProxy,
    oLDAPServer,
    oLDAPFile,
    oLDAPTimeout,
    oLDAPAddServers,
    oOCSPResponder,
    oOCSPSigner,
    oOCSPMaxClockSkew,
    oOCSPMaxPeriod,
    oOCSPCurrentPeriod,
    oMaxReplies,
    oHkpCaCert,
    oFakedSystemTime,
    oForce,
    oAllowOCSP,
    oAllowVersionCheck,
    oStealSocket,
    oSocketName,
    oLDAPWrapperProgram,
    oHTTPWrapperProgram,
    oIgnoreCert,
    oIgnoreCertExtension,
    oUseTor,
    oNoUseTor,
    oKeyServer,
    oNameServer,
    oDisableCheckOwnSocket,
    oStandardResolver,
    oRecursiveResolver,
    oResolverTimeout,
    oConnectTimeout,
    oConnectQuickTimeout,
    oListenBacklog,
    aTest,

    // Special, implicit commands.
    aHelp = 'h' as isize,
    aVersion = 32769,
    aWarranty = 32770,
    aDumpOptions = 32771,
    aDumpOpttbl = 32772,
}

impl From<CmdOrOpt> for isize {
    fn from(c: CmdOrOpt) -> isize {
        c as isize
    }
}

use CmdOrOpt::*;

include!("dirmngr.option.inc");

pub fn parse(config: &mut crate::Config) -> Result<()> {
    tracer!(TRACE, "dirmngr::parse");

    let parser: Parser<CmdOrOpt> = Parser::new(
        "dirmngr", "",
        &OPTIONS);

    let p = config.homedir.join("dirmngr.conf");
    for rarg in parser.try_parse_file(&p)? {
        let argument =
            rarg.with_context(|| {
                format!("Error parsing config file {}",
                        p.display())
            })?;

        let (cmd, value) = match argument {
            Argument::Option(cmd, value) => (cmd, value),
            Argument::Positional(arg) =>
                return Err(anyhow::anyhow!(
                    "Encountered positional argument {:?}", arg)),
        };
        let mut handle_argument = || -> Result<()> {
            use CmdOrOpt::*;
            match cmd {
	        oKeyServer => {
                    let ks = value.as_str().unwrap().parse()?;
                    if ! config.keyserver.contains(&ks) {
                        config.keyserver.push(ks);
                    }
	        },

                c => t!("Ignoring {:?}={:?}", c, value),
            }
            Ok(())
        };

        handle_argument().with_context(|| {
            if let Some(arg) = parser.argument_name(cmd) {
                format!("Error parsing option {} in {}", arg, p.display())
            } else {
                format!("Error parsing unknown option in {}", p.display())
            }
        })?;
    }

    Ok(())
}
