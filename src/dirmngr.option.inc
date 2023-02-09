/// dirmngr's command line options.
const OPTIONS: &[Opt<CmdOrOpt>] = &[

  Opt { short_opt: aGPGConfList, long_opt: "gpgconf-list", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
  Opt { short_opt: aGPGConfTest, long_opt: "gpgconf-test", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
  Opt { short_opt: aGPGConfVersions, long_opt: "gpgconf-versions", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },

  Opt { short_opt: o300, long_opt: "", flags: 0, description: "@Commands:\n ", },

  Opt { short_opt: aServer, long_opt: "server", flags: (TYPE_NONE | OPT_COMMAND), description: "run in server mode (foreground)", },
  Opt { short_opt: aDaemon, long_opt: "daemon", flags: (TYPE_NONE | OPT_COMMAND), description: "run in daemon mode (background)", },

  Opt { short_opt: aSupervised, long_opt: "supervised", flags: (TYPE_NONE | OPT_COMMAND), description: "run in supervised mode", },

  Opt { short_opt: aListCRLs, long_opt: "list-crls", flags: (TYPE_NONE | OPT_COMMAND), description: "list the contents of the CRL cache", },
  Opt { short_opt: aLoadCRL, long_opt: "load-crl", flags: (TYPE_NONE | OPT_COMMAND), description: "|FILE|load CRL from FILE into cache", },
  Opt { short_opt: aFetchCRL, long_opt: "fetch-crl", flags: (TYPE_NONE | OPT_COMMAND), description: "|URL|fetch a CRL from URL", },
  Opt { short_opt: aShutdown, long_opt: "shutdown", flags: (TYPE_NONE | OPT_COMMAND), description: "shutdown the dirmngr", },
  Opt { short_opt: aFlush, long_opt: "flush", flags: (TYPE_NONE | OPT_COMMAND), description: "flush the cache", },


  Opt { short_opt: o1, long_opt: "", flags: (OPT_HEADER), description: "Options used for startup", },

  Opt { short_opt: oNoDetach, long_opt: "no-detach", flags: TYPE_NONE, description: "do not detach from the console", },
  Opt { short_opt: oSh, long_opt: "sh", flags: TYPE_NONE, description: "sh-style command output", },
  Opt { short_opt: oCsh, long_opt: "csh", flags: TYPE_NONE, description: "csh-style command output", },
  Opt { short_opt: oStealSocket, long_opt: "steal-socket", flags: TYPE_NONE, description: "@", },
  Opt { short_opt: oHomedir, long_opt: "homedir", flags: TYPE_STRING, description: "@", },
  Opt { short_opt: oOptions, long_opt: "options", flags: (TYPE_STRING|OPT_CONFFILE), description: "|FILE|read options from FILE", },
  Opt { short_opt: oNoOptions, long_opt: "no-options", flags: (TYPE_NONE|OPT_CONFFILE), description: "@", },


  Opt { short_opt: o1, long_opt: "Monitor", flags: (OPT_HEADER), description: "Options controlling the diagnostic output", },

  Opt { short_opt: oVerbose, long_opt: "verbose", flags: TYPE_NONE, description: "verbose", },
  Opt { short_opt: oQuiet, long_opt: "quiet", flags: TYPE_NONE, description: "be somewhat more quiet", },
  Opt { short_opt: oNoGreeting, long_opt: "no-greeting", flags: TYPE_NONE, description: "@", },
  Opt { short_opt: oDebugLevel, long_opt: "debug-level", flags: TYPE_STRING, description: "|LEVEL|set the debugging level to LEVEL", }
                                                              ,
  Opt { short_opt: oDebug, long_opt: "debug", flags: TYPE_STRING, description: "@", },
  Opt { short_opt: oDebugAll, long_opt: "debug-all", flags: TYPE_NONE, description: "@", },
  Opt { short_opt: oGnutlsDebug, long_opt: "gnutls-debug", flags: TYPE_INT, description: "@", },
  Opt { short_opt: oGnutlsDebug, long_opt: "tls-debug", flags: TYPE_INT, description: "@", },
  Opt { short_opt: oDebugWait, long_opt: "debug-wait", flags: TYPE_INT, description: "@", },
  Opt { short_opt: oLogFile, long_opt: "log-file", flags: TYPE_STRING, description: "|FILE|write server mode logs to FILE", }
                                                           ,


  Opt { short_opt: o1, long_opt: "Configuration", flags: (OPT_HEADER), description: "Options controlling the configuration", }
                                                               ,

  Opt { short_opt: oAllowVersionCheck, long_opt: "allow-version-check", flags: TYPE_NONE, description: "allow online software version check", }
                                                          ,
  Opt { short_opt: oListenBacklog, long_opt: "listen-backlog", flags: TYPE_INT, description: "@", },
  Opt { short_opt: oMaxReplies, long_opt: "max-replies", flags: TYPE_INT, description: "|N|do not return more than N items in one query", }
                                                                      ,
  Opt { short_opt: oFakedSystemTime, long_opt: "faked-system-time", flags: TYPE_ULONG, description: "@", },
  Opt { short_opt: oDisableCheckOwnSocket, long_opt: "disable-check-own-socket", flags: TYPE_NONE, description: "@", },
  Opt { short_opt: oIgnoreCert, long_opt: "ignore-cert", flags: TYPE_STRING, description: "@", },
  Opt { short_opt: oIgnoreCertExtension, long_opt: "ignore-cert-extension", flags: TYPE_STRING, description: "@", },


  Opt { short_opt: o1, long_opt: "Network", flags: (OPT_HEADER), description: "Network related options", },

  Opt { short_opt: oUseTor, long_opt: "use-tor", flags: TYPE_NONE, description: "route all network traffic via Tor", },
  Opt { short_opt: oNoUseTor, long_opt: "no-use-tor", flags: TYPE_NONE, description: "@", },
  Opt { short_opt: oDisableIPv4, long_opt: "disable-ipv4", flags: TYPE_NONE, description: "@", },
  Opt { short_opt: oDisableIPv6, long_opt: "disable-ipv6", flags: TYPE_NONE, description: "@", },
  Opt { short_opt: oStandardResolver, long_opt: "standard-resolver", flags: TYPE_NONE, description: "@", },
  Opt { short_opt: oRecursiveResolver, long_opt: "recursive-resolver", flags: TYPE_NONE, description: "@", },
  Opt { short_opt: oResolverTimeout, long_opt: "resolver-timeout", flags: TYPE_INT, description: "@", },
  Opt { short_opt: oNameServer, long_opt: "nameserver", flags: TYPE_STRING, description: "@", },
  Opt { short_opt: oConnectTimeout, long_opt: "connect-timeout", flags: TYPE_INT, description: "@", },
  Opt { short_opt: oConnectQuickTimeout, long_opt: "connect-quick-timeout", flags: TYPE_INT, description: "@", },


  Opt { short_opt: o1, long_opt: "Keyserver", flags: (OPT_HEADER), description: "Configuration for Keyservers", },

  Opt { short_opt: oKeyServer, long_opt: "keyserver", flags: TYPE_STRING, description: "|URL|use keyserver at URL", }
                                                ,
  Opt { short_opt: oHkpCaCert, long_opt: "hkp-cacert", flags: TYPE_STRING, description: "|FILE|use the CA certificates in FILE for HKP over TLS", }
                                                                             ,


  Opt { short_opt: o1, long_opt: "HTTP", flags: (OPT_HEADER), description: "Configuration for HTTP servers", },

  Opt { short_opt: oDisableHTTP, long_opt: "disable-http", flags: TYPE_NONE, description: "inhibit the use of HTTP", },
  Opt { short_opt: oIgnoreHTTPDP, long_opt: "ignore-http-dp", flags: TYPE_NONE, description: "ignore HTTP CRL distribution points", }
                                                          ,
  Opt { short_opt: oHTTPProxy, long_opt: "http-proxy", flags: TYPE_STRING, description: "|URL|redirect all HTTP requests to URL", }
                                                             ,
  Opt { short_opt: oHonorHTTPProxy, long_opt: "honor-http-proxy", flags: TYPE_NONE, description: "use system's HTTP proxy setting", }
                                                      ,
  Opt { short_opt: oLDAPWrapperProgram, long_opt: "ldap-wrapper-program", flags: TYPE_STRING, description: "@", },


  Opt { short_opt: o1, long_opt: "LDAP", flags: (OPT_HEADER), description: "Configuration of LDAP servers to use", },

  Opt { short_opt: oDisableLDAP, long_opt: "disable-ldap", flags: TYPE_NONE, description: "inhibit the use of LDAP", },
  Opt { short_opt: oIgnoreLDAPDP, long_opt: "ignore-ldap-dp", flags: TYPE_NONE, description: "ignore LDAP CRL distribution points", }
                                                          ,
  Opt { short_opt: oLDAPProxy, long_opt: "ldap-proxy", flags: TYPE_STRING, description: "|HOST|use HOST for LDAP queries", }
                                                      ,
  Opt { short_opt: oOnlyLDAPProxy, long_opt: "only-ldap-proxy", flags: TYPE_NONE, description: "do not use fallback hosts with --ldap-proxy", }
                                                                  ,
  Opt { short_opt: oLDAPServer, long_opt: "ldapserver", flags: TYPE_STRING, description: "|SPEC|use this keyserver to lookup keys", }
                                                              ,
  Opt { short_opt: oLDAPFile, long_opt: "ldapserverlist-file", flags: TYPE_STRING, description: "|FILE|read LDAP server list from FILE", }
                                                            ,
  Opt { short_opt: oLDAPAddServers, long_opt: "add-servers", flags: TYPE_NONE, description: "add new servers discovered in CRL distribution points to serverlist", }

                                            ,
  Opt { short_opt: oLDAPTimeout, long_opt: "ldaptimeout", flags: TYPE_INT, description: "|N|set LDAP timeout to N seconds", }
                                                       ,


  Opt { short_opt: o1, long_opt: "OCSP", flags: (OPT_HEADER), description: "Configuration for OCSP", },

  Opt { short_opt: oAllowOCSP, long_opt: "allow-ocsp", flags: TYPE_NONE, description: "allow sending OCSP requests", },
  Opt { short_opt: oIgnoreOCSPSvcUrl, long_opt: "ignore-ocsp-service-url", flags: TYPE_NONE, description: "ignore certificate contained OCSP service URLs", }
                                                                     ,
  Opt { short_opt: oOCSPResponder, long_opt: "ocsp-responder", flags: TYPE_STRING, description: "|URL|use OCSP responder at URL", }
                                                     ,
  Opt { short_opt: oOCSPSigner, long_opt: "ocsp-signer", flags: TYPE_STRING, description: "|FPR|OCSP response signed by FPR", }
                                                       ,
  Opt { short_opt: oOCSPMaxClockSkew, long_opt: "ocsp-max-clock-skew", flags: TYPE_INT, description: "@", },
  Opt { short_opt: oOCSPMaxPeriod, long_opt: "ocsp-max-period", flags: TYPE_INT, description: "@", },
  Opt { short_opt: oOCSPCurrentPeriod, long_opt: "ocsp-current-period", flags: TYPE_INT, description: "@", },


  Opt { short_opt: o1, long_opt: "", flags: (OPT_HEADER), description: "Other options", },

  Opt { short_opt: oForce, long_opt: "force", flags: TYPE_NONE, description: "force loading of outdated CRLs", },

  Opt { short_opt: oSocketName, long_opt: "socket-name", flags: TYPE_STRING, description: "@", },
  Opt { short_opt: oDebugCacheExpiredCerts, long_opt: "debug-cache-expired-certs", flags: TYPE_NONE, description: "@", },

  Opt { short_opt: o1, long_opt: "", flags: (OPT_HEADER), description: "", },


  Opt { short_opt: oBatch, long_opt: "batch", flags: TYPE_NONE, description: "@", },
  Opt { short_opt: oHTTPWrapperProgram, long_opt: "http-wrapper-program", flags: TYPE_STRING, description: "@", },


  Opt { short_opt: o302, long_opt: "", flags: 0, description: "@\n(See the \"info\" manual for a complete listing of all commands and options)\n", }
                                                           ,

 

        // Special, implicit commands.
        Opt { short_opt: aHelp, long_opt: "help", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
        Opt { short_opt: aVersion, long_opt: "version", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
        Opt { short_opt: aWarranty, long_opt: "warranty", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
        Opt { short_opt: aDumpOpttbl, long_opt: "dump-option-table", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
        Opt { short_opt: aDumpOptions, long_opt: "dump-options", flags: (TYPE_NONE | OPT_COMMAND), description: "@", },
];
