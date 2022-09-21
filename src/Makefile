gpg.option.inc: gpg.option.gpg.c.fragment gpg.option.oxidize gpg.option.implicit
	echo "/// GnuPG's command line options." > "$@"
	echo 'const OPTIONS: &[Opt<CmdOrOpt>] = &[' >> "$@"
	gcc -x c -E "$<" \
		| grep -v '^#' \
		| sed >> "$@" \
			-e 's/ \([0-9]\+\),/ o\1,/' \
			-e 's/" "//g' \
			-e 's/ARGPARSE_//g' \
			-e 's/long_opt: NULL,/long_opt: "",/'
	cat gpg.option.implicit >> "$@"
	echo '];' >> "$@"
