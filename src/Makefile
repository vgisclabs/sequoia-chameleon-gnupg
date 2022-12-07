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

error_codes.inc: err-codes.h.in
	echo >"$@.new" "/// Error codes defined in libgpg-error."
	echo >>"$@.new" "#[derive(Clone, Copy, Debug, PartialEq, Eq)]"
	echo >>"$@.new" "#[allow(non_camel_case_types)]"
	echo >>"$@.new" "pub enum Error {"
	sed -n -e '/[0-9]\+\s\+GPG_ERR_.*\s\+[A-Z].*/p' "$<" | while read N SYMBOL DESC; do \
	    echo >>"$@.new" "    /// $$DESC."; \
	    echo >>"$@.new" "    $$SYMBOL = $$N,"; \
	done
	echo >>"$@.new" "}"
	echo >>"$@.new"

	echo >>"$@.new" "impl std::fmt::Display for Error {"
	echo >>"$@.new" "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {"
	echo >>"$@.new" "        use Error::*;"
	echo >>"$@.new" "        match self {"
	sed -n -e '/[0-9]\+\s\+GPG_ERR_.*\s\+[A-Z].*/p' "$<" | while read N SYMBOL DESC; do \
	    echo >>"$@.new" "            $$SYMBOL => f.write_str(\"$$DESC\"),"; \
	done
	echo >>"$@.new" "        }"
	echo >>"$@.new" "    }"
	echo >>"$@.new" "}"
	echo >>"$@.new"

	echo >>"$@.new" "impl  std::error::Error for Error {}"

	mv "$@.new" "$@"
