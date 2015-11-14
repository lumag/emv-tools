CAPK_files = capk.txt visa.keys mastercard.keys amex.keys
EXTRA_DIST = mastercard-test.keys visa-test.keys
dist_pkgdata_DATA = $(CAPK_files) maestro.emu

pkgsysconf_DATA = config.txt

all-am: notinst.txt pklinks
DISTCLEANFILES = config.txt notinst.txt *.0
EXTRA_DIST += config.txt.in notinst.txt.in

edit = sed \
	-e 's|@default_crypto[@]|$(default_crypto)|g' \
	-e 's|@default_scard[@]|$(default_scard)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
	-e 's|@builddir[@]|$(abs_builddir)|g' \
	-e 's|@srcdir[@]|$(abs_srcdir)|g'

parseca = sed \
	-e 's/^\(..\):\(..\):\(..\):\(..\):\(..\) \(..\).*/\1\2\3\4\5_\6/g'

config.txt: $(builddir)/Makefile $(srcdir)/config.txt.in
	rm -f "$@" "$@.tmp"
	$(edit) "$(srcdir)/$@.in" > "$@.tmp"
	mv "$@.tmp" "$@"

notinst.txt: $(builddir)/Makefile $(srcdir)/notinst.txt.in
	rm -f "$@" "$@.tmp"
	$(edit) "$(srcdir)/$@.in" > "$@.tmp"
	mv "$@.tmp" "$@"

.PHONY: pklinks
pklinks: $(CAPK_files)
	for capk in $^; do \
		$(parseca) $$capk | while read pk; do \
			ln -sf $$capk $$pk.0; \
		done; \
	done

install-data-hook:
	for capk in $(CAPK_files); do \
		$(parseca) $(srcdir)/$$capk | while read pk; do \
			ln -sf $$capk $(DESTDIR)$(pkgdatadir)/$$pk.0; \
		done; \
	done

uninstall-hook:
	-rm -f $(DESTDIR)$(pkgdatadir)/*.0
