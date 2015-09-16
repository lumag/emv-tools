dist_pkgdata_DATA = capk.txt maestro.emu

pkgsysconf_DATA = config.txt

all-am: notinst.txt
DISTCLEANFILES = config.txt notinst.txt
EXTRA_DIST = config.txt.in notinst.txt.in

edit = sed \
	-e 's|@default_crypto[@]|$(default_crypto)|g' \
	-e 's|@default_scard[@]|$(default_scard)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
	-e 's|@builddir[@]|$(abs_builddir)|g' \
	-e 's|@srcdir[@]|$(abs_srcdir)|g'

config.txt: $(builddir)/Makefile $(srcdir)/config.txt.in
	rm -f "$@" "$@.tmp"
	$(edit) "$(srcdir)/$@.in" > "$@.tmp"
	mv "$@.tmp" "$@"

notinst.txt: $(builddir)/Makefile $(srcdir)/notinst.txt.in
	rm -f "$@" "$@.tmp"
	$(edit) "$(srcdir)/$@.in" > "$@.tmp"
	mv "$@.tmp" "$@"
