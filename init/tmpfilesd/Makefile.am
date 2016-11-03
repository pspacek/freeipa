dist_noinst_DATA = 	\
	ipa.conf.in

systemdtmpfiles_DATA = 	\
	ipa.conf

%: %.in Makefile
	sed -e 's|@localstatedir[@]|$(localstatedir)|g' '$(srcdir)/$@.in' >$@
