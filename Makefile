include nessus.tmpl

ALLDEPS = nessus.tmpl nessus-config

all: $(ALLDEPS) $(PCAP_MAKE)
	cd libnessus && ${MAKE}
	cd libhosts_gatherer && ${MAKE}

nessus-config: nessus-config.pre Makefile nessus.tmpl
	@echo Creating $@ ...
	@eval LDFLAGS=\"$(CIPHER_LDFLAGS)\" ; \
	 eval  CFLAGS=\"$(CIPHER_CFLAGS)\" ; \
	 sed -e 's?%CIPHER_LDFLAGS%?'"$$LDFLAGS"'?' \
	     -e  's?%CIPHER_CFLAGS%?'"$$CFLAGS"'?' \
	     nessus-config.pre >$@

nessus.tmpl: nessus.tmpl.in configure VERSION
	$(SHELL) configure $(CONFIGURE_ARGS)
	touch $@

win32:
	-cd libpcap-nessus    && ${MAKE} distclean
	-cd libhosts_gatherer && ${MAKE} distclean
	@echo
	@echo ' --------------------------------------------------------------'
	@echo ' The header files necessary and some docs have been generated,'
	@echo ' now.  Go ahead and move the nessus lib to a windows box where'
	@echo ' it can be compiled using nmake (all Micro$$oft stuff.)'
	@echo ' --------------------------------------------------------------'
	@echo


pcap-make :
	-cd libpcap-nessus && ${MAKE}

pcap-install:
	test -d $(DESTDIR)${prefix} || ${INSTALL_DIR} -m 755 $(DESTDIR)${prefix}
	test -d $(DESTDIR)${libdir} || ${INSTALL_DIR} -m 755 $(DESTDIR)${libdir}
	-cd libpcap-nessus && ${MAKE} install

pcap-clean :
	-cd libpcap-nessus && ${MAKE} clean

pcap-distclean:
	-cd libpcap-nessus && ${MAKE} distclean

install : $(PCAP_INSTALL)
	test -d $(DESTDIR)${prefix} || ${INSTALL_DIR} -m 755 $(DESTDIR)${prefix}
	test -d $(DESTDIR)${includedir}/nessus || ${INSTALL_DIR} -m 755 $(DESTDIR)${includedir}/nessus
	cd libnessus && ${MAKE} install
	cd libhosts_gatherer && ${MAKE} install


	$(INSTALL) -m 0444 include/includes.h $(DESTDIR)${includedir}/nessus
	$(INSTALL) -m 0444 include/libnessus.h $(DESTDIR)${includedir}/nessus
	$(INSTALL) -m 0444 include/harglists.h $(DESTDIR)${includedir}/nessus
	$(INSTALL) -m 0444 include/libvers.h   $(DESTDIR)${includedir}/nessus
	$(INSTALL) -m 0444 include/getopt.h    $(DESTDIR)${includedir}/nessus
	test -d $(DESTDIR)${bindir} || ${INSTALL_DIR} -m 755 $(DESTDIR)${bindir}
	test -d $(DESTDIR)${sbindir} || ${INSTALL_DIR} -m 755 $(DESTDIR)${sbindir}
	$(INSTALL) -m 0755 nessus-config $(DESTDIR)${bindir}/nessus-config
	$(INSTALL) -m 0755 uninstall-nessus $(DESTDIR)${sbindir}/uninstall-nessus
	test -d $(DESTDIR)${mandir} || ${INSTALL_DIR} -m 755 $(DESTDIR)${mandir}
	test -d $(DESTDIR)${mandir}/man1 || ${INSTALL_DIR} -m 755 $(DESTDIR)${mandir}/man1
	$(INSTALL) -m 0644 nessus-config.1 $(DESTDIR)${mandir}/man1

	@echo
	@echo ' --------------------------------------------------------------'
	@echo ' nessus-libraries has been sucessfully installed. '
	@echo " Make sure that $(bindir) is in your PATH before you"
	@echo " continue "
	@if [ -f /etc/ld.so.conf ]; then echo " Be sure to add $(libdir) in /etc/ld.so.conf and type 'ldconfig'"; else echo ""; fi
	@echo ' --------------------------------------------------------------'
	@echo

clean : $(PCAP_CLEAN)
	-cd libnessus && ${MAKE} clean
	-cd libhosts_gatherer && ${MAKE} clean

distclean : clean $(PCAP_DISTCLEAN)
	rm -f ${rootdir}/include/config.h libtool config.cache \
	config.status config.log ${rootdir}/include/libvers.h 
	-cd libnessus && ${MAKE} distclean
	-cd libhosts_gatherer && ${MAKE} distclean
	rm -f nessus.tmpl nessus-config nessus-config.pre uninstall-nessus
