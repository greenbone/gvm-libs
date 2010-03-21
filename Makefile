# OpenVAS
# $Id$
# Description: Overall Makefile for OpenVAS-libraries.
#
# Authors:
# Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
#
# Copyright:
# Based on work Copyright (C) 1998 - 2007 Tenable Network Security, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation

include openvas-libraries.tmpl

ALLDEPS = openvas-libraries.tmpl

all: $(ALLDEPS)
	cd base && cmake -DCMAKE_INSTALL_PREFIX=${prefix} -DSYSCONFDIR=${sysconfdir} -DLOCALSTATEDIR=${localstatedir} -DHAVE_WMI=$(HAVE_WMI) -DLIBDIR=$(libdir) && ${MAKE}
	cd misc && cmake -DCMAKE_INSTALL_PREFIX=${prefix} -DSYSCONFDIR=${sysconfdir} -DLOCALSTATEDIR=${localstatedir} -DLIBDIR=$(libdir) && ${MAKE}
	cd hg   && cmake -DCMAKE_INSTALL_PREFIX=${prefix} -DSYSCONFDIR=${sysconfdir} -DLOCALSTATEDIR=${localstatedir} -DLIBDIR=$(libdir) && ${MAKE}
	cd nasl && cmake -DCMAKE_INSTALL_PREFIX=${prefix} -DSYSCONFDIR=${sysconfdir} -DLOCALSTATEDIR=${localstatedir} -DLIBDIR=$(libdir) && ${MAKE}
	cd omp  && cmake -DCMAKE_INSTALL_PREFIX=${prefix} -DSYSCONFDIR=${sysconfdir} -DLOCALSTATEDIR=${localstatedir} -DLIBDIR=$(libdir) && ${MAKE}

openvas-libraries.tmpl: openvas-libraries.tmpl.in configure VERSION
	$(SHELL) configure $(CONFIGURE_ARGS)
	touch $@

install-tools:
	test -d $(DESTDIR)${datarootdir}/openvas || $(INSTALL_DIR) -m 755 $(DESTDIR)${datarootdir}/openvas
	$(INSTALL) -m 755 tools/openvas-lsc-rpm-creator.sh $(DESTDIR)${datarootdir}/openvas

install: all install-tools
	test -d $(DESTDIR)${prefix} || ${INSTALL_DIR} -m 755 $(DESTDIR)${prefix}
	test -d $(DESTDIR)${includedir}/openvas || ${INSTALL_DIR} -m 755 $(DESTDIR)${includedir}/openvas
	test -d $(DESTDIR)${includedir}/openvas/base || ${INSTALL_DIR} -m 755 $(DESTDIR)${includedir}/openvas/base
	test -d $(DESTDIR)${includedir}/openvas/nasl || ${INSTALL_DIR} -m 755 $(DESTDIR)${includedir}/openvas/nasl
	test -d $(DESTDIR)${includedir}/openvas/omp || ${INSTALL_DIR} -m 755 $(DESTDIR)${includedir}/openvas/omp

	cd base && ${MAKE} install
	cd misc && ${MAKE} install
	cd hg   && ${MAKE} install
	cd nasl && ${MAKE} install
	cd omp  && ${MAKE} install

	$(INSTALL) -m 0444 include/nvt_categories.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 include/libvers.h   $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/arglists.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/bpf_share.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/ftp_funcs.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/hash_table_file.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/kb.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/network.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/otp.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/pcap_openvas.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/plugutils.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/popen.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/proctitle.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/rand.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/resolve.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/openvas_ssh_login.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/openvas_logging.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/openvas_server.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/openvas_auth.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/scanners_utils.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/services1.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/share_fd.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/store.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/system.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 misc/www_funcs.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0444 base/certificate.h $(DESTDIR)${includedir}/openvas/base
	$(INSTALL) -m 0444 base/hash_table_util.h $(DESTDIR)${includedir}/openvas/base
	$(INSTALL) -m 0444 nasl/nasl.h   $(DESTDIR)${includedir}/openvas/nasl
	$(INSTALL) -m 0444 base/nvti.h $(DESTDIR)${includedir}/openvas/base
	$(INSTALL) -m 0444 base/settings.h $(DESTDIR)${includedir}/openvas/base
	$(INSTALL) -m 0444 base/openvas_certificate_file.h $(DESTDIR)${includedir}/openvas/base
	$(INSTALL) -m 0444 base/openvas_string.h $(DESTDIR)${includedir}/openvas/base
	$(INSTALL) -m 0444 base/pidfile.h $(DESTDIR)${includedir}/openvas/base
	$(INSTALL) -m 0444 base/severity_filter.h $(DESTDIR)${includedir}/openvas/base
	$(INSTALL) -m 0444 omp/omp.h $(DESTDIR)${includedir}/openvas/omp
	$(INSTALL) -m 0444 omp/xml.h $(DESTDIR)${includedir}/openvas/omp
	test -d $(DESTDIR)${bindir} || ${INSTALL_DIR} -m 755 $(DESTDIR)${bindir}
	$(INSTALL) -m 0755 libopenvas-config $(DESTDIR)${bindir}/libopenvas-config
	test -d $(DESTDIR)${mandir} || ${INSTALL_DIR} -m 755 $(DESTDIR)${mandir}
	test -d $(DESTDIR)${mandir}/man1 || ${INSTALL_DIR} -m 755 $(DESTDIR)${mandir}/man1
	$(INSTALL) -m 0644 doc/libopenvas-config.1 $(DESTDIR)${mandir}/man1
	$(INSTALL) -m 0644 doc/openvas-nasl.1 ${DESTDIR}${mandir}/man1

	@echo
	@echo ' --------------------------------------------------------------'
	@echo ' openvas-libraries has been successfully installed. '
	@echo " Make sure that $(DESTDIR)$(bindir) is in your PATH before you"
	@echo " continue "
	@if [ -f /etc/ld.so.conf ]; then echo " Be sure to add $(DESTDIR)$(libdir) in /etc/ld.so.conf and type 'ldconfig'"; else echo ""; fi
	@echo ' --------------------------------------------------------------'
	@echo

clean:
	-cd base && ${MAKE} clean
	-cd hg   && ${MAKE} clean
	-cd misc && ${MAKE} clean
	-cd nasl && ${MAKE} clean
	-cd omp  && ${MAKE} clean
	rm -rf doc/generated

distclean: clean
	rm -f ${rootdir}/include/config.h libtool config.cache \
	config.status config.log ${rootdir}/include/libvers.h
	-cd misc && ${MAKE} distclean
	-cd hg && ${MAKE} distclean
	rm -f openvas-libraries.tmpl libopenvas-config libopenvas-config.pre
	rm -f libopenvas.pc
	rm -rf doc/generated
	find . -name CMakeCache.txt -exec rm {} \;

dist:
	version="`cat VERSION`"; \
	rm -rf openvas-libraries-$${version}* ; \
	mkdir openvas-libraries-$${version} ; \
	tar cf openvas-libraries-$${version}/x.tar `cat MANIFEST`; \
	( cd openvas-libraries-$${version} ; tar xf x.tar ; rm -f x.tar ) ; \
	tar cf openvas-libraries-$${version}.tar openvas-libraries-$${version} ; \
	gzip -9 openvas-libraries-$${version}.tar

# Generates basic code documentation (placed in doc/generated)
doc:
	doxygen doc/Doxyfile

# Generates more extensive code documentation with graphs
# (placed in doc/generated) and builds doc/generated/latex/refman.pdf
doc-full:
	doxygen doc/Doxyfile_full
	if [ -d doc/generated/latex ]; then make -C doc/generated/latex; fi

.PHONY: doc doc-full
