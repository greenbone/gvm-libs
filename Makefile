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

ALLDEPS = openvas-libraries.tmpl libopenvas-config

all: $(ALLDEPS) $(PCAP_MAKE)
	cd libopenvas && ${MAKE}
	cd libhosts_gatherer && ${MAKE}

libopenvas-config: libopenvas-config.pre Makefile openvas-libraries.tmpl
	@echo Creating $@ ...
	@eval LDFLAGS=\"$(CIPHER_LDFLAGS)\" ; \
	 eval  CFLAGS=\"$(CIPHER_CFLAGS)\" ; \
	 sed -e 's?%CIPHER_LDFLAGS%?'"$$LDFLAGS"'?' \
	     -e  's?%CIPHER_CFLAGS%?'"$$CFLAGS"'?' \
	     libopenvas-config.pre >$@

openvas-libraries.tmpl: openvas-libraries.tmpl.in configure VERSION
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
	test -d ${prefix} || ${INSTALL_DIR} -m 755 ${prefix}
	test -d ${libdir} || ${INSTALL_DIR} -m 755 ${libdir}
	-cd libpcap-nessus && ${MAKE} install

pcap-clean :
	-cd libpcap-nessus && ${MAKE} clean

pcap-distclean:
	-cd libpcap-nessus && ${MAKE} distclean

install : all $(PCAP_INSTALL)
	test -d ${prefix} || ${INSTALL_DIR} -m 755 ${prefix}
	test -d ${includedir}/openvas || ${INSTALL_DIR} -m 755 ${includedir}/openvas
	cd libopenvas && ${MAKE} install
	cd libhosts_gatherer && ${MAKE} install


	$(INSTALL) -m 0444 include/includes.h ${includedir}/openvas
	$(INSTALL) -m 0444 include/libopenvas.h ${includedir}/openvas
	$(INSTALL) -m 0444 include/harglists.h ${includedir}/openvas
	$(INSTALL) -m 0444 include/libvers.h   ${includedir}/openvas
	$(INSTALL) -m 0444 include/getopt.h    ${includedir}/openvas
	test -d ${bindir} || ${INSTALL_DIR} -m 755 ${bindir}
	test -d ${sbindir} || ${INSTALL_DIR} -m 755 ${sbindir}
	$(INSTALL) -m 0755 libopenvas-config ${bindir}/libopenvas-config
	test -d ${mandir} || ${INSTALL_DIR} -m 755 ${mandir}
	test -d ${mandir}/man1 || ${INSTALL_DIR} -m 755 ${mandir}/man1
	$(INSTALL) -m 0644 libopenvas-config.1 ${mandir}/man1

	@echo
	@echo ' --------------------------------------------------------------'
	@echo ' openvas-libraries has been sucessfully installed. '
	@echo " Make sure that $(bindir) is in your PATH before you"
	@echo " continue "
	@if [ -f /etc/ld.so.conf ]; then echo " Be sure to add $(libdir) in /etc/ld.so.conf and type 'ldconfig'"; else echo ""; fi
	@echo ' --------------------------------------------------------------'
	@echo

clean : $(PCAP_CLEAN)
	-cd libopenvas && ${MAKE} clean
	-cd libhosts_gatherer && ${MAKE} clean

distclean : clean $(PCAP_DISTCLEAN)
	rm -f ${rootdir}/include/config.h libtool config.cache \
	config.status config.log ${rootdir}/include/libvers.h 
	-cd libopenvas && ${MAKE} distclean
	-cd libhosts_gatherer && ${MAKE} distclean
	rm -f openvas-libraries.tmpl libopenvas-config libopenvas-config.pre

dist:
	version="`cat VERSION`"; \
	rm -rf openvas-libraries-$${version}* ; \
	mkdir openvas-libraries-$${version} ; \
	tar cf openvas-libraries-$${version}/x.tar `cat MANIFEST`; \
	( cd openvas-libraries-$${version} ; tar xf x.tar ; rm -f x.tar ) ; \
	tar cf openvas-libraries-$${version}.tar openvas-libraries-$${version} ; \
	gzip -9 openvas-libraries-$${version}.tar
