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

all: $(ALLDEPS)
	cd libopenvas && ${MAKE}
	cd libopenvas_hg && ${MAKE}

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

install : all
	test -d ${prefix} || ${INSTALL_DIR} -m 755 ${prefix}
	test -d ${includedir}/openvas || ${INSTALL_DIR} -m 755 ${includedir}/openvas
	cd libopenvas && ${MAKE} install
	cd libopenvas_hg && ${MAKE} install


	$(INSTALL) -m 0444 include/includes.h ${includedir}/openvas
	$(INSTALL) -m 0444 include/libopenvas.h ${includedir}/openvas
	$(INSTALL) -m 0444 include/libvers.h   ${includedir}/openvas
	$(INSTALL) -m 0444 include/getopt.h    ${includedir}/openvas
	$(INSTALL) -m 0444 libopenvas/arglists.h ${includedir}/openvas
	$(INSTALL) -m 0444 libopenvas/bpf_share.h ${includedir}/openvas
	$(INSTALL) -m 0444 libopenvas/ftp_funcs.h ${includedir}/openvas
	$(INSTALL) -m 0444 libopenvas/harglists.h ${includedir}/openvas
	$(INSTALL) -m 0444 libopenvas/kb.h ${includedir}/openvas
	$(INSTALL) -m 0444 libopenvas/network.h ${includedir}/openvas
	$(INSTALL) -m 0444 libopenvas/pcap_openvas.h ${includedir}/openvas
	$(INSTALL) -m 0444 libopenvas/plugutils.h ${includedir}/openvas
	$(INSTALL) -m 0444 libopenvas/system.h ${includedir}/openvas
	$(INSTALL) -m 0444 libopenvas/www_funcs.h ${includedir}/openvas
	test -d ${bindir} || ${INSTALL_DIR} -m 755 ${bindir}
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

clean :
	-cd libopenvas && ${MAKE} clean
	-cd libopenvas_hg && ${MAKE} clean

distclean : clean
	rm -f ${rootdir}/include/config.h libtool config.cache \
	config.status config.log ${rootdir}/include/libvers.h 
	-cd libopenvas && ${MAKE} distclean
	-cd libopenvas_hg && ${MAKE} distclean
	rm -f openvas-libraries.tmpl libopenvas-config libopenvas-config.pre

dist:
	version="`cat VERSION`"; \
	rm -rf openvas-libraries-$${version}* ; \
	mkdir openvas-libraries-$${version} ; \
	tar cf openvas-libraries-$${version}/x.tar `cat MANIFEST`; \
	( cd openvas-libraries-$${version} ; tar xf x.tar ; rm -f x.tar ) ; \
	tar cf openvas-libraries-$${version}.tar openvas-libraries-$${version} ; \
	gzip -9 openvas-libraries-$${version}.tar
