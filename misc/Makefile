# OpenVAS
# $Id$
# Description: Makefile for libopenvasmisc of OpenVAS-libraries.
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

include ../openvas-libraries.tmpl

LIBS += $(GLIB_LIBS)

OBJS = plugutils.o system.o network.o resolve.o arglists.o ftp_funcs.o \
	scanners_utils.o pcap.o hlst.o  harglists.o \
	www_funcs.o ids_send.o rand.o popen.o \
	bpf_share.o rand.o popen.o services.o services1.o \
	proctitle.o store.o kb.o share_fd.o hash_table_file.o \
	openvas_ssh_login.o openvas_server.o openvas_auth.o \
	openvas_logging.o

LO_OBJS = plugutils.lo system.lo network.lo resolve.lo arglists.lo \
	ftp_funcs.lo scanners_utils.lo pcap.lo hlst.lo  harglists.lo \
	www_funcs.lo ids_send.lo \
	rand.lo popen.lo bpf_share.lo services.lo services1.lo \
	proctitle.lo store.lo kb.lo share_fd.lo hash_table_file.lo \
	openvas_ssh_login.lo openvas_server.lo openvas_auth.lo \
	openvas_logging.lo

# += does not work with non-GNU make ...
# CFLAGS+=-I../$(CIPHER_SUBDIR)
CFLAGS+=-g -Wall
INCLUDE = $(include) $(GLIB_CFLAGS) $(DEFS) -I../base
CIPHER = -I../$(CIPHER_SUBDIR)
COMPILE = $(LIBTOOL) --mode=compile $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS)
LINK = $(LIBTOOL) --mode=link $(CC) $(LDFLAGS)
all : libopenvasmisc.la

#../base/nvti.o: ../base/nvti.c ../base/nvti.h
#	$(COMPILE) -c ../base/nvti.c

#../base/certificate.o: ../base/certificate.c ../base/certificate.h
#	$(COMPILE) -c ../base/certificate.c

#../base/accessrules.o: ../base/accessrules.c ../base/accessrules.h
#	$(COMPILE) -c ../base/accessrules.c

plugutils.o: plugutils.c arglists.h comm.h harglists.h kb.h network.h \
             rand.h plugutils.h services.h share_fd.h system.h \
             scanners_utils.h
	$(COMPILE) -c plugutils.c

resolve.o : resolve.c resolve.h
	$(COMPILE) -c resolve.c

share_fd.o : share_fd.c 
	$(COMPILE) -c share_fd.c

system.o : system.c system_internal.h
	$(COMPILE) -c system.c 

arglists.o: arglists.c arglists.h system_internal.h
	$(COMPILE) -c arglists.c

network.o: network.c resolve.h ids_send.h plugutils.h
	$(COMPILE) -c network.c

scanners_utils.o: scanners_utils.c comm.h network.h services.h plugutils.h system.h scanners_utils.h
	$(COMPILE) -c scanners_utils.c

ftp_funcs.o: ftp_funcs.c network.h ftp_funcs.h
	$(COMPILE) -c ftp_funcs.c

www_funcs.o: www_funcs.c kb.h plugutils.h system.h
	$(COMPILE) -c www_funcs.c

pcap.o: pcap.c bpf_share.h pcap_openvas.h system_internal.h network.h
	$(COMPILE) -c pcap.c

hlst.o: hlst.c hlst.h system.h
	$(COMPILE) -c hlst.c

harglists.o: harglists.c hlst.h system_internal.h harglists.h
	$(COMPILE) -c harglists.c

ids_send.o: ids_send.c arglists.h bpf_share.h resolve.h ids_send.h network.h \
            pcap_openvas.h plugutils.h system.h
	$(COMPILE) -c ids_send.c 

bpf_share.o: bpf_share.c
	$(COMPILE) -c bpf_share.c

rand.o: rand.c
	$(COMPILE) -c rand.c

popen.o: popen.c system.h
	$(COMPILE) -c popen.c

services.o: services.c services.h
	$(COMPILE) -DOPENVAS_STATE_DIR=\"$(localstatedir)\" -c services.c

services1.o: services1.c services.h
	$(COMPILE) -DOPENVAS_STATE_DIR=\"$(localstatedir)\" -DCONF_DIR=\"$(sysconfdir)\" -c services1.c

proctitle.o: proctitle.c proctitle.h
	$(COMPILE) -c proctitle.c

store.o: store.c share_fd.h system.h plugutils.h
	$(COMPILE) -DOPENVAS_STATE_DIR=\"$(localstatedir)\" -c store.c

hash_table_file.o: hash_table_file.c hash_table_file.h
	$(COMPILE) -c hash_table_file.c

kb.o: kb.c arglists.h kb.h system_internal.h
	$(COMPILE) -c kb.c

openvas_ssh_login.o: openvas_ssh_login.c openvas_ssh_login.h
	$(COMPILE) -c openvas_ssh_login.c

openvas_logging.o: openvas_logging.c openvas_logging.h
	$(COMPILE) -c openvas_logging.c

openvas_server.o: openvas_server.c openvas_server.h
	$(COMPILE) -c openvas_server.c

OPENVAS_USERS_DIR = $(localstatedir)/lib/openvas/users/

openvas_auth.o: openvas_auth.c openvas_auth.h
	$(COMPILE) -DOPENVAS_USERS_DIR=\"$(OPENVAS_USERS_DIR)\" -c openvas_auth.c

libopenvasmisc.la: $(OBJS)
	$(LINK) -o libopenvasmisc.la $(LO_OBJS) $(LIBS) -rpath ${libdir} \
	-version-info ${PACKAGE_VERSION}

install : libopenvasmisc.la
	test -d $(DESTDIR)${libdir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${libdir}
	$(LIBTOOL) --mode install $(INSTALL) libopenvasmisc.la $(DESTDIR)${libdir}/libopenvasmisc.la
	$(LIBTOOL) --finish $(DESTDIR)${libdir}

distclean : clean

clean :
	rm -f *.o *.lo .libs/[!C][!V][!S]* *.la
	rm -rf .libs
