# OpenVAS
# $Id$
# Description: Makefile for libopenvas of OpenVAS-libraries.
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
	openvas_ssh_login.o
	
LO_OBJS = plugutils.lo system.lo network.lo resolve.lo arglists.lo \
	ftp_funcs.lo scanners_utils.lo pcap.lo hlst.lo  harglists.lo \
	www_funcs.lo ids_send.lo \
	rand.lo popen.lo bpf_share.lo services.lo services1.lo \
	proctitle.lo store.lo kb.lo share_fd.lo hash_table_file.lo \
	openvas_ssh_login.lo

# += does not work with non-GNU make ...
# CFLAGS+=-I../$(CIPHER_SUBDIR)
CFLAGS+=-g -Wall
INCLUDE = $(include) $(GLIB_CFLAGS) $(DEFS)
CIPHER = -I../$(CIPHER_SUBDIR)

all : libopenvas.la


plugutils.o: plugutils.c arglists.h comm.h harglists.h kb.h network.h \
             rand.h plugutils.h services.h share_fd.h store_internal.h system.h \
             scanners_utils.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c plugutils.c

resolve.o : resolve.c resolve.h
	$(LIBTOOL) $(CC)  $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c resolve.c

share_fd.o : share_fd.c 
	$(LIBTOOL) $(CC)  $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c share_fd.c

system.o : system.c system_internal.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c system.c 

arglists.o: arglists.c arglists.h system_internal.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c arglists.c

network.o: network.c resolve.h ids_send.h plugutils.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c network.c

scanners_utils.o: scanners_utils.c comm.h network.h services.h plugutils.h system.h scanners_utils.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c scanners_utils.c

ftp_funcs.o: ftp_funcs.c network.h ftp_funcs.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c ftp_funcs.c

www_funcs.o: www_funcs.c kb.h plugutils.h system.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c www_funcs.c

pcap.o: pcap.c bpf_share.h pcap_openvas.h system_internal.h network.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c pcap.c

hlst.o: hlst.c hlst.h system.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c hlst.c

harglists.o: harglists.c hlst.h system_internal.h harglists.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c harglists.c

ids_send.o: ids_send.c arglists.h bpf_share.h resolve.h ids_send.h network.h \
            pcap_openvas.h plugutils.h system.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c ids_send.c 

bpf_share.o: bpf_share.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c bpf_share.c

rand.o: rand.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c rand.c

popen.o: popen.c system.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c popen.c

services.o: services.c services.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -DNESSUS_STATE_DIR=\"$(localstatedir)\" -c services.c

services1.o: services1.c services.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -DNESSUS_STATE_DIR=\"$(localstatedir)\" -DCONF_DIR=\"$(sysconfdir)\" -c services1.c

proctitle.o: proctitle.c proctitle.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c proctitle.c

store.o: store.c store_internal.h share_fd.h system.h plugutils.h plugutils_internal.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -DNESSUS_STATE_DIR=\"$(localstatedir)\" -c store.c

hash_table_file.o: hash_table_file.c hash_table_file.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c hash_table_file.c

kb.o: kb.c arglists.h kb.h system_internal.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c kb.c

openvas_ssh_login.o: openvas_ssh_login.c openvas_ssh_login.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c openvas_ssh_login.c

libopenvas.la: $(OBJS)
	$(LIBTOOL) $(CC) $(LDFLAGS) -o libopenvas.la $(LO_OBJS) $(LIBS) -rpath ${libdir} \
	-version-info ${PACKAGE_VERSION}

install : libopenvas.la
	test -d $(DESTDIR)${libdir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${libdir}
	$(LIBTOOL) --mode install $(INSTALL) libopenvas.la $(DESTDIR)${libdir}/libopenvas.la
	$(LIBTOOL) --finish $(DESTDIR)${libdir}

distclean : clean

clean :
	rm -f *.o *.lo .libs/[!C][!V][!S]* *.la
	rm -rf .libs
