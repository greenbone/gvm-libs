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

OBJS = plugutils.o system.o network.o resolve.o arglists.o ftp_funcs.o \
	scanners_utils.o pcap.o hlst.o  harglists.o \
        getopt.o getopt1.o www_funcs.o diff.o ids_send.o rand.o popen.o \
	bpf_share.o rand.o popen.o services.o services1.o \
	proctitle.o store.o snprintf.o kb.o share_fd.o
	
LO_OBJS = plugutils.lo system.lo network.lo resolve.lo arglists.lo \
	ftp_funcs.lo scanners_utils.lo pcap.lo hlst.lo  harglists.lo \
	getopt.lo getopt1.lo www_funcs.lo diff.lo ids_send.lo \
	rand.lo popen.lo bpf_share.lo services.lo services1.lo \
	proctitle.lo store.lo snprintf.lo kb.lo share_fd.lo

# += does not work with non-GNU make ...
# CFLAGS+=-I../$(CIPHER_SUBDIR)
CFLAGS+=-g
INCLUDE = ${include} 
CIPHER = -I../$(CIPHER_SUBDIR)

all : libopenvas.la


getopt.o : getopt.c
	 $(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c getopt.c

getopt1.o : getopt1.c
	 $(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c getopt1.c

plugutils.o : plugutils.c
	 $(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c plugutils.c

resolve.o : resolve.c resolve.h
	$(LIBTOOL) $(CC)  $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c resolve.c

share_fd.o : share_fd.c 
	$(LIBTOOL) $(CC)  $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c share_fd.c

system.o : system.c system.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c system.c 

arglists.o : arglists.c 
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c arglists.c

network.o : network.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c network.c

scanners_utils.o : scanners_utils.c scanners_utils.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c scanners_utils.c

ftp_funcs.o : ftp_funcs.c ftp_funcs.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c ftp_funcs.c
www_funcs.o : www_funcs.c 
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c www_funcs.c
	
pcap.o : pcap.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c pcap.c

hlst.o : hlst.c hlst.h
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c hlst.c

ptycall.o : ptycall.c 
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c ptycall.c

harglists.o : harglists.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c harglists.c

diff.o : diff.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c diff.c

ids_send.o : ids_send.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c ids_send.c 

bpf_share.o: bpf_share.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -DNESSUS_STATE_DIR=\"$(localstatedir)\" -c bpf_share.c

rand.o: rand.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c rand.c

popen.o: popen.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c popen.c

services.o: services.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -DNESSUS_STATE_DIR=\"$(localstatedir)\" -c services.c

services1.o: services1.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -DNESSUS_STATE_DIR=\"$(localstatedir)\" -DCONF_DIR=\"$(sysconfdir)\" -c services1.c

proctitle.o: proctitle.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c proctitle.c

store.o: store.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -DNESSUS_STATE_DIR=\"$(localstatedir)\" -c store.c
	
	
kb.o: kb.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c kb.c


snprintf.o : snprintf.c
	$(LIBTOOL) $(CC) $(CIPHER) $(DEFS) $(INCLUDE) $(CFLAGS) -c snprintf.c	
libopenvas.la: $(OBJS)
	$(LIBTOOL) $(CC) -o libopenvas.la $(LO_OBJS) -rpath ${libdir} \
	-version-info ${PACKAGE_VERSION}

install : libopenvas.la
	test -d $(DESTDIR)${libdir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${libdir}
	$(LIBTOOL) --mode install $(INSTALL) libopenvas.la $(DESTDIR)${libdir}/libopenvas.la
	$(LIBTOOL) --finish $(DESTDIR)${libdir}

distclean : clean

clean :
	rm -f *.o *.lo .libs/[!C][!V][!S]* *.la
	rm -rf .libs


