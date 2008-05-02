# OpenVAS
# $Id$
# Description: Makefile for libopenvas_hg of OpenVAS-libraries.
#
# Authors:
# Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
#
# Copyright:
# Based on work Copyright (C) 1998 - 2007 Tenable Network Security, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

include ../openvas-libraries.tmpl
COMPILE = $(CC) $(DEFS) $(include) $(CFLAGS) -Wall -I../libopenvas
LTCOMPILE = $(LIBTOOL) --mode=compile $(CC) $(DEFS) $(include) $(CFLAGS)
LINK = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(WS2_32)


OBJS = hg_utils.o hg_add_hosts.o hg_subnet.o hg_filter.o hosts_gatherer.o \
	hg_debug.o hg_dns_axfr.o

LO_OBJS = hg_utils.lo hg_add_hosts.lo hg_subnet.lo hg_filter.lo \
	hosts_gatherer.lo hg_debug.lo hg_dns_axfr.lo


all : libopenvas_hg.la

test : libopenvas_hg.la test.c
	$(COMPILE)  test.c -o test -L.libs -lopenvas_hg $(LIBS)

install : libopenvas_hg.la
	test -d $(DESTDIR)${libdir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${libdir}
	$(LIBTOOL) --mode install $(INSTALL) libopenvas_hg.la $(DESTDIR)${libdir} 
	$(LIBTOOL) --finish $(DESTDIR)${libdir}
	$(INSTALL) -m 0644 hosts_gatherer.h $(DESTDIR)${includedir}/openvas
	$(INSTALL) -m 0644 hg_utils.h $(DESTDIR)${includedir}/openvas

libopenvas_hg.la : $(OBJS)
	$(LIBTOOL) $(CC) $(LIBS) -o libopenvas_hg.la $(LO_OBJS) -rpath ${libdir} \
	-version-info ${PACKAGE_VERSION}
	        
hg_utils.o : hg_utils.h hosts_gatherer.h hg_utils.c
	$(LIBTOOL) --mode=compile  $(COMPILE) -c hg_utils.c

hg_add_hosts.o : hg_add_hosts.h hosts_gatherer.h hg_add_hosts.c
	$(LIBTOOL) --mode=compile  $(COMPILE) -c hg_add_hosts.c

hg_subnet.o : hg_subnet.h hosts_gatherer.h hg_subnet.c
	$(LIBTOOL) --mode=compile  $(COMPILE) -c hg_subnet.c
	
hg_filter.o : hg_filter.h hosts_gatherer.h hg_filter.c
	$(LIBTOOL) --mode=compile  $(COMPILE) -c hg_filter.c	

hosts_gatherer.o : hosts_gatherer.h hosts_gatherer.c
	$(LIBTOOL) --mode=compile  $(COMPILE) -c hosts_gatherer.c
		
hg_dns_axfr.o : hg_dns_axfr.c hosts_gatherer.h hg_dns_axfr.c
	$(LIBTOOL) --mode=compile $(COMPILE) -c hg_dns_axfr.c
	
hg_debug.o : hg_debug.c hosts_gatherer.h hg_debug.c
	$(LIBTOOL) --mode=compile  $(COMPILE) -c hg_debug.c
	
distclean : clean
	
clean :
	@rm -f OBJ/* lib*.a *~ *core *.lo *.o lib*.la
	@rm -rf .libs
