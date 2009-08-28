# OpenVAS
# $Id$
# Description: Makefile for nasl of OpenVAS-libnasl.
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

include ../nasl.tmpl
OPENVAS_CFLAGS= -I../include $(OPTIMIZE) `$(LIBOPENVASCONFIG) --cflags` `$(GPGME_CONFIG) --cflags` $(GLIB_CFLAGS)
OPENVAS_LIBS = $(LIBS) `$(LIBOPENVASCONFIG) --libs` `$(GPGME_CONFIG) --libs` $(GLIB_LIBS)

OPENVAS_INCLUDE = $(OPENVAS_CFLAGS) $(include) $(DEFS)

YACC = bison 
YFLAGS	= -d -v -t -p nasl

OBJS = \
	nasl_packet_forgery.o \
	nasl_socket.o \
	nasl_crypto.o \
	nasl_crypto2.o \
	nasl_http.o \
	nasl_host.o \
	nasl_text_utils.o \
	nasl_nessusd_glue.o \
	nasl_misc_funcs.o \
	nasl_cmd_exec.o \
	capture_packet.o \
	nasl_grammar.tab.o \
	nasl_tree.o \
	nasl_var.o \
	exec.o \
	lint.o \
	nasl_lex_ctxt.o \
	nasl_func.o \
	nasl_init.o \
	strutils.o \
	regex.o \
	lsearch.o \
	preparse.o \
	nasl_signature.o \
	nasl_wmi.o \
	nasl_smb.o \
        wmi_interface_stub.o \
	smb_interface_stub.o \
	nasl_debug.o

LO_OBJS = \
	nasl_packet_forgery.lo \
	nasl_socket.lo \
	nasl_crypto.lo \
	nasl_crypto2.lo \
	nasl_http.lo \
	nasl_host.lo \
	nasl_text_utils.lo \
	nasl_nessusd_glue.lo \
	nasl_misc_funcs.lo \
	nasl_cmd_exec.lo \
	capture_packet.lo \
	nasl_grammar.tab.lo \
	nasl_tree.lo \
	nasl_var.lo \
	exec.lo \
	lint.lo \
	nasl_lex_ctxt.lo \
	nasl_func.lo \
	nasl_init.lo \
	strutils.lo \
	regex.lo \
	lsearch.lo \
	preparse.lo \
	nasl_signature.lo \
	nasl_wmi.lo \
	nasl_smb.lo \
        wmi_interface_stub.lo \
	smb_interface_stub.lo \
	nasl_debug.lo

COMPILE = $(LIBTOOL) --mode=compile $(CC) $(CFLAGS) $(OPENVAS_INCLUDE)
LINK = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(OPENVAS_INCLUDE)
all : libopenvasnasl.la openvas-nasl

.c.o:
	$(COMPILE) -c $<

openvas-nasl : $(OBJS) libopenvasnasl.la nasl.c
	$(LINK) $(LDFLAGS) -o openvas-nasl -DVERSION=\"$(VERSION)\" nasl.c $(LO_OBJS) \
	$(OPENVAS_LIBS)

libopenvasnasl.la : $(OBJS)
	$(LINK) $(LDFLAGS) $(OPENVAS_LIBS) -o libopenvasnasl.la $(LO_OBJS) -rpath ${libdir} \
	-version-info ${PACKAGE_VERSION}

install : libopenvasnasl.la openvas-nasl
	test -d ${DESTDIR}${libdir} || $(INSTALL_DIR) -m 755 ${DESTDIR}${libdir}
	test -d ${DESTDIR}${bindir} || $(INSTALL_DIR) -m 755 ${DESTDIR}${bindir}
	$(LIBTOOL) --mode=install $(INSTALL) libopenvasnasl.la ${DESTDIR}${libdir}/libopenvasnasl.la
	$(LIBTOOL) --mode=finish ${DESTDIR}${libdir}
	test -d ${DESTDIR}${bindir} || $(INSTALL_DIR) -m 755 ${DESTDIR}${bindir}
	$(INSTALL) openvas-nasl ${DESTDIR}${bindir}/


nasl_grammar.tab.o: nasl_grammar.tab.h nasl_grammar.tab.c nasl_tree.h
	$(COMPILE) -c nasl_grammar.tab.c

nasl_grammar.tab.h: nasl_grammar.tab.c nasl_grammar.y

nasl_grammar.tab.c: nasl_grammar.y
	$(YACC) $(YFLAGS) nasl_grammar.y

nasl_init.o: nasl_init.c
	 $(COMPILE) -c -DVERSION=\"$(VERSION)\" nasl_init.c


nasl_crypto2.o: nasl_crypto2.c
	$(COMPILE) -c nasl_crypto2.c

nasl_cmd_exec.o: nasl_cmd_exec.c
	$(COMPILE) -c -DOPENVAS_STATE_DIR=\"$(localstatedir)\" nasl_cmd_exec.c 

nasl_signature.o: nasl_signature.c
	$(COMPILE) -c -DOPENVAS_SYSCONFDIR=\"$(sysconfdir)\" nasl_signature.c

nasl_func.o: nasl_func.c nasl_var.h

nasl_var.o: nasl_var.c nasl_var.h

nasl_wmi.o: nasl_wmi.c nasl_wmi.h

nasl_smb.o: nasl_smb.c nasl_smb.h

exec.o: exec.c exec.h nasl_tree.h nasl_global_ctxt.h nasl_func.h nasl_var.h nasl_lex_ctxt.h nasl_init.h strutils.h

lint.o: lint.c exec.h nasl_tree.h nasl_global_ctxt.h nasl_func.h nasl_var.h nasl_lex_ctxt.h nasl_init.h strutils.h

wmi_interface_stub.o: wmi_interface_stub.c openvas_wmi_interface.h
	$(COMPILE) -c wmi_interface_stub.c

smb_interface_stub.o: smb_interface_stub.c openvas_smb_interface.h
	$(COMPILE) -c smb_interface_stub.c

distclean : clean

clean :
	@rm -f OBJ/*.*
	@rm -f *~
	@rm -f *.o *.lo *.la
	@rm -rf .libs
	@rm -f openvas-nasl *core cflags
	@rm -f y.tab.h y.tab.c nasl_grammar.tab.c nasl_grammar.tab.h lex.yy.clex.yy.h y.output nasl_grammar.output
