# OpenVAS-libraries/nasl
# $Id$
# Description: Top-level cmake control for the nasl library.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Felix Wolfsteller <felix.wolfsteller@greenbone.net>
#
# Copyright:
# Copyright (C) 2009-2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the Free
# Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

## Config

# Set policy for consistent behaviour regarding relative paths in
# link_directories
if (POLICY CMP0015)
  cmake_policy (SET CMP0015 OLD)
endif (POLICY CMP0015)

## Library

set (HARDENING_FLAGS            "-Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector -Wl,-z,relro -Wl,-z,now")

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Werror")
# The "-D_FILE_OFFSET_BITS=64 -DLARGEFILE_SOURCE=1" is necessary for GPGME!
# The "-fno-strict-aliasing" silences warnings caused by macros defined in byteorder.h.
# Once the warnings have been addressed this flag should be removed.
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} ${HARDENING_FLAGS} -Wall -D_FILE_OFFSET_BITS=64 -DLARGEFILE_SOURCE=1 -fno-strict-aliasing")

## Compile the parser - note that there are (better) CMake macros to achieve
## that and that the user is not warned if bison is not installed
add_custom_command (
   COMMAND bison
   ARGS -d -v -t -p nasl ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.y
   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.y
   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.tab.c
   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.tab.h
   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.output)

set (FILES arc4.c capture_packet.c charcnv.c exec.c genrand.c hmacmd5.c
     iconv.c lint.c md4.c md5.c nasl.c nasl_builtin_find_service.c
     nasl_builtin_openvas_tcp_scanner.c nasl_builtin_synscan.c nasl_builtin_nmap.c
     nasl_cmd_exec.c nasl_crypto2.c nasl_ssh.c nasl_cert.c
     nasl_crypto.c nasl_debug.c nasl_func.c nasl_grammar.tab.c nasl_host.c
     nasl_http.c nasl_init.c nasl_lex_ctxt.c nasl_misc_funcs.c nasl_scanner_glue.c
     nasl_packet_forgery.c nasl_packet_forgery_v6.c nasl_signature.c nasl_smb.c
     nasl_socket.c nasl_text_utils.c nasl_tree.c nasl_var.c nasl_wmi.c
     nasl_isotime.c
     ntlmssp.c strutils.c smb_crypt.c smb_crypt2.c
     smb_signing.c time.c)

set (HEADERS nasl.h)

if (NOT WMICLIENT_FOUND)
  set (FILES smb_interface_stub.c wmi_interface_stub.c ${FILES})
else (NOT WMICLIENT_FOUND)
  set (WMI_LIBS -lwmiclient)
  set (WMI wmiclient)
endif (NOT WMICLIENT_FOUND)

if (NOT WINCMD_FOUND)
  set (FILES smb_interface_stub.c ${FILES})
else (NOT WINCMD_FOUND)
  set (WINCMD_LIBS -lwincmd)
  set (WINCMD wincmd)
endif (NOT WINCMD_FOUND)

if (LIBSSH_FOUND)
  add_definitions (-DHAVE_LIBSSH)
endif (LIBSSH_FOUND)

if (KSBA)
  add_definitions (-DHAVE_LIBKSBA)
endif (KSBA)

set_source_files_properties (nasl_grammar.tab.c GENERATED)

## Pass-throughs
add_definitions (-DOPENVAS_STATE_DIR=\\\"${OPENVAS_STATE_DIR}\\\")
add_definitions (-DOPENVASLIB_VERSION=\\\"${OPENVASLIB_VERSION}\\\")
add_definitions (-DOPENVAS_SYSCONF_DIR=\\\"${OPENVAS_SYSCONF_DIR}\\\")

include_directories (../base)
include_directories (../misc)
include_directories (../include)

link_directories (${LIBDIR} ../base ../misc)

if (BUILD_STATIC)
   add_library (openvas_nasl_static STATIC ${FILES})

   set_target_properties (openvas_nasl_static PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${WMI_LIBS} ${WINCMD_LIBS} ${GPGME_CFLAGS} ${LIBSSH_CFLAGS} ${KSBA_CFLAGS} ${PCAP_LDFLAGS}")
   set_target_properties (openvas_nasl_static PROPERTIES OUTPUT_NAME "openvas_nasl")
   set_target_properties (openvas_nasl_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
   set_target_properties (openvas_nasl_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
   target_link_libraries (openvas_nasl_static openvas_base_static openvas_misc_static
                          "${GLIB_LDFLAGS}" gcrypt "${GPGME_LDFLAGS}"
                          gnutls "${PCAP_LDFLAGS}" "${WMI}" "${WINCMD}" "${LIBSSH_LDFLAGS}" "${KSBA_LDFLAGS}")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  add_library (openvas_nasl_shared SHARED ${FILES})
  set_target_properties (openvas_nasl_shared PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${WMI_LIBS} ${WINCMD_LIBS} ${GPGME_CFLAGS} ${LIBSSH_CFLAGS} ${KSBA_CFLAGS} ${PCAP_CFLAGS}")
  set_target_properties (openvas_nasl_shared PROPERTIES OUTPUT_NAME "openvas_nasl")
  set_target_properties (openvas_nasl_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (openvas_nasl_shared PROPERTIES SOVERSION "${CPACK_PACKAGE_VERSION_MAJOR}")
  set_target_properties (openvas_nasl_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  set_target_properties (openvas_nasl_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")
# line bellow is needed so it also works with no-undefined which is e.g. used by Mandriva
  target_link_libraries (openvas_nasl_shared openvas_base_shared openvas_misc_shared
                         "${GLIB_LDFLAGS}" "${GPGME_LDFLAGS}"
                         gnutls "${PCAP_LDFLAGS}" m ${WMI} ${WINCMD} ${LIBSSH_LDFLAGS} "${KSBA_LDFLAGS}")
endif (BUILD_SHARED)

# Link the openvas-nasl executable
if (BUILD_STATIC)
  add_executable (openvas-nasl nasl.c)
  target_link_libraries (openvas-nasl openvas_misc_static openvas_nasl_static
    openvas_base_static ${GLIB_LDFLAGS} -lgcrypt
    "${GPGME_LDFLAGS}" -lgnutls "${PCAP_LDFLAGS}" -lresolv -lm ${WMI_LIBS}
    ${GPGME_LDFLAGS} ${LIBSSH_LDFLAGS} ${KSBA_LDFLAGS} ${WINCMD_LIBS}) 
  set_target_properties (openvas-nasl PROPERTIES COMPILE_FLAGS
    "${GLIB_CFLAGS} ${GPGME_CFLAGS} ${LIBSSH_CFLAGS} ${KSBA_CFLAGS}")
endif (BUILD_STATIC)
if (BUILD_SHARED)
  add_executable (openvas-nasl nasl.c)
  target_link_libraries (openvas-nasl openvas_misc_shared openvas_nasl_shared
    openvas_base_shared ${GLIB_LDFLAGS} -lgcrypt
    "${GPGME_LDFLAGS}" -lgnutls "${PCAP_LDFLAGS}" -lresolv -lm ${WMI_LIBS}
    ${GPGME_LDFLAGS} ${LIBSSH_LDFLAGS} ${KSBA_LDFLAGS} ${WINCMD_LIBS}) 
  set_target_properties (openvas-nasl PROPERTIES COMPILE_FLAGS
    "${GLIB_CFLAGS} ${GPGME_CFLAGS} ${LIBSSH_CFLAGS} ${KSBA_CFLAGS}")
endif (BUILD_SHARED)

# Link the openvas-nasl-lint executable
if (BUILD_STATIC)
  add_executable (openvas-nasl-lint nasl-lint.c)
  target_link_libraries (openvas-nasl-lint openvas_misc_static openvas_nasl_static
    openvas_base_static ${GLIB_LDFLAGS} -lgcrypt
    "${GPGME_LDFLAGS}" -lgnutls "${PCAP_LDFLAGS}" -lresolv -lm ${WMI_LIBS}
    ${GPGME_LDFLAGS} ${LIBSSH_LDFLAGS} ${KSBA_LDFLAGS} ${WINCMD_LIBS}) 
  set_target_properties (openvas-nasl-lint PROPERTIES COMPILE_FLAGS
    "${GLIB_CFLAGS} ${GPGME_CFLAGS} ${LIBSSH_CFLAGS} ${KSBA_CFLAGS}")
endif (BUILD_STATIC)
if (BUILD_SHARED)
  add_executable (openvas-nasl-lint nasl-lint.c)
  target_link_libraries (openvas-nasl-lint openvas_misc_shared openvas_nasl_shared
    openvas_base_shared ${GLIB_LDFLAGS} -lgcrypt
    "${GPGME_LDFLAGS}" -lgnutls "${PCAP_LDFLAGS}" -lresolv -lm ${WMI_LIBS}
    ${GPGME_LDFLAGS} ${LIBSSH_LDFLAGS} ${KSBA_LDFLAGS} ${WINCMD_LIBS}) 
  set_target_properties (openvas-nasl-lint PROPERTIES COMPILE_FLAGS
    "${GLIB_CFLAGS} ${GPGME_CFLAGS} ${LIBSSH_CFLAGS} ${KSBA_CFLAGS}")
endif (BUILD_SHARED)

## Install

if (BUILD_STATIC)
  install (TARGETS openvas_nasl_static openvas-nasl openvas-nasl-lint
           RUNTIME DESTINATION ${BINDIR}
           ARCHIVE DESTINATION ${LIBDIR}
           PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/nasl")
endif (BUILD_STATIC)
if (BUILD_SHARED)
  install (TARGETS openvas_nasl_shared openvas-nasl openvas-nasl-lint
           RUNTIME DESTINATION ${BINDIR}
           LIBRARY DESTINATION ${LIBDIR}
           ARCHIVE DESTINATION ${LIBDIR}
           PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/nasl")
endif (BUILD_SHARED)

## End
