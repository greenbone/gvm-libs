# OpenVAS-libraries/nasl
# $Id$
# Description: Top-level cmake control for the nasl library.
#
# Authors:
# Matthew Mundell <matthew.mundell@intevation.de>
# Felix Wolfsteller <felix.wolfsteller@intevation.de>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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

message ("-- Configuring OpenVAS-libraries/nasl...")

project (openvas-libraries/nasl C)

cmake_minimum_required (VERSION 2.6)

if (POLICY CMP0005)
   cmake_policy (SET CMP0005 OLD)
endif (POLICY CMP0005)

set (CMAKE_BUILD_TYPE debug)

## Version

file (READ ../VERSION _OPENVASLIBNASL_VERSION)

string (REGEX REPLACE "\\\n" "." _OPENVASLIBNASL_VERSION_STR ${_OPENVASLIBNASL_VERSION})
string (REGEX REPLACE "\\." ";" OPENVASLIBNASL_VERSION ${_OPENVASLIBNASL_VERSION_STR})

list(GET OPENVASLIBNASL_VERSION 0 OPENVASLIBNASL_MAJOR)
list(GET OPENVASLIBNASL_VERSION 1 OPENVASLIBNASL_MINOR)
list(GET OPENVASLIBNASL_VERSION 2 OPENVASLIBNASL_PATCH)

## CPack configuration

set (CPACK_CMAKE_GENERATOR "Unix Makefiles")
set (CPACK_GENERATOR "TGZ")
set (CPACK_INSTALL_CMAKE_PROJECTS ".;openvas-libraries/nasl;ALL;/")
set (CPACK_MODULE_PATH "")
set (CPACK_RESOURCE_FILE_LICENSE "../COPYING")
set (CPACK_SOURCE_GENERATOR "TGZ")
set (CPACK_SOURCE_TOPLEVEL_TAG "")
set (CPACK_SYSTEM_NAME "")
set (CPACK_TOPLEVEL_TAG "")
set (CPACK_PACKAGE_VERSION_MAJOR ${OPENVASLIBNASL_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${OPENVASLIBNASL_MINOR})
set (CPACK_PACKAGE_VERSION_PATCH ${OPENVASLIBNASL_PATCH})
set (CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
set (CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_PACKAGE_VENDOR "The OpenVAS Project")
set (CPACK_SOURCE_IGNORE_FILES
"/.svn/"
"/_CPack_Packages/"
"/CMakeFiles/"
"cmake$"
"swp$"
"Cache.txt$"
".tar.gz"
"install_manifest.txt"
"Makefile"
"/doc/generated/"
)

include (CPack)

## Variables

set (CMAKE_BUILD                Debug)
set (CMAKE_VERBOSE_MAKEFILE     ON)

if (NOT SYSCONFDIR)
  set (SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc")
endif (NOT SYSCONFDIR)

if (NOT EXEC_PREFIX)
  set (EXEC_PREFIX "${CMAKE_INSTALL_PREFIX}")
endif (NOT EXEC_PREFIX)

if (NOT BINDIR)
  set (BINDIR "${EXEC_PREFIX}/bin")
endif (NOT BINDIR)

if (NOT SBINDIR)
  set (SBINDIR "${EXEC_PREFIX}/sbin")
endif (NOT SBINDIR)

if (NOT LIBDIR)
  set (LIBDIR "${EXEC_PREFIX}/lib")
endif (NOT LIBDIR)

if (NOT LOCALSTATEDIR)
  set (LOCALSTATEDIR "${CMAKE_INSTALL_PREFIX}/var")
endif (NOT LOCALSTATEDIR)

if (NOT INCLUDEDIR)
  set (INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif (NOT INCLUDEDIR)

set (OPENVAS_STATE_DIR   "${LOCALSTATEDIR}/lib/openvas")
set (OPENVAS_LOG_DIR     "${LOCALSTATEDIR}/log/openvas")
set (OPENVAS_PID_DIR     "${LOCALSTATEDIR}/run")
set (OPENVAS_SYSCONF_DIR "${SYSCONFDIR}/openvas")

set (OPENVAS_LIB_INSTALL_DIR    "${LIBDIR}")
set (OPENVAS_HEADER_INSTALL_DIR "${INCLUDEDIR}")
set (OPENVAS_SERVER_CERTIFICATE "${OPENVAS_STATE_DIR}/CA/servercert.pem")
set (OPENVAS_SERVER_KEY         "${OPENVAS_STATE_DIR}/private/CA/serverkey.pem")
set (OPENVAS_CA_CERTIFICATE     "${OPENVAS_STATE_DIR}/CA/cacert.pem")

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")


## Config

exec_program (pkg-config
              ARGS --cflags glib-2.0
              OUTPUT_VARIABLE GLIB_CFLAGS)

## Library

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Wall")
# The "-D_FILE_OFFSET_BITS=64 -DLARGEFILE_SOURCE=1" is necessary for GPGME!
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -Wall -D_FILE_OFFSET_BITS=64 -DLARGEFILE_SOURCE=1")


## Compile the parser - note that there are (better) CMake macros to achieve
## that and that the user is not warned if bison is not installed
add_custom_command (
   COMMAND bison
   ARGS -d -v -t -p nasl nasl_grammar.y
   DEPENDS nasl_grammar.y
   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.tab.c
   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.tab.h
   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.output)

set (FILES capture_packet.c exec.c hmacmd5.c lint.c lsearch.c md5.c
     nasl_cmd_exec.c nasl_crypto2.c nasl_crypto.c nasl_debug.c nasl_func.c
     nasl_grammar.tab.c nasl_host.c nasl_http.c nasl_init.c nasl_lex_ctxt.c
     nasl_misc_funcs.c nasl_scanner_glue.c nasl_packet_forgery.c nasl_packet_forgery_v6.c
     nasl_signature.c nasl_smb.c nasl_socket.c nasl_text_utils.c nasl_tree.c
     nasl_var.c nasl_wmi.c preparse.c regex.c strutils.c smb_crypt.c smb_crypt2.c)

set (HEADERS nasl.h)

if (NOT HAVE_WMI)
  set (FILES smb_interface_stub.c wmi_interface_stub.c ${FILES})
else (NOT HAVE_WMI)
  set (WMI_LIBS -lwmiclient)
endif (NOT HAVE_WMI)


set_source_files_properties (nasl_grammar.tab.c GENERATED)

## Pass-throughs
add_definitions (-DOPENVAS_STATE_DIR=\\\"${OPENVAS_STATE_DIR}\\\")
add_definitions (-DVERSION=\\\"${_OPENVASLIBNASL_VERSION_STR}\\\")
add_definitions (-DOPENVAS_SYSCONFDIR=\\\"${OPENVAS_SYSCONF_DIR}\\\")

include_directories (../base)
include_directories (../hg)
include_directories (../misc)
include_directories (../include)

add_library (openvas_nasl_static STATIC ${FILES})

set_target_properties (openvas_nasl_static PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${WMI_LIBS}")
set_target_properties (openvas_nasl_static PROPERTIES OUTPUT_NAME "openvas_nasl")
set_target_properties (openvas_nasl_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_nasl_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
target_link_libraries (openvas_nasl_static libopenvas_base libopenvas_misc
			libopenvas_hg glib-2.0 gcrypt gpgme
			gpg-error gnutls pcap)

add_library (openvas_nasl_shared SHARED ${FILES})
set_target_properties (openvas_nasl_shared PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${WMI_LIBS}")
set_target_properties (openvas_nasl_shared PROPERTIES OUTPUT_NAME "openvas_nasl")
set_target_properties (openvas_nasl_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_nasl_shared PROPERTIES SOVERSION "${CPACK_PACKAGE_VERSION_MAJOR}")
set_target_properties (openvas_nasl_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
set_target_properties (openvas_nasl_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")
# line bellow is needed so it also works with no-undefined which is e.g. used by Mandriva
target_link_libraries (openvas_nasl_shared libopenvas_base libopenvas_misc
			libopenvas_hg glib-2.0 gcrypt gpgme
			gpg-error gnutls pcap)


# Find GLib
exec_program (pkg-config
              ARGS --cflags glib-2.0
              OUTPUT_VARIABLE GLIB_CFLAGS)
              # Find GLib and compile and link the openvas-nasl executable
exec_program (pkg-config
              ARGS --libs glib-2.0
              OUTPUT_VARIABLE GLIB_LDFLAGS)

# Add ("import") static libs from Make based subprojects of openvas-libraries
add_library (libopenvas_base SHARED IMPORTED)
add_library (libopenvas_hg SHARED IMPORTED)
add_library (libopenvas_misc SHARED IMPORTED)
set_property (TARGET libopenvas_misc PROPERTY
              IMPORTED_LOCATION ../misc/libopenvas_misc.so)
set_property (TARGET libopenvas_base PROPERTY
              IMPORTED_LOCATION ../base/libopenvas_base.so)
set_property (TARGET libopenvas_hg PROPERTY
              IMPORTED_LOCATION ../hg/libopenvas_hg.so)

# Link the openvas-nasl executable
add_executable (openvas-nasl nasl.c)
target_link_libraries (openvas-nasl openvas_nasl_static libopenvas_base
                       libopenvas_misc libopenvas_hg ${GLIB_LDFLAGS} -lgcrypt
                       -lgpgme -lgpg-error -lgnutls -lpcap -lresolv)
set_target_properties (openvas-nasl PROPERTIES COMPILE_FLAGS
                       ${GLIB_CFLAGS})
set_target_properties (openvas-nasl PROPERTIES LINK_FLAGS
                       ${GLIB_LDFLAGS})

## Install

install (TARGETS openvas_nasl_static openvas_nasl_shared openvas-nasl
         RUNTIME DESTINATION ${BINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR}
         PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/nasl")

## Documentation

#add_subdirectory (doc)

## Tests

#ENABLE_TESTING ()

#add_subdirectory (tests)

## End
