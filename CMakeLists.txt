# OpenVAS
# $Id$
# Description: Top-level cmake control for the Libraries.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2011-2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

cmake_minimum_required(VERSION 2.8)

include (openvas_cmake_macros)

message ("-- Configuring the Libraries...")

project (openvas-libraries C)

if (POLICY CMP0005)
  cmake_policy (SET CMP0005 OLD)
endif (POLICY CMP0005)

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Debug)
endif (NOT CMAKE_BUILD_TYPE)

OPTION(OPENVAS_OMP_ONLY "Build only the omp library and the required base and misc libraries" OFF)
OPTION(BUILD_STATIC "Build static versions of the openvas libraries" OFF)

if (NOT BUILD_STATIC)
  set (BUILD_SHARED ON)
else (NOT BUILD_STATIC)
  set (BUILD_SHARED OFF)
endif (NOT BUILD_STATIC)

## Retrieve svn revision (at configure time)
#  Not using Subversion_WC_INFO, as it would have to connect to the repo
find_program (SVN_EXECUTABLE svn DOC "subversion command line client")

macro (Subversion_GET_REVISION dir variable)
  execute_process (COMMAND ${SVN_EXECUTABLE} info ${CMAKE_SOURCE_DIR}/${dir}
    OUTPUT_VARIABLE ${variable}
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  string (REGEX REPLACE "^(.*\n)?Revision: ([^\n]+).*"
    "\\2" ${variable} "${${variable}}")
endmacro (Subversion_GET_REVISION)

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
  if (EXISTS "${CMAKE_SOURCE_DIR}/.svn/")
    if (SVN_EXECUTABLE)
      Subversion_GET_REVISION(. ProjectRevision)
      set (SVN_REVISION "~svn${ProjectRevision}")
    else (SVN_EXECUTABLE)
      set (SVN_REVISION "~svn")
    endif (SVN_EXECUTABLE)
  endif (EXISTS "${CMAKE_SOURCE_DIR}/.svn/")
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

# TODO: Check pkg-config (maybe with code like in gsa/CMakeLists.txt).

## CPack configuration

set (CPACK_CMAKE_GENERATOR "Unix Makefiles")
set (CPACK_GENERATOR "TGZ")
set (CPACK_INSTALL_CMAKE_PROJECTS ".;openvas-libraries;ALL;/")
set (CPACK_MODULE_PATH "")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/COPYING")
set (CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README")
set (CPACK_RESOURCE_FILE_WELCOME "${CMAKE_SOURCE_DIR}/README")
set (CPACK_SOURCE_GENERATOR "TGZ")
set (CPACK_SOURCE_TOPLEVEL_TAG "")
set (CPACK_SYSTEM_NAME "")
set (CPACK_TOPLEVEL_TAG "")
set (CPACK_PACKAGE_VERSION_MAJOR "9")
set (CPACK_PACKAGE_VERSION_MINOR "0")

# Use this scheme for stable releases:
set (CPACK_PACKAGE_VERSION_PATCH "2${SVN_REVISION}")
set (CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
# Use this scheme for +betaN and +rcN releases:
#set (CPACK_PACKAGE_VERSION_PATCH "+beta1${SVN_REVISION}")
#set (CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}${CPACK_PACKAGE_VERSION_PATCH}")

set (CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_PACKAGE_VENDOR "The OpenVAS Project")
set (CPACK_SOURCE_IGNORE_FILES
"${CMAKE_BINARY_DIR}"
"/.svn/"
"swp$"
"nasl/nasl_grammar.tab.c"
"nasl/nasl_grammar.tab.h"
"nasl/nasl_grammar.output"
)

include (CPack)

## Variables

if (SYSCONF_INSTALL_DIR)
  set (SYSCONFDIR "${SYSCONF_INSTALL_DIR}")
endif (SYSCONF_INSTALL_DIR)

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
  set (_DEFAULT_LIBRARY_INSTALL_DIR lib)
  if (EXISTS "${EXEC_PREFIX}/lib32/" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
    set (_DEFAULT_LIBRARY_INSTALL_DIR lib32)
  endif (EXISTS "${EXEC_PREFIX}/lib32/" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
  if (EXISTS "${CMAKE_INSTALL_PREFIX}/lib64/" AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    set (_DEFAULT_LIBRARY_INSTALL_DIR lib64)
  endif (EXISTS "${CMAKE_INSTALL_PREFIX}/lib64/" AND CMAKE_SIZEOF_VOID_P EQUAL 8)
  set( LIBRARY_INSTALL_DIR "${_DEFAULT_LIBRARY_INSTALL_DIR}")
  set (LIBDIR "${EXEC_PREFIX}/${LIBRARY_INSTALL_DIR}")
endif (NOT LIBDIR)

if (NOT LOCALSTATEDIR)
  set (LOCALSTATEDIR "${CMAKE_INSTALL_PREFIX}/var")
endif (NOT LOCALSTATEDIR)

if (NOT INCLUDEDIR)
  set (INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif (NOT INCLUDEDIR)

if (NOT DATADIR)
  set (DATADIR "${CMAKE_INSTALL_PREFIX}/share")
endif (NOT DATADIR)

if (NOT OPENVAS_PID_DIR)
  set (OPENVAS_PID_DIR "${LOCALSTATEDIR}/run")
endif (NOT OPENVAS_PID_DIR)

#if (NOT SYSCONFDIR)
#  set (SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc")
#endif (NOT SYSCONFDIR)

set (OPENVAS_DATA_DIR    "${DATADIR}/openvas")
set (OPENVAS_STATE_DIR   "${LOCALSTATEDIR}/lib/openvas")
set (OPENVAS_LOG_DIR     "${LOCALSTATEDIR}/log/openvas")
set (OPENVAS_CACHE_DIR   "${LOCALSTATEDIR}/cache/openvas")
set (OPENVAS_SYSCONF_DIR "${SYSCONFDIR}/openvas")

set (OPENVAS_LIB_INSTALL_DIR     "${LIBDIR}")

set (OPENVAS_HEADER_INSTALL_DIR "${INCLUDEDIR}")
add_definitions (-DOPENVASSD_CONF=\\\"${OPENVAS_SYSCONF_DIR}/openvassd.conf\\\")

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")

## Dependency checks
##
## TODO Also check for headers where needed.

pkg_check_modules (GNUTLS REQUIRED gnutls>=3.2.15)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.32)
if (NOT OPENVAS_OMP_ONLY)
  pkg_check_modules (OPENVAS_WMICLIENT libopenvas_wmiclient>=1.0.1)
  pkg_check_modules (OPENVAS_WINCMD libopenvas_wincmd>=1.0.1)
  pkg_check_modules (LIBSSH REQUIRED libssh>=0.5.0)

  message (STATUS "Looking for pcap...")
  find_library (PCAP pcap)
  message (STATUS "Looking for pcap... ${PCAP}")
  if (NOT PCAP)
    message (SEND_ERROR "The pcap library is required.")
  endif (NOT PCAP)

  message (STATUS "Looking for pcap-config...")
  find_program (PCAP_CONFIG pcap-config)

  if (PCAP_CONFIG)
    message (STATUS "Looking for pcap-config... ${PCAP_CONFIG}")
    execute_process (COMMAND pcap-config --libs
      OUTPUT_VARIABLE PCAP_LDFLAGS
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process (COMMAND pcap-config --cflags
      OUTPUT_VARIABLE PCAP_CFLAGS
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  else (PCAP_CONFIG)
    message (STATUS "pcap-config not found, using defaults...")
    set (PCAP_LDFLAGS "-L/usr/lib -lpcap")
    set (PCAP_CFLAGS "-I/usr/include")
  endif (PCAP_CONFIG)
endif (NOT OPENVAS_OMP_ONLY)

if (NOT MINGW)
  # TODO: We do not have a library lookup for those modules
  # which also works when cross compiling. Library names
  # are hardcoded in the corresponding linker commands.
  message (STATUS "Looking for gpgme...")
  find_library (GPGME gpgme)
  message (STATUS "Looking for gpgme... ${GPGME}")
  if (NOT GPGME)
    message (SEND_ERROR "The gpgme library is required.")
  endif (NOT GPGME)

  execute_process (COMMAND gpgme-config --libs
    OUTPUT_VARIABLE GPGME_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND gpgme-config --cflags
    OUTPUT_VARIABLE GPGME_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  message (STATUS "Looking for netsnmp...")
  find_library (SNMP snmp)
  message (STATUS "Looking for netsnmp... ${SNMP}")
  if (SNMP)
    execute_process (COMMAND net-snmp-config --libs
      OUTPUT_VARIABLE SNMP_LDFLAGS
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif (SNMP)

  message (STATUS "Looking for libgcrypt...")
  find_library (GCRYPT gcrypt)
  message (STATUS "Looking for libgcrypt... ${GCRYPT}")
  if (NOT GCRYPT)
    message (SEND_ERROR "The libgcrypt library is required.")
  else (NOT GCRYPT)
    execute_process (COMMAND libgcrypt-config --libs
      OUTPUT_VARIABLE GCRYPT_LDFLAGS
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process (COMMAND libgcrypt-config --cflags
      OUTPUT_VARIABLE GCRYPT_CFLAGS
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif (NOT GCRYPT)

endif (NOT MINGW)

set (HARDENING_FLAGS "-Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector")
set (LINKER_HARDENING_FLAGS "-Wl,-z,relro -Wl,-z,now")
set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Werror")


## Version

string (REPLACE "
" "" OPENVASLIB_VERSION ${CPACK_PACKAGE_VERSION})

string(SUBSTRING ${CPACK_PACKAGE_VERSION_PATCH} 0 1 BETA_INDICATOR)
if (BETA_INDICATOR MATCHES "^\\+")
  set (LIBOPENVASCONFIG_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.0")
else (BETA_INDICATOR MATCHES "^\\+")
  set (LIBOPENVASCONFIG_VERSION "${OPENVASLIB_VERSION}")
endif (BETA_INDICATOR MATCHES "^\\+")

# Configure Doxyfile with version number
configure_file (doc/Doxyfile.in ${CMAKE_BINARY_DIR}/doc/Doxyfile @ONLY)
configure_file (doc/Doxyfile_full.in ${CMAKE_BINARY_DIR}/doc/Doxyfile_full @ONLY)
configure_file (VERSION.in ${CMAKE_BINARY_DIR}/VERSION @ONLY)
configure_file (libopenvas_base.pc.in ${CMAKE_BINARY_DIR}/libopenvas_base.pc @ONLY)
configure_file (libopenvas_omp.pc.in ${CMAKE_BINARY_DIR}/libopenvas_omp.pc @ONLY)
configure_file (libopenvas_misc.pc.in ${CMAKE_BINARY_DIR}/libopenvas_misc.pc @ONLY)
configure_file (libopenvas_nasl.pc.in ${CMAKE_BINARY_DIR}/libopenvas_nasl.pc @ONLY)
configure_file (libopenvas_osp.pc.in ${CMAKE_BINARY_DIR}/libopenvas_osp.pc @ONLY)

## Program

add_subdirectory (base)
add_subdirectory (misc)
if (NOT OPENVAS_OMP_ONLY)
  add_subdirectory (nasl)
endif (NOT OPENVAS_OMP_ONLY)
add_subdirectory (omp)
add_subdirectory (osp)

## Documentation

add_subdirectory (doc)

## Install

install (FILES doc/openvas-nasl.1
         DESTINATION ${DATADIR}/man/man1 )
install (FILES doc/openvas-nasl-lint.1
         DESTINATION ${DATADIR}/man/man1 )

install (FILES ${CMAKE_BINARY_DIR}/libopenvas_base.pc
         DESTINATION ${LIBDIR}/pkgconfig)
install (FILES ${CMAKE_BINARY_DIR}/libopenvas_omp.pc
         DESTINATION ${LIBDIR}/pkgconfig)
install (FILES ${CMAKE_BINARY_DIR}/libopenvas_misc.pc
         DESTINATION ${LIBDIR}/pkgconfig)
install (FILES ${CMAKE_BINARY_DIR}/libopenvas_nasl.pc
         DESTINATION ${LIBDIR}/pkgconfig)
install (FILES ${CMAKE_BINARY_DIR}/libopenvas_osp.pc
         DESTINATION ${LIBDIR}/pkgconfig)

install (DIRECTORY DESTINATION ${OPENVAS_LOG_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_DATA_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_CACHE_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_PID_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_SYSCONF_DIR})
install (DIRECTORY
  DESTINATION ${OPENVAS_SYSCONF_DIR}/gnupg
  DIRECTORY_PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE)
install (DIRECTORY
  DESTINATION ${OPENVAS_STATE_DIR}/gnupg
  DIRECTORY_PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE)

## Tests

enable_testing ()

## End
