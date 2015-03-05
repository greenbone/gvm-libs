# OpenVAS
# $Id$
# Description: Top-level cmake control for the Libraries.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2011-2014 Greenbone Networks GmbH
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

cmake_minimum_required(VERSION 2.6)

include (openvas_cmake_macros)

message ("-- Configuring the Libraries...")

project (openvas-libraries C)

cmake_minimum_required (VERSION 2.6)

if (POLICY CMP0005)
  cmake_policy (SET CMP0005 OLD)
endif (POLICY CMP0005)

include (FindPkgConfig)

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
      set (SVN_REVISION ".SVN.r${ProjectRevision}")
    else (SVN_EXECUTABLE)
      set (SVN_REVISION ".SVN")
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
set (CPACK_PACKAGE_VERSION_MAJOR "7")
set (CPACK_PACKAGE_VERSION_MINOR "0")

# Use this scheme for stable releases:
set (CPACK_PACKAGE_VERSION_PATCH "10${SVN_REVISION}")
set (CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
# Use this scheme for +betaN and +rcN releases:
#set (CPACK_PACKAGE_VERSION_PATCH "+beta1${SVN_REVISION}")
#set (CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}${CPACK_PACKAGE_VERSION_PATCH}")

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
"log.conf$"
"Doxyfile$"
"Doxyfile_full$"
"VERSION$"
"libopenvas.pc$"
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

#if (NOT SYSCONFDIR)
#  set (SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc")
#endif (NOT SYSCONFDIR)

set (OPENVAS_DATA_DIR    "${DATADIR}/openvas")
set (OPENVAS_STATE_DIR   "${LOCALSTATEDIR}/lib/openvas")
set (OPENVAS_LOG_DIR     "${LOCALSTATEDIR}/log/openvas")
set (OPENVAS_CACHE_DIR   "${LOCALSTATEDIR}/cache/openvas")
set (OPENVAS_PID_DIR     "${LOCALSTATEDIR}/run")
set (OPENVAS_SYSCONF_DIR "${SYSCONFDIR}/openvas")

set (OPENVAS_NVT_DIR     "${OPENVAS_STATE_DIR}/plugins")

set (OPENVAS_LIB_INSTALL_DIR     "${LIBDIR}")

set (OPENVAS_HEADER_INSTALL_DIR "${INCLUDEDIR}")
set (OPENVAS_SERVER_CERTIFICATE "${OPENVAS_STATE_DIR}/CA/servercert.pem")
set (OPENVAS_SERVER_KEY         "${OPENVAS_STATE_DIR}/private/CA/serverkey.pem")
set (OPENVAS_CA_CERTIFICATE     "${OPENVAS_STATE_DIR}/CA/cacert.pem")

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")

## Dependency checks
##
## TODO Also check for headers where needed.
## Improve for workflow: First collect list of missing libs, then print the
## list and throw an error, otherwise long install-cmake-install-cmake cycles
## might occur.

pkg_check_modules (GNUTLS REQUIRED gnutls>=2.12)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.16)
if (NOT OPENVAS_OMP_ONLY)
  pkg_check_modules (WMICLIENT wmiclient>=1.3.14)
  pkg_check_modules (WINCMD wincmd>=0.80)
  pkg_check_modules (LIBSSH libssh>=0.5.0)

  message (STATUS "Looking for pcap...")
  find_library (PCAP pcap)
  message (STATUS "Looking for pcap... ${PCAP}")
  if (NOT PCAP)
    message (FATAL_ERROR "The pcap library is required.")
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

execute_process (COMMAND pkg-config --cflags glib-2.0
  OUTPUT_VARIABLE GLIB_CFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process (COMMAND pkg-config --libs glib-2.0
  OUTPUT_VARIABLE GLIB_LDFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process (COMMAND pkg-config --cflags gnutls
  OUTPUT_VARIABLE GNUTLS_CFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process (COMMAND pkg-config --libs gnutls
  OUTPUT_VARIABLE GNUTLS_LDFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)


if (NOT MINGW)
  # TODO: We do not have a library lookup for those modules
  # which also works when cross compiling. Library names
  # are hardcoded in the corresponding linker commands.
  message (STATUS "Looking for gpgme...")
  find_library (GPGME gpgme)
  message (STATUS "Looking for gpgme... ${GPGME}")
  if (NOT GPGME)
    message (FATAL_ERROR "The gpgme library is required.")
  endif (NOT GPGME)

  execute_process (COMMAND gpgme-config --libs
    OUTPUT_VARIABLE GPGME_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND gpgme-config --cflags
    OUTPUT_VARIABLE GPGME_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  message (STATUS "Looking for ksba...")
  find_library (KSBA ksba)
  message (STATUS "Looking for ksba... ${KSBA}")

  execute_process (COMMAND ksba-config --libs
    OUTPUT_VARIABLE KSBA_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND ksba-config --cflags
    OUTPUT_VARIABLE KSBA_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  execute_process (COMMAND libgcrypt-config --libs
    OUTPUT_VARIABLE GCRYPT_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND libgcrypt-config --cflags
    OUTPUT_VARIABLE GCRYPT_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)

endif (NOT MINGW)

set (EXTRA_LIBS "${GPGME_LDFLAGS}")
set (EXTRA_CFLAGS "${GPGME_CFLAGS}")

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
configure_file (libopenvas.pc.in ${CMAKE_BINARY_DIR}/libopenvas.pc @ONLY)

## Program

add_subdirectory (base)
add_subdirectory (misc)
if (NOT OPENVAS_OMP_ONLY)
  add_subdirectory (nasl)
endif (NOT OPENVAS_OMP_ONLY)
add_subdirectory (omp)

## Documentation

add_subdirectory (doc)

## Install

install (FILES doc/openvas-nasl.1
         DESTINATION ${DATADIR}/man/man1 )

install (FILES ${CMAKE_BINARY_DIR}/libopenvas.pc
         DESTINATION ${LIBDIR}/pkgconfig)

install (DIRECTORY DESTINATION ${OPENVAS_LOG_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_DATA_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_CACHE_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_PID_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_NVT_DIR})
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
