# OpenVAS
# $Id$
# Description: Top-level cmake control for the Libraries.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2011, 2012 Greenbone Networks GmbH
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
  if (EXISTS ".svn/")
    if (SVN_EXECUTABLE)
      Subversion_GET_REVISION(. ProjectRevision)
      set (SVN_REVISION ".SVN.r${ProjectRevision}")
    else (SVN_EXECUTABLE)
      set (SVN_REVISION ".SVN")
    endif (SVN_EXECUTABLE)
  endif (EXISTS ".svn/")
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
set (CPACK_PACKAGE_VERSION_MAJOR "5")
set (CPACK_PACKAGE_VERSION_MINOR "0")
set (CPACK_PACKAGE_VERSION_PATCH "+rc2${SVN_REVISION}")
set (CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}${CPACK_PACKAGE_VERSION_PATCH}")
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

set (OPENVAS_USERS_DIR   "${OPENVAS_STATE_DIR}/users")
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

pkg_check_modules (GNUTLS REQUIRED gnutls>=2.2)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.12)
pkg_check_modules (WMICLIENT wmiclient>=1.3.14)
pkg_check_modules (LIBSSH libssh>=0.4.5)

message (STATUS "Looking for pcap...")
find_library (PCAP pcap)
message (STATUS "Looking for pcap... ${PCAP}")
if (NOT PCAP)
  message (FATAL_ERROR "The pcap library is required.")
endif (NOT PCAP)

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

execute_process (COMMAND pkg-config --cflags glib-2.0
  OUTPUT_VARIABLE GLIB_CFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process (COMMAND pkg-config --libs glib-2.0
  OUTPUT_VARIABLE GLIB_LDFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)

if (NOT BUILD_WITHOUT_LDAP)
  message (STATUS "Looking for libldap...")

  find_library (LIBLDAP ldap2)
  if (NOT LIBLDAP)
    find_library (LIBLDAP ldap)
  endif (NOT LIBLDAP)
  if (NOT LIBLDAP)
    message (STATUS "  No ldap library found - ldap support disabled")
  else (NOT LIBLDAP)
    message (STATUS "  Found ${LIBLDAP} - ldap support enabled")
    add_definitions (-DENABLE_LDAP_AUTH=1)
    set (BUILD_WITH_LDAP TRUE)
  endif (NOT LIBLDAP)
else (NOT BUILD_WITHOUT_LDAP)
  message (STATUS "Disabled ldap via configuration option")
endif (NOT BUILD_WITHOUT_LDAP)

if (NOT LIBSSH_FOUND)
  message (STATUS "Did not find libssh via pkg-config, trying alternative approach ...")
  set (LibSSH_FIND_VERSION TRUE)
  if (LIBSSH_LIBRARIES AND LIBSSH_INCLUDE_DIRS)
    # in cache already
    set(LIBSSH_FOUND TRUE)
  else (LIBSSH_LIBRARIES AND LIBSSH_INCLUDE_DIRS)

    find_path(LIBSSH_INCLUDE_DIR
      NAMES
      libssh/libssh.h
      PATHS
      /usr/include
      /usr/local/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
      )

    find_library(SSH_LIBRARY
      NAMES
      ssh
      libssh
      PATHS
      /usr/lib
      /usr/local/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
      )

    if (LIBSSH_INCLUDE_DIR AND SSH_LIBRARY)
      set(LIBSSH_FOUND TRUE)
    endif (LIBSSH_INCLUDE_DIR AND SSH_LIBRARY)

    set(LIBSSH_INCLUDE_DIRS
      ${LIBSSH_INCLUDE_DIR}
      )

    if (LIBSSH_FOUND)
      set(LIBSSH_LIBRARIES
        ${LIBSSH_LIBRARIES}
        ${SSH_LIBRARY}
        )

      if (LibSSH_FIND_VERSION)
        file(STRINGS ${LIBSSH_INCLUDE_DIR}/libssh/libssh.h LIBSSH_VERSION_MAJOR
          REGEX "#define[ ]+LIBSSH_VERSION_MAJOR[ ]+[0-9]+")

        # Older versions of libssh like libssh-0.2 have LIBSSH_VERSION but not LIBSSH_VERSION_MAJOR
        if (LIBSSH_VERSION_MAJOR)
          string(REGEX MATCH "[0-9]+" LIBSSH_VERSION_MAJOR ${LIBSSH_VERSION_MAJOR})
          file(STRINGS ${LIBSSH_INCLUDE_DIR}/libssh/libssh.h LIBSSH_VERSION_MINOR
            REGEX "#define[ ]+LIBSSH_VERSION_MINOR[ ]+[0-9]+")
          string(REGEX MATCH "[0-9]+" LIBSSH_VERSION_MINOR ${LIBSSH_VERSION_MINOR})
          file(STRINGS ${LIBSSH_INCLUDE_DIR}/libssh/libssh.h LIBSSH_VERSION_PATCH
            REGEX "#define[ ]+LIBSSH_VERSION_MICRO[ ]+[0-9]+")
          string(REGEX MATCH "[0-9]+" LIBSSH_VERSION_PATCH ${LIBSSH_VERSION_PATCH})

          set(LIBSSH_VERSION ${LIBSSH_VERSION_MAJOR}.${LIBSSH_VERSION_MINOR}.${LIBSSH_VERSION_PATCH})

        else (LIBSSH_VERSION_MAJOR)
          set(LIBSSH_FOUND FALSE)
        endif (LIBSSH_VERSION_MAJOR)
      endif (LibSSH_FIND_VERSION)
    endif (LIBSSH_FOUND)

    # If the version is too old, but libs and includes are set,
    # find_package_handle_standard_args will set LIBSSH_FOUND to TRUE again,
    # so we need this if() here.
    if (LIBSSH_FOUND)
      include(FindPackageHandleStandardArgs)
      find_package_handle_standard_args(LibSSH DEFAULT_MSG LIBSSH_LIBRARIES LIBSSH_INCLUDE_DIRS)
    endif (LIBSSH_FOUND)

    # show the LIBSSH_INCLUDE_DIRS and LIBSSH_LIBRARIES variables only in the advanced view
    mark_as_advanced(LIBSSH_INCLUDE_DIRS LIBSSH_LIBRARIES)

  endif (LIBSSH_LIBRARIES AND LIBSSH_INCLUDE_DIRS)
  if (LIBSSH_FOUND)
    message (STATUS "Found libssh ${LIBSSH_VERSION}.")
  else (LIBSSH_FOUND)
    message (STATUS "Did not find libssh.")
  endif (LIBSSH_FOUND)
else (NOT LIBSSH_FOUND)
  execute_process (COMMAND pkg-config --cflags libssh
    OUTPUT_VARIABLE LIBSSH_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND pkg-config --libs libssh
    OUTPUT_VARIABLE LIBSSH_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  set (LIBSSH_PKGCONFIG TRUE)
endif (NOT LIBSSH_FOUND)

if (LIBSSH_FOUND AND NOT LIBSSH_PKGCONFIG)
  if (NOT LIBSSH_CFLAGS)
    set (LIBSSH_CFLAGS "-I${LIBSSH_INCLUDE_DIRS}")
  endif (NOT LIBSSH_CFLAGS)
  if (NOT LIBSSH_LDFLAGS)
    get_filename_component (LIBSSH_LIB_DIR ${LIBSSH_LIBRARIES} PATH)
    set (LIBSSH_LDFLAGS "-L${LIBSSH_LIB_DIR} -lssh")
  endif (NOT LIBSSH_LDFLAGS)
endif (LIBSSH_FOUND AND NOT LIBSSH_PKGCONFIG)

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
configure_file (doc/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/doc/Doxyfile @ONLY)
configure_file (doc/Doxyfile_full.in ${CMAKE_CURRENT_BINARY_DIR}/doc/Doxyfile_full @ONLY)
configure_file (VERSION.in ${CMAKE_CURRENT_BINARY_DIR}/VERSION @ONLY)
configure_file (libopenvas.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libopenvas.pc @ONLY)

## Program

set (HARDENING_FLAGS            "-Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector -Wl,-z,relro -Wl,-z,now")

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG}")
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} ${HARDENING_FLAGS} -Wall -Werror")

add_subdirectory (base)
add_subdirectory (misc)
add_subdirectory (hg)
add_subdirectory (nasl)
add_subdirectory (omp)

## Documentation

add_subdirectory (doc)

## Install

install (FILES doc/openvas-nasl.1
         DESTINATION ${DATADIR}/man/man1 )

install (FILES ${CMAKE_CURRENT_BINARY_DIR}/libopenvas.pc
         DESTINATION ${LIBDIR}/pkgconfig)

install (FILES ${CMAKE_SOURCE_DIR}/openvas-services DESTINATION ${OPENVAS_DATA_DIR}
         PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)

install (FILES ${CMAKE_SOURCE_DIR}/tools/openvas-lsc-rpm-creator.sh
         DESTINATION ${OPENVAS_DATA_DIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE
                     WORLD_READ WORLD_EXECUTE)

install (DIRECTORY DESTINATION ${OPENVAS_USERS_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_LOG_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_DATA_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_CACHE_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_PID_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_NVT_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_SYSCONF_DIR})

## Tests

enable_testing ()

## End
