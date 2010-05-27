# OpenVAS-libraries/misc
# $Id$
# Description: Makefile for misc of OpenVAS-libraries.
#
# Authors:
# Matthew Mundell <matthew.mundell@intevation.de>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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

message ("-- Configure OpenVAS-libraries/misc...")

project (openvas-libraries/misc C)

cmake_minimum_required (VERSION 2.6)

if (POLICY CMP0005)
   cmake_policy (SET CMP0005 OLD)
endif (POLICY CMP0005)

set (CMAKE_BUILD_TYPE debug)

# Version
file (READ ../VERSION  _OPENVASLIBMISC_VERSION)

string (REGEX REPLACE "\\\n" "." _OPENVASLIBMISC_VERSION_STR ${_OPENVASLIBMISC_VERSION})
string (REGEX REPLACE "\\." ";" OPENVASLIBMISC_VERSION ${_OPENVASLIBMISC_VERSION_STR})

list (GET OPENVASLIBMISC_VERSION 0 OPENVASLIBMISC_MAJOR)
list (GET OPENVASLIBMISC_VERSION 1 OPENVASLIBMISC_MINOR)
list (GET OPENVASLIBMISC_VERSION 2 OPENVASLIBMISC_PATCH)

## CPack configuration

set (CPACK_CMAKE_GENERATOR "Unix Makefiles")
set (CPACK_GENERATOR "TGZ")
set (CPACK_INSTALL_CMAKE_PROJECTS ".;openvas-libraries/misc;ALL;/")
set (CPACK_MODULE_PATH "")
set (CPACK_RESOURCE_FILE_LICENSE "../COPYING")
set (CPACK_RESOURCE_FILE_README "README.txt")
set (CPACK_RESOURCE_FILE_WELCOME "README.txt")
set (CPACK_SOURCE_GENERATOR "TGZ")
set (CPACK_SOURCE_TOPLEVEL_TAG "")
set (CPACK_SYSTEM_NAME "")
set (CPACK_TOPLEVEL_TAG "")
set (CPACK_PACKAGE_VERSION_MAJOR ${OPENVASLIBMISC_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${OPENVASLIBMISC_MINOR})
set (CPACK_PACKAGE_VERSION_PATCH ${OPENVASLIBMISC_PATCH})
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
message ("-- Variables will set...")

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
set (OPENVAS_USERS_DIR           "${OPENVAS_STATE_DIR}/users/")

set (OPENVAS_LIB_INSTALL_DIR    "${LIBDIR}")
set (OPENVAS_HEADER_INSTALL_DIR "${INCLUDEDIR}")
set (OPENVAS_SERVER_CERTIFICATE "${OPENVAS_STATE_DIR}/CA/servercert.pem")
set (OPENVAS_SERVER_KEY         "${OPENVAS_STATE_DIR}/private/CA/serverkey.pem")
set (OPENVAS_CA_CERTIFICATE     "${OPENVAS_STATE_DIR}/CA/cacert.pem")

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")

## Pass-throughs

include_directories (../include)
include_directories (../base)

if (MINGW)
  if (CROSS_ENV)
    include_directories (${CROSS_ENV}/include)
    include_directories (${CROSS_ENV}/include/glib-2.0)
    include_directories (${CROSS_ENV}/lib/glib-2.0/include)
  else (CROSS_ENV)
    message (FATAL_ERROR "Could not find include path for WIN32. Consider"
             " building with -DCROSS_ENV=path/to win32/environment")
  endif (CROSS_ENV)
endif (MINGW)

## Config

exec_program (pkg-config
              ARGS --cflags glib-2.0
              OUTPUT_VARIABLE GLIB_CFLAGS)

if (NOT MINGW)
  message (STATUS "Looking for uuid...")
  find_library (UUID uuid)
  message (STATUS "Looking for uuid... ${UUID}")
  if (NOT UUID)
    message (FATAL_ERROR "The uuid library is required.")
  endif (NOT UUID)
endif (NOT MINGW)

# Check for openldap if -DBUILD_WITH_LDAP=ON was given
if (NOT BUILD_WITH_LDAP)
   # fine
else (NOT BUILD_WITH_LDAP)
   message (STATUS "Looking for openldap...")
   find_library (OPENLDAP ldap2)
   if (NOT OPENLDAP)
     find_library (OPENLDAP ldap)
   endif (NOT OPENLDAP)
   message (STATUS "Looking for openldap... ${OPENLDAP}")
   if (NOT OPENLDAP)
     message (FATAL_ERROR "Could not build with ldap support - no ldap library"
              " was found. Consider building with -DBUILD_WITH_LDAP=OFF")
   endif (NOT OPENLDAP)
   add_definitions (-DENABLE_LDAP_AUTH=1)
endif (NOT BUILD_WITH_LDAP)

# Library

message ("-- prepare for add libraries ...")
set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Wall -fPIC")
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -Wall -fPIC")

if (MINGW)
  set (FILES openvas_auth.c openvas_server.c proctitle.c)
  set (HEADERS proctitle.h openvas_auth.h openvas_server.h share_fd.h)
else (MINGW)
  set (FILES arglists.c bpf_share.c ftp_funcs.c harglists.c hash_table_file.c
             hlst.c ids_send.c kb.c network.c openvas_auth.c openvas_logging.c
             openvas_server.c openvas_ssh_login.c openvas_uuid.c plugutils.c
             popen.c proctitle.c
             rand.c resolve.c scanners_utils.c services1.c services.c share_fd.c
             store.c system.c www_funcs.c pcap.c)

  set (HEADERS arglists.h bpf_share.h ftp_funcs.h hash_table_file.h kb.h
               network.h otp.h pcap_openvas.h plugutils.h popen.h proctitle.h
               rand.h resolve.h openvas_auth.h openvas_logging.h
               openvas_server.h openvas_ssh_login.h openvas_uuid.h
               scanners_utils.h services1.h
               share_fd.h store.h system.h www_funcs.h)
endif (MINGW)

if (BUILD_WITH_LDAP)
  list (APPEND FILES ldap_auth.c ads_auth.c)
endif (BUILD_WITH_LDAP)

link_directories (${CMAKE_CURRENT_SOURCE_DIR}/../base)

add_library (openvas_misc_static STATIC ${FILES})

set_target_properties (openvas_misc_static PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS}")
set_target_properties (openvas_misc_static PROPERTIES OUTPUT_NAME "openvas_misc")
set_target_properties (openvas_misc_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_misc_static PROPERTIES PUBLIC_HEADER "${HEADERS}")

add_library (openvas_misc_shared SHARED ${FILES})

set_target_properties (openvas_misc_shared PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS}")
set_target_properties (openvas_misc_shared PROPERTIES OUTPUT_NAME "openvas_misc")
set_target_properties (openvas_misc_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_misc_shared PROPERTIES SOVERSION "${CPACK_PACKAGE_VERSION_MAJOR}")
set_target_properties (openvas_misc_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
set_target_properties (openvas_misc_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")
if (NOT MINGW)
  target_link_libraries (openvas_misc_shared glib-2.0 pcap gnutls gcrypt openvas_base)
endif (NOT MINGW)
if (OPENVAS_USERS_DIR)
  add_definitions (-DOPENVAS_USERS_DIR=\\\"${OPENVAS_USERS_DIR}\\\")
endif (OPENVAS_USERS_DIR)

if (OPENVAS_STATE_DIR)
  add_definitions (-DOPENVAS_STATE_DIR=\\\"${OPENVAS_STATE_DIR}\\\")
endif (OPENVAS_STATE_DIR)

#$(COMPILE) -DOPENVAS_STATE_DIR=\"$(localstatedir)\" -DCONF_DIR=\"$(sysconfdir)\" -c services1.c
if (OPENVAS_SYSCONF_DIR)
  add_definitions (-DONF_DIR=\\\"${OPENVAS_SYSCONF_DIR}\\\")
endif (OPENVAS_SYSCONF_DIR)

if (MINGW)
  target_link_libraries (openvas_misc_static uuid openvas_base ${GLIB_LDFLAGS} -lglib-2.0
                         -lgcrypt -lgnutls -lintl -liconv -lgpg-error -lws2_32
                         -lole32 -lz)
  target_link_libraries (openvas_misc_shared uuid openvas_base ${GLIB_LDFLAGS} -lglib-2.0
                         -lgcrypt -lgnutls -lintl -liconv -lgpg-error -lws2_32
                         -lole32 -lz)
else (MINGW)
  if (NOT BUILD_WITH_LDAP)
    target_link_libraries (openvas_misc_static uuid ${GLIB_LDFLAGS})
    target_link_libraries (openvas_misc_shared uuid ${GLIB_LDFLAGS})
  else (NOT BUILD_WITH_LDAP)
    target_link_libraries (openvas_misc_static uuid ${GLIB_LDFLAGS} ldap)
    target_link_libraries (openvas_misc_shared uuid ${GLIB_LDFLAGS} ldap)
  endif (NOT BUILD_WITH_LDAP)
endif (MINGW)

# install library
message ("-- installing libraries...")
install (TARGETS openvas_misc_static openvas_misc_shared
         RUNTIME DESTINATION ${BINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR}
         PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas")
