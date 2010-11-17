# openvas-libraries/omp
# $Id$
# Description: Top-level cmake control for the OMP library.
#
# Authors:
# Matthew Mundell <matthew.mundell@intevation.de>
#
# Copyright:
# Copyright (C) 2009,2010 Greenbone Networks GmbH
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

message ("-- Configuring openvas-libraries/omp...")

project (openvas-libraries/base C)

cmake_minimum_required (VERSION 2.6)

if (POLICY CMP0005)
   cmake_policy (SET CMP0005 OLD)
endif (POLICY CMP0005)

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Debug)
endif (NOT CMAKE_BUILD_TYPE)

## Version

file (READ ../VERSION _OPENVASLIBOMP_VERSION)

string (REGEX REPLACE "\\\n" "." _OPENVASLIBOMP_VERSION_STR ${_OPENVASLIBOMP_VERSION})
string (REGEX REPLACE "\\." ";" OPENVASLIBOMP_VERSION ${_OPENVASLIBOMP_VERSION_STR})

list (GET OPENVASLIBOMP_VERSION 0 OPENVASLIBOMP_MAJOR)
list (GET OPENVASLIBOMP_VERSION 1 OPENVASLIBOMP_MINOR)
list (GET OPENVASLIBOMP_VERSION 2 OPENVASLIBOMP_PATCH)

## CPack configuration

set (CPACK_CMAKE_GENERATOR "Unix Makefiles")
set (CPACK_GENERATOR "TGZ")
set (CPACK_INSTALL_CMAKE_PROJECTS ".;openvas-libraries/base;ALL;/")
set (CPACK_MODULE_PATH "")
set (CPACK_RESOURCE_FILE_LICENSE "../COPYING")
set (CPACK_RESOURCE_FILE_README "README.txt")
set (CPACK_RESOURCE_FILE_WELCOME "README.txt")
set (CPACK_SOURCE_GENERATOR "TGZ")
set (CPACK_SOURCE_TOPLEVEL_TAG "")
set (CPACK_SYSTEM_NAME "")
set (CPACK_TOPLEVEL_TAG "")
set (CPACK_PACKAGE_VERSION_MAJOR ${OPENVASLIBOMP_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${OPENVASLIBOMP_MINOR})
set (CPACK_PACKAGE_VERSION_PATCH ${OPENVASLIBOMP_PATCH})
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

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG}")
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -Wall -Werror")

set (FILES xml.c omp.c)

set (HEADERS xml.h omp.h)

include_directories (../misc)
link_directories( ${CMAKE_CURRENT_SOURCE_DIR}/../misc )

add_library (openvas_omp_static STATIC ${FILES})
set_target_properties (openvas_omp_static PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS}")
set_target_properties (openvas_omp_static PROPERTIES OUTPUT_NAME "openvas_omp")
set_target_properties (openvas_omp_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_omp_static PROPERTIES PUBLIC_HEADER "${HEADERS}")

add_library (openvas_omp_shared SHARED ${FILES})
set_target_properties (openvas_omp_shared PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS}")
set_target_properties (openvas_omp_shared PROPERTIES OUTPUT_NAME "openvas_omp")
set_target_properties (openvas_omp_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_omp_shared PROPERTIES SOVERSION "${CPACK_PACKAGE_VERSION_MAJOR}")
set_target_properties (openvas_omp_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
set_target_properties (openvas_omp_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

if (MINGW)
  target_link_libraries (openvas_omp_shared openvas_misc -lglib-2.0 -lgnutls
                         -lgcrypt -lgpg-error -lintl -lws2_32 -liconv -lole32
                         -lz -lkernel32)
else (MINGW)
  target_link_libraries (openvas_omp_shared openvas_misc glib-2.0 gnutls)
endif (MINGW)

## Install

install (TARGETS openvas_omp_static openvas_omp_shared
         RUNTIME DESTINATION ${BINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR}
         PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/omp")

## End
