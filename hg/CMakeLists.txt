# OpenVAS-libraries/hg
# $Id$
# Description: Makefile for hg of OpenVAS-libraries.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
#
# Copyright:
# Copyright (C) 2010, 2011 Greenbone Networks GmbH
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

## Pass-throughs

include_directories(../misc)

# Library
set (HARDENING_FLAGS            "-Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector -Wl,-z,relro -Wl,-z,now")

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG}")
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} ${HARDENING_FLAGS} -Wall -Werror -fPIC")

set (FILES hg_add_hosts.c hg_debug.c hg_dns_axfr.c hg_filter.c hg_subnet.c 
           hg_utils.c hosts_gatherer.c)

set (HEADERS hg_utils.h hosts_gatherer.h)

link_directories (${CMAKE_CURRENT_BINARY_DIR}/../misc)

add_library (openvas_hg_static STATIC ${FILES})
set_target_properties (openvas_hg_static PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS}")
set_target_properties (openvas_hg_static PROPERTIES OUTPUT_NAME "openvas_hg")
set_target_properties (openvas_hg_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_hg_static PROPERTIES PUBLIC_HEADER "${HEADERS}")

add_library (openvas_hg_shared SHARED ${FILES})
set_target_properties (openvas_hg_shared PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS}")
set_target_properties (openvas_hg_shared PROPERTIES OUTPUT_NAME "openvas_hg")
set_target_properties (openvas_hg_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_hg_shared PROPERTIES SOVERSION "${CPACK_PACKAGE_VERSION_MAJOR}")
set_target_properties (openvas_hg_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
set_target_properties (openvas_hg_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")
target_link_libraries (openvas_hg_shared resolv openvas_misc_shared openvas_base_shared)

if (OPENVAS_PID_DIR)
  add_definitions (-DOPENVAS_PID_DIR=\\\"${OPENVAS_PID_DIR}\\\")
endif (OPENVAS_PID_DIR)

target_link_libraries (openvas_hg_static ${GLIB_LDFLAGS})
target_link_libraries (openvas_hg_shared ${GLIB_LDFLAGS})

# Build the hg testing executable (uncommented, as of linker errors in certain
# environments)
#add_executable (hg-test test.c)
#target_link_libraries (hg-test openvas_hg_static openvas_misc_static pcap)

# Would be great to build the little test tool.

# install library
install (TARGETS openvas_hg_static openvas_hg_shared
         RUNTIME DESTINATION ${BINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR}
         PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/hg")

## End
