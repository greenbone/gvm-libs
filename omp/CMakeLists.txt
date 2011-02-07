# openvas-libraries/omp
# $Id$
# Description: Top-level cmake control for the OMP library.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
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

## Library

set (HARDENING_FLAGS            "-Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector -Wl,-z,relro -Wl,-z,now")

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG}")
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} ${HARDENING_FLAGS} -Wall -Werror")

set (FILES xml.c omp.c)

set (HEADERS xml.h omp.h)

include_directories (../misc)
link_directories( ${CMAKE_CURRENT_BINARY_DIR}/../misc )

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
