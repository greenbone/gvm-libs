# OpenVAS-libraries/base
# $Id$
# Description: Top-level cmake control for the base library.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
#
# Copyright:
# Copyright (C) 2009,2010,2013 Greenbone Networks GmbH
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

if (NOT MINGW)
  set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Werror")
  # FIXME: certain flags should be defined on the global level,
  # because they change the API (e.g. _FILE_OFFSET_BITS).
  set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} ${HARDENING_FLAGS} -D_FILE_OFFSET_BITS=64 -Wall -fPIC")
endif (NOT MINGW)

if (MINGW)
  set  (FILES array.c certificate.c credentials.c
       nvti.c nvticache.c openvas_certificate_file.c
       openvas_file.c openvas_string.c pidfile.c severity_filter.c settings.c
       gpgme_util.c pwpolicy.c)
  set (HEADERS array.h certificate.h credentials.h
       nvti.h settings.h openvas_certificate_file.h
       openvas_file.h openvas_string.h pidfile.h severity_filter.h
       gpgme_util.h pwpolicy.h)
else (MINGW)
  set (FILES array.c certificate.c credentials.c
       cvss.c drop_privileges.c
       nvti.c nvticache.c openvas_certificate_file.c
       openvas_file.c openvas_string.c pidfile.c severity_filter.c settings.c
       gpgme_util.c pwpolicy.c)
  set (HEADERS array.h certificate.h credentials.h
       cvss.h drop_privileges.h nvticache.h
       nvti.h settings.h openvas_certificate_file.h
       openvas_file.h openvas_string.h pidfile.h severity_filter.h
       gpgme_util.h pwpolicy.h)
endif (MINGW)

add_library (openvas_base_static STATIC ${FILES})
set_target_properties (openvas_base_static PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${GPGME_CFLAGS}")
set_target_properties (openvas_base_static PROPERTIES OUTPUT_NAME "openvas_base")
set_target_properties (openvas_base_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_base_static PROPERTIES PUBLIC_HEADER "${HEADERS}")

add_library (openvas_base_shared SHARED ${FILES})
set_target_properties (openvas_base_shared PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${GPGME_CFLAGS}")
set_target_properties (openvas_base_shared PROPERTIES OUTPUT_NAME "openvas_base")
set_target_properties (openvas_base_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_base_shared PROPERTIES SOVERSION "${CPACK_PACKAGE_VERSION_MAJOR}")
set_target_properties (openvas_base_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
set_target_properties (openvas_base_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

add_definitions (-DOPENVAS_SYSCONF_DIR=\\\"${OPENVAS_SYSCONF_DIR}\\\")
add_definitions (-DOPENVAS_STATE_DIR=\\\"${OPENVAS_STATE_DIR}\\\")
if (OPENVAS_PID_DIR)
  add_definitions (-DOPENVAS_PID_DIR=\\\"${OPENVAS_PID_DIR}\\\")
endif (OPENVAS_PID_DIR)

if (MINGW)
  target_link_libraries (openvas_base_static ${GLIB_LDFlAGS} intl iconv ole32)
  target_link_libraries (openvas_base_shared ${GLIB_LDFLAGS} intl iconv ole32)
else (MINGW)
  target_link_libraries (openvas_base_static ${GLIB_LDFLAGS} ${GPGME_LDFLAGS})
  target_link_libraries (openvas_base_shared ${GLIB_LDFLAGS} ${GPGME_LDFLAGS})
endif (MINGW)

add_custom_indent_targets (${FILES})

## Install
install (TARGETS openvas_base_static openvas_base_shared
         RUNTIME DESTINATION ${BINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR}
         PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/base")

## End
