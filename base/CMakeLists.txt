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

  message (STATUS "Looking for zlib...")
  find_library (ZLIB z)
  message (STATUS "Looking for zlib... ${ZLIB}")
  if (NOT ZLIB)
    message (FATAL_ERROR "The zlib library is required.")
  endif (NOT ZLIB)
  execute_process (COMMAND pkg-config --cflags zlib
    OUTPUT_VARIABLE ZLIB_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND pkg-config --libs zlib
    OUTPUT_VARIABLE ZLIB_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  execute_process (COMMAND pkg-config --libs gio-2.0
    OUTPUT_VARIABLE GIO_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif (NOT MINGW)

if (MINGW)
  set  (FILES array.c credentials.c openvas_hosts.c cvss.c nvti.c nvticache.c
        openvas_file.c openvas_string.c pidfile.c settings.c gpgme_util.c
        pwpolicy.c)
  set (HEADERS array.h credentials.h openvas_hosts.h cvss.h nvti.h settings.h
       openvas_file.h openvas_string.h pidfile.h gpgme_util.h pwpolicy.h)
else (MINGW)
  set (FILES array.c credentials.c openvas_hosts.c cvss.c drop_privileges.c
       nvti.c nvticache.c openvas_compress.c openvas_file.c openvas_networking.c
       openvas_string.c pidfile.c settings.c gpgme_util.c pwpolicy.c)
  set (HEADERS array.h credentials.h openvas_hosts.h cvss.h drop_privileges.h
       nvticache.h nvti.h settings.h openvas_compress.h openvas_file.h
       openvas_networking.h openvas_string.h pidfile.h gpgme_util.h pwpolicy.h)
endif (MINGW)

if (BUILD_STATIC)
  add_library (openvas_base_static STATIC ${FILES})
  set_target_properties (openvas_base_static PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${GPGME_CFLAGS} ${ZLIB_CFLAGS}")
  set_target_properties (openvas_base_static PROPERTIES OUTPUT_NAME "openvas_base")
  set_target_properties (openvas_base_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (openvas_base_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  add_library (openvas_base_shared SHARED ${FILES})
  set_target_properties (openvas_base_shared PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${GPGME_CFLAGS} ${ZLIB_CFLAGS}")
  set_target_properties (openvas_base_shared PROPERTIES OUTPUT_NAME "openvas_base")
  set_target_properties (openvas_base_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (openvas_base_shared PROPERTIES SOVERSION "${CPACK_PACKAGE_VERSION_MAJOR}")
  set_target_properties (openvas_base_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  set_target_properties (openvas_base_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

  if (MINGW)
    set (GLIB_LDFLAGS -Wl,--start-group ${GLIB_LDFLAGS} gmodule-2.0 -Wl,--end-group)
    set (W32LIBS ${GLIB_LDFLAGS} intl iconv gpgme
      assuan libgpg-error ole32 ws2_32 ffi z shlwapi dnsapi winmm)
    target_link_libraries (openvas_base_shared ${W32LIBS})
  else (MINGW)
    target_link_libraries (openvas_base_shared ${GLIB_LDFLAGS} ${GIO_LDFLAGS} ${GPGME_LDFLAGS} ${ZLIB_LDFLAGS})
  endif (MINGW)
endif (BUILD_SHARED)

add_definitions (-DOPENVAS_SYSCONF_DIR=\\\"${OPENVAS_SYSCONF_DIR}\\\")
add_definitions (-DOPENVAS_STATE_DIR=\\\"${OPENVAS_STATE_DIR}\\\")
if (OPENVAS_PID_DIR)
  add_definitions (-DOPENVAS_PID_DIR=\\\"${OPENVAS_PID_DIR}\\\")
endif (OPENVAS_PID_DIR)

add_custom_indent_targets (${FILES})

# Link the test-hosts executable
if (BUILD_SHARED)
  add_executable (test-hosts test-hosts.c)
  target_link_libraries (test-hosts openvas_base_shared openvas_misc_shared ${GLIB_LDFLAGS} -lgcrypt
    "${GPGME_LDFLAGS}" -lgnutls "${PCAP_LDFLAGS}" -lresolv -lm ${WMI_LIBS}
    ${GPGME_LDFLAGS} ${LIBSSH_LDFLAGS} ${KSBA_LDFLAGS} ${WINCMD_LIBS}) 
  set_target_properties (test-hosts PROPERTIES COMPILE_FLAGS
    "${GLIB_CFLAGS} ${GPGME_CFLAGS} ${LIBSSH_CFLAGS} ${KSBA_CFLAGS}")
endif (BUILD_SHARED)
if (BUILD_STATIC)
  add_executable (test-hosts test-hosts.c)
  target_link_libraries (test-hosts openvas_base_static openvas_misc_static ${GLIB_LDFLAGS} -lgcrypt
    "${GPGME_LDFLAGS}" -lgnutls "${PCAP_LDFLAGS}" -lresolv -lm ${WMI_LIBS}
    ${GPGME_LDFLAGS} ${LIBSSH_LDFLAGS} ${KSBA_LDFLAGS} ${WINCMD_LIBS}) 
  set_target_properties (test-hosts PROPERTIES COMPILE_FLAGS
    "${GLIB_CFLAGS} ${GPGME_CFLAGS} ${LIBSSH_CFLAGS} ${KSBA_CFLAGS}")
endif (BUILD_STATIC)

## Install
if (BUILD_STATIC)
  install (TARGETS openvas_base_static
    RUNTIME DESTINATION ${BINDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/base")
endif (BUILD_STATIC)
if (BUILD_SHARED)
  install (TARGETS openvas_base_shared
    RUNTIME DESTINATION ${BINDIR}
    LIBRARY DESTINATION ${LIBDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/base")
endif (BUILD_SHARED)

## End
