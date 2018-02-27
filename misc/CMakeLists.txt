# OpenVAS-libraries/misc
# $Id$
# Description: Makefile for misc of OpenVAS-libraries.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
#
# Copyright:
# Copyright (C) 2010, 2011 Greenbone Networks GmbH
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

## Pass-throughs

include_directories (${GLIB_INCLUDE_DIRS})
include_directories (${GNUTLS_INCLUDE_DIRS})

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

if (NOT MINGW)
  pkg_check_modules (UUID REQUIRED uuid)

  if (BUILD_WITH_RADIUS)
    message (STATUS "Looking for freeradius-client library...")
    find_library (LIBFREERADIUS freeradius-client)
    if (NOT LIBFREERADIUS)
      message (STATUS "Looking for radcli library...")
      find_library (LIBRADCLI radcli)
    endif (NOT LIBFREERADIUS)
    if (NOT LIBFREERADIUS AND NOT LIBRADCLI)
      message (SEND_ERROR "  No suitable radius library found")
    elseif (LIBFREERADIUS)
      message (STATUS "  Found ${LIBFREERADIUS} - radius support enabled")
      set (RADIUS_LDFLAGS "-lfreeradius-client")
      add_definitions (-DENABLE_RADIUS_AUTH=1 -DRADIUS_AUTH_FREERADIUS=1)
    elseif (LIBRADCLI)
      message (STATUS "  Found ${LIBRADCLI} - radius support enabled")
      set (RADIUS_LDFLAGS "-lradcli")
      add_definitions (-DENABLE_RADIUS_AUTH=1 -DRADIUS_AUTH_RADCLI=1)
    endif (NOT LIBFREERADIUS AND NOT LIBRADCLI)
  endif (BUILD_WITH_RADIUS)

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
      set (LDAP_LDFLAGS "-lldap")
    endif (NOT LIBLDAP)
  else (NOT BUILD_WITHOUT_LDAP)
    message (STATUS "Disabled ldap via configuration option")
  endif (NOT BUILD_WITHOUT_LDAP)

endif (NOT MINGW)

# Library


if (NOT MINGW)
  # On windows we are always PIC and stack-protector is replaces by DEP
  # Also stack protection needs a shared library to work
  set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} ${HARDENING_FLAGS} -Wall -Wextra -fPIC")
endif (NOT MINGW)

if (MINGW)
  set (FILES openvas_auth.c openvas_ssh.c openvas_server.c openvas_proctitle.c)
  set (HEADERS openvas_proctitle.h openvas_ssh.h openvas_auth.h openvas_server.h)
else (MINGW)
  set (FILES arglists.c bpf_share.c ftp_funcs.c ids_send.c ldap_connect_auth.c
             network.c openvas_ssh.c openvas_auth.c openvas_logging.c
             openvas_server.c openvas_uuid.c plugutils.c popen.c radius.c
             openvas_proctitle.c prefs.c www_funcs.c pcap.c vendorversion.c)

  set (HEADERS arglists.h bpf_share.h ftp_funcs.h ldap_connect_auth.h
               network.h pcap_openvas.h plugutils.h popen.h openvas_proctitle.h
               openvas_auth.h openvas_logging.h openvas_server.h openvas_uuid.h
               openvas_ssh.h prefs.h nvt_categories.h internal_com.h www_funcs.h
               radius.h vendorversion.h)
endif (MINGW)

if (BUILD_WITH_LDAP)
  list (APPEND FILES ldap_connect_auth.c)
endif (BUILD_WITH_LDAP)

link_directories (${CMAKE_CURRENT_BINARY_DIR}/../base)

# Indentation targets
# TODO: Commented out as it provokes error. Unclear
# what this directive is good for.
#add_custom_indent_targets (${FILES})

if (BUILD_STATIC)
  add_library (openvas_misc_static STATIC ${FILES})

  set_target_properties (openvas_misc_static PROPERTIES OUTPUT_NAME "openvas_misc")
  set_target_properties (openvas_misc_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (openvas_misc_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
  target_link_libraries (openvas_misc_static openvas_base_static)
endif (BUILD_STATIC)

if (BUILD_SHARED)
  add_library (openvas_misc_shared SHARED ${FILES})

  set_target_properties (openvas_misc_shared PROPERTIES OUTPUT_NAME "openvas_misc")
  set_target_properties (openvas_misc_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (openvas_misc_shared PROPERTIES SOVERSION "${CPACK_PACKAGE_VERSION_MAJOR}")
  set_target_properties (openvas_misc_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  set_target_properties (openvas_misc_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

  if (MINGW)
    set (GLIB_LDFLAGS -Wl,--start-group ${GLIB_LDFLAGS} gmodule-2.0 -Wl,--end-group)
    set (W32LIBS uuid ${GLIB_LDFLAGS} gnutls intl iconv tasn1
       gcrypt gpgme assuan libgpg-error ole32 ws2_32 ffi z shlwapi dnsapi winmm)
    target_link_libraries (openvas_misc_shared openvas_base_shared ${W32LIBS})
  else (MINGW)
    target_link_libraries (openvas_misc_shared LINK_PRIVATE ${GNUTLS_LDFLAGS} openvas_base_shared ${UUID_LDFLAGS}
                           ${GLIB_LDFLAGS} ${PCAP_LDFLAGS} ${LIBSSH_LDFLAGS} ${LDAP_LDFLAGS}
                           ${GCRYPT_LDFLAGS} ${RADIUS_LDFLAGS}
                           ${LINKER_HARDENING_FLAGS})
  endif (MINGW)
endif (BUILD_SHARED)

if (OPENVASLIB_VERSION)
  add_definitions (-DOPENVASLIB_VERSION=\\\"${OPENVASLIB_VERSION}\\\")

  string (REGEX REPLACE "^\([0-9]+\).*" "\\1" PATCH_VERS
          ${CPACK_PACKAGE_VERSION_PATCH})

  string (COMPARE EQUAL ${PATCH_VERS} ${CPACK_PACKAGE_VERSION_PATCH} EQ)
  if (EQ)
    set (PATCH_VERS "0")
  endif (EQ)

  add_definitions (-DOPENVASLIB_VERSION_MAJOR=${CPACK_PACKAGE_VERSION_MAJOR})
  add_definitions (-DOPENVASLIB_VERSION_MINOR=${CPACK_PACKAGE_VERSION_MINOR})
  add_definitions (-DOPENVASLIB_VERSION_PATCH=${PATCH_VERS})
endif (OPENVASLIB_VERSION)


if (OPENVAS_STATE_DIR)
  add_definitions (-DOPENVAS_STATE_DIR=\\\"${OPENVAS_STATE_DIR}\\\")
endif (OPENVAS_STATE_DIR)

if (OPENVAS_DATA_DIR)
  add_definitions (-DOPENVAS_DATA_DIR=\\\"${OPENVAS_DATA_DIR}\\\")
endif (OPENVAS_DATA_DIR)

# @todo Why is this definition setting guarded? OPENVAS_SYSCONF_DIR should
#       always be set.
#$(COMPILE) -DOPENVAS_STATE_DIR=\"$(localstatedir)\" -DCONF_DIR=\"$(sysconfdir)\" -c services1.c
if (OPENVAS_SYSCONF_DIR)
  add_definitions (-DOPENVAS_SYSCONF_DIR=\\\"${OPENVAS_SYSCONF_DIR}\\\")
endif (OPENVAS_SYSCONF_DIR)

# install library

if (BUILD_STATIC)
  install (TARGETS openvas_misc_static
           RUNTIME DESTINATION ${BINDIR}
           ARCHIVE DESTINATION ${LIBDIR}
           PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/misc")
endif (BUILD_STATIC)
if (BUILD_SHARED)
  install (TARGETS openvas_misc_shared
           RUNTIME DESTINATION ${BINDIR}
           LIBRARY DESTINATION ${LIBDIR}
           ARCHIVE DESTINATION ${LIBDIR}
           PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/misc")
endif (BUILD_SHARED)
