# Copyright (C) 2016-2021 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

## Library

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)

## Dependency checks

# for all modules we need glib
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)

# for compressutils we need zlib
pkg_check_modules (ZLIB REQUIRED zlib>=1.2.8)

# for fileutils we need giolib
pkg_check_modules (GIO REQUIRED gio-2.0>=2.42)

# for serverutils, sshutils and xmlutils we need gnutls
pkg_check_modules (GNUTLS REQUIRED gnutls>=3.2.15)

# for uuidutils we need uuidlib
pkg_check_modules (UUID REQUIRED uuid>=2.25.0)

# for sshutils we need libssh
pkg_check_modules (LIBSSH REQUIRED libssh>=0.6.0)

# for kb we need libhiredis
pkg_check_modules (REDIS REQUIRED hiredis>=0.10.1)

# for fast XML we need libxml2
pkg_check_modules (LIBXML2 REQUIRED libxml-2.0>=2.0)

# Set NVTICACHE name with the version
set (NVTICACHE_STR "nvticache${PROJECT_VERSION}")
add_definitions (-DNVTICACHE_STR="${NVTICACHE_STR}")

#for gpgmeutils we need libgpgme
set (GPGME_MIN_VERSION "1.7.0")
message (STATUS "Looking for gpgme...")
find_library (GPGME gpgme)
if (NOT GPGME)
  message (SEND_ERROR "The gpgme library is required.")
else (NOT GPGME)
  execute_process (COMMAND gpgme-config --version
    OUTPUT_VARIABLE GPGME_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  message (STATUS "Found gpgme: ${GPGME}, version ${GPGME_VERSION}")
  if (GPGME_VERSION VERSION_LESS GPGME_MIN_VERSION)
    message (SEND_ERROR "The gpgme library >= ${GPGME_MIN_VERSION} is required.")
  else (GPGME_VERSION VERSION_LESS GPGME_MIN_VERSION)
    execute_process (COMMAND gpgme-config --libs
      OUTPUT_VARIABLE GPGME_LDFLAGS
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process (COMMAND gpgme-config --cflags
      OUTPUT_VARIABLE GPGME_CFLAGS
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FILE_OFFSET_BITS=64 -DLARGEFILE_SOURCE=1")
    string(REPLACE "-I" "" GPGME_INCLUDE_DIRS "${GPGME_CFLAGS}")
  endif (GPGME_VERSION VERSION_LESS GPGME_MIN_VERSION)
endif (NOT GPGME)

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
string(REPLACE "-I" "" GCRYPT_INCLUDE_DIRS "${GCRYPT_CFLAGS}")
endif (NOT GCRYPT)

option (BUILD_WITH_RADIUS "Try to build with Radius support" ON)
option (BUILD_WITH_LDAP "Try to build with LDAP support" ON)

if (BUILD_WITH_RADIUS)
  #for radiusutils we need freeradius-client library
  message (STATUS "Looking for freeradius-client library...")
  find_library (LIBFREERADIUS freeradius-client)
  if (NOT LIBFREERADIUS)
    message (STATUS "Looking for radcli library...")
    find_library (LIBRADCLI radcli)
  endif (NOT LIBFREERADIUS)
  if (NOT LIBFREERADIUS AND NOT LIBRADCLI)
    message (STATUS "  No suitable radius library found - radius support disabled")
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

if (BUILD_WITH_LDAP)
  #for ldaputils we need ldap library
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
    set (LDAP_LDFLAGS "-lldap")
  endif (NOT LIBLDAP)
endif (BUILD_WITH_LDAP)

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
  # set C standard for older GNU compilers (GCC < 6.3.0)
  if (CMAKE_C_COMPILER_VERSION VERSION_LESS 6.3)
    add_compile_options(-std=gnu99)
  endif()
endif()

include_directories (${GLIB_INCLUDE_DIRS} ${GPGME_INCLUDE_DIRS} ${GCRYPT_INCLUDE_DIRS}
                     ${LIBXML2_INCLUDE_DIRS})

set (FILES authutils.c compressutils.c fileutils.c gpgmeutils.c kb.c ldaputils.c
           nvticache.c radiusutils.c serverutils.c sshutils.c uuidutils.c
           xmlutils.c)

set (HEADERS authutils.h compressutils.h fileutils.h gpgmeutils.h kb.h
             ldaputils.h nvticache.h radiusutils.h serverutils.h sshutils.h
             uuidutils.h xmlutils.h)

if (BUILD_STATIC)
  add_library (gvm_util_static STATIC ${FILES})
  set_target_properties (gvm_util_static PROPERTIES OUTPUT_NAME "gvm_util")
  set_target_properties (gvm_util_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_util_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  add_library (gvm_util_shared SHARED ${FILES})
  set_target_properties (gvm_util_shared PROPERTIES OUTPUT_NAME "gvm_util")
  set_target_properties (gvm_util_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_util_shared PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}")
  set_target_properties (gvm_util_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  set_target_properties (gvm_util_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

  target_link_libraries (gvm_util_shared LINK_PRIVATE ${GLIB_LDFLAGS}
                         ${GIO_LDFLAGS} ${GPGME_LDFLAGS} ${ZLIB_LDFLAGS}
                         ${RADIUS_LDFLAGS} ${LIBSSH_LDFLAGS} ${GNUTLS_LDFLAGS}
                         ${GCRYPT_LDFLAGS} ${LDAP_LDFLAGS} ${REDIS_LDFLAGS}
                         ${LIBXML2_LDFLAGS} ${UUID_LDFLAGS}
                         ${LINKER_HARDENING_FLAGS})
endif (BUILD_SHARED)


## Tests

if (BUILD_TESTS)
  add_executable (xmlutils-test
                  EXCLUDE_FROM_ALL
                  xmlutils_tests.c)

  add_test (xmlutils-test xmlutils-test)

  target_include_directories (xmlutils-test PRIVATE ${CGREEN_INCLUDE_DIRS})

  target_link_libraries (xmlutils-test ${CGREEN_LIBRARIES}
                        ${GLIB_LDFLAGS} ${GIO_LDFLAGS} ${GPGME_LDFLAGS} ${ZLIB_LDFLAGS}
              ${RADIUS_LDFLAGS} ${LIBSSH_LDFLAGS} ${GNUTLS_LDFLAGS}
              ${GCRYPT_LDFLAGS} ${LDAP_LDFLAGS} ${REDIS_LDFLAGS}
              ${LIBXML2_LDFLAGS} ${UUID_LDFLAGS}
              ${LINKER_HARDENING_FLAGS})

  add_custom_target (tests-xmlutils
                    DEPENDS xmlutils-test)

endif (BUILD_TESTS)

## Install
configure_file (libgvm_util.pc.in ${CMAKE_BINARY_DIR}/libgvm_util.pc @ONLY)

install (FILES ${CMAKE_BINARY_DIR}/libgvm_util.pc
         DESTINATION ${LIBDIR}/pkgconfig)

if (BUILD_STATIC)
  install (TARGETS gvm_util_static
    RUNTIME DESTINATION ${BINDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/util")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  install (TARGETS gvm_util_shared
    RUNTIME DESTINATION ${BINDIR}
    LIBRARY DESTINATION ${LIBDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/util")
endif (BUILD_SHARED)

## End
