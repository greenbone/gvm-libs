# SPDX-FileCopyrightText: 2016-2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

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

# for gpgmeutils we need libgpgme
pkg_check_modules (GPGME REQUIRED gpgme>=1.7.0)

# for serverutils we need libgcrypt
pkg_check_modules (GCRYPT REQUIRED libgcrypt)

# for json parsing we need cJSON
pkg_check_modules (CJSON REQUIRED libcjson>=1.7.14)

# for mqtt
find_library(LIBPAHO paho-mqtt3c)
message (STATUS "Looking for paho-mqtt3c ... ${LIBPAHO}")
if (NOT LIBPAHO)
  message (SEND_ERROR "libpaho-mqtt3c is required for MQTTv5 support.")
else (NOT LIBPAHO)
  set (LIBPAHO_LDFLAGS "paho-mqtt3c")
  add_definitions (-DHAVE_MQTT=1)
endif (NOT LIBPAHO)

message (STATUS "Looking for libcrypt...")
find_library (CRYPT crypt)
message (STATUS "Looking for libcrypt... ${CRYPT}")
if (NOT CRYPT)
message (SEND_ERROR "The libcrypt library is required.")
else (NOT CRYPT)
    pkg_search_module(CRYPT_M QUIET libcrypt)
    if (DEFINED ${CRYPT_M_VERSION} AND ${CRYPT_M_VERSION} VERSION_GREATER "3.1.1")
        message (STATUS "\t Using external crypt_gensal_r of ... ${CRYPT_M_VERSION}")
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DEXTERNAL_CRYPT_GENSALT_R=1")
    endif()
    set (CRYPT_LDFLAGS "-lcrypt")
endif (NOT CRYPT)

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

include_directories (${GLIB_INCLUDE_DIRS} ${GPGME_INCLUDE_DIRS} ${GCRYPT_INCLUDE_DIRS}
                     ${LIBXML2_INCLUDE_DIRS})

set (FILES cpeutils.c passwordbasedauthentication.c compressutils.c fileutils.c gpgmeutils.c json.c jsonpull.c kb.c
           ldaputils.c nvticache.c mqtt.c radiusutils.c serverutils.c sshutils.c uuidutils.c versionutils.c
           xmlutils.c)

set (HEADERS cpeutils.h passwordbasedauthentication.h authutils.h compressutils.h fileutils.h gpgmeutils.h
             json.h jsonpull.h kb.h ldaputils.h nvticache.h mqtt.h radiusutils.h serverutils.h sshutils.h
             uuidutils.h versionutils.h xmlutils.h)

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

  target_link_libraries (gvm_util_shared LINK_PRIVATE ${LIBPAHO_LDFLAGS} ${GLIB_LDFLAGS}
                         ${GIO_LDFLAGS} ${GPGME_LDFLAGS} ${ZLIB_LDFLAGS}
                         ${RADIUS_LDFLAGS} ${LIBSSH_LDFLAGS} ${GNUTLS_LDFLAGS}
                         ${GCRYPT_LDFLAGS} ${LDAP_LDFLAGS} ${REDIS_LDFLAGS}
                         ${LIBXML2_LDFLAGS} ${UUID_LDFLAGS}
                         ${LINKER_HARDENING_FLAGS} ${CRYPT_LDFLAGS}
                         ${CJSON_LDFLAGS})
endif (BUILD_SHARED)


## Tests

if (BUILD_TESTS)
  add_unit_test (json-test json_tests.c ${GLIB_LDFLAGS} ${CJSON_LDFLAGS})
  add_unit_test (jsonpull-test jsonpull_tests.c ${GLIB_LDFLAGS} ${CJSON_LDFLAGS})
  add_unit_test (passwordbasedauthentication-test passwordbasedauthentication_tests.c
                 ${BSD_LDFLAGS} ${GCRYPT_LDFLAGS} ${CRYPT_LDFLAGS} ${GLIB_LDFLAGS})
  add_unit_test (compressutils-test compressutils_tests.c
                 ${GLIB_LDFLAGS} ${GIO_LDFLAGS} ${GPGME_LDFLAGS} ${ZLIB_LDFLAGS}
                 ${RADIUS_LDFLAGS} ${LIBSSH_LDFLAGS} ${GNUTLS_LDFLAGS}
                 ${GCRYPT_LDFLAGS} ${LDAP_LDFLAGS} ${REDIS_LDFLAGS}
                 ${LIBXML2_LDFLAGS} ${UUID_LDFLAGS}
                 ${LINKER_HARDENING_FLAGS})
  add_unit_test (cpeutils-test cpeutils_tests.c
                 ${GLIB_LDFLAGS} ${GIO_LDFLAGS} ${GPGME_LDFLAGS} ${ZLIB_LDFLAGS}
                 ${RADIUS_LDFLAGS} ${LIBSSH_LDFLAGS} ${GNUTLS_LDFLAGS}
                 ${GCRYPT_LDFLAGS} ${LDAP_LDFLAGS} ${REDIS_LDFLAGS}
                 ${LIBXML2_LDFLAGS} ${UUID_LDFLAGS}
                 ${LINKER_HARDENING_FLAGS})
  add_unit_test (kb-test kb_tests.c gvm_base_shared ${GLIB_LDFLAGS}  ${REDIS_LDFLAGS}
                 ${LINKER_HARDENING_FLAGS})
  add_unit_test (versionutils-test versionutils_tests.c
                 ${GLIB_LDFLAGS} ${GIO_LDFLAGS} ${GPGME_LDFLAGS} ${ZLIB_LDFLAGS}
                 ${RADIUS_LDFLAGS} ${LIBSSH_LDFLAGS} ${GNUTLS_LDFLAGS}
                 ${GCRYPT_LDFLAGS} ${LDAP_LDFLAGS} ${REDIS_LDFLAGS}
                 ${LIBXML2_LDFLAGS} ${UUID_LDFLAGS}
                 ${LINKER_HARDENING_FLAGS})
  add_unit_test (xmlutils-test xmlutils_tests.c
                 ${GLIB_LDFLAGS} ${GIO_LDFLAGS} ${GPGME_LDFLAGS} ${ZLIB_LDFLAGS}
                 ${RADIUS_LDFLAGS} ${LIBSSH_LDFLAGS} ${GNUTLS_LDFLAGS}
                 ${GCRYPT_LDFLAGS} ${LDAP_LDFLAGS} ${REDIS_LDFLAGS}
                 ${LIBXML2_LDFLAGS} ${UUID_LDFLAGS}
                 ${LINKER_HARDENING_FLAGS})
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
