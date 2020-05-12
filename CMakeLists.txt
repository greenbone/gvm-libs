# Copyright (C) 2011-2019 Greenbone Networks GmbH
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

cmake_minimum_required(VERSION 3.0)

message ("-- Configuring the Greenbone Vulnerability Management Libraries...")

project (gvm-libs
  VERSION 11.0.1
  LANGUAGES C)

if (POLICY CMP0005)
  cmake_policy (SET CMP0005 NEW)
endif (POLICY CMP0005)

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Debug)
endif (NOT CMAKE_BUILD_TYPE)

OPTION(BUILD_STATIC "Build static versions of the libraries" OFF)
OPTION(ENABLE_COVERAGE "Enable support for coverage analysis" OFF)
OPTION(BUILD_TESTS "Build tests for the libraries" OFF)

if (NOT BUILD_STATIC)
  set (BUILD_SHARED ON)
else (NOT BUILD_STATIC)
  set (BUILD_SHARED OFF)
endif (NOT BUILD_STATIC)

## Retrieve git revision (at configure time)
find_package (Git)

## make format
message (STATUS "Looking for clang-format...")
find_program (CLANG_FORMAT clang-format)

if (CLANG_FORMAT)
  message (STATUS "Looking for clang-format... ${CLANG_FORMAT}")
  add_custom_target(format COMMAND ${CLANG_FORMAT} "-i" "./base/*.c" "./gmp/*.c"
                    "./osp/*.c" "./util/*.c" "./base/*.h" "./gmp/*.h" "./osp/*.h"
                    "./util/*.h" WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
else (CLANG_FORMAT)
  message (STATUS "clang-format not found...")
endif (CLANG_FORMAT)


macro (Git_GET_REVISION dir variable)
  execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
                  WORKING_DIRECTORY ${dir}
                  OUTPUT_VARIABLE GIT_BRANCH
                  OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process(COMMAND ${GIT_EXECUTABLE} log -1 --format=%h
                  WORKING_DIRECTORY ${dir}
                  OUTPUT_VARIABLE GIT_COMMIT_HASH
                  OUTPUT_STRIP_TRAILING_WHITESPACE)
  string (REPLACE "/" "_" GIT_BRANCH ${GIT_BRANCH})
  set (${variable} "${GIT_COMMIT_HASH}-${GIT_BRANCH}")
endmacro (Git_GET_REVISION)

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
  if (EXISTS "${CMAKE_SOURCE_DIR}/.git/")
    if (GIT_FOUND)
      Git_GET_REVISION(${CMAKE_SOURCE_DIR} ProjectRevision)
      set (GIT_REVISION "~git-${ProjectRevision}")
    else (GIT_FOUND)
      set (GIT_REVISION "~git")
    endif (GIT_FOUND)
  endif (EXISTS "${CMAKE_SOURCE_DIR}/.git/")
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

# Set beta version if this is a beta release series,
# unset if this is a stable release series.
set (PROJECT_BETA_RELEASE 0)

if (GIT_REVISION)
  set (PROJECT_VERSION_GIT "${GIT_REVISION}")
endif (GIT_REVISION)

# If PROJECT_BETA_RELEASE is set, the version string will be set to:
#   "major.minor+beta${PROJECT_BETA_RELEASE}"
# If PROJECT_BETA_RELEASE is NOT set, the version string will be set to:
#   "major.minor.patch"
if (PROJECT_BETA_RELEASE)
  set (PROJECT_VERSION_SUFFIX "+beta${PROJECT_BETA_RELEASE}")
else (PROJECT_BETA_RELEASE)
  set (PROJECT_VERSION_SUFFIX ".${PROJECT_VERSION_PATCH}")
endif (PROJECT_BETA_RELEASE)

set (PROJECT_VERSION_STRING "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}${PROJECT_VERSION_SUFFIX}")

## CPack configuration

set (CPACK_CMAKE_GENERATOR "Unix Makefiles")
set (CPACK_GENERATOR "TGZ")
set (CPACK_INSTALL_CMAKE_PROJECTS ".;gvm-libs;ALL;/")
set (CPACK_MODULE_PATH "")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/COPYING")
set (CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
set (CPACK_RESOURCE_FILE_WELCOME "${CMAKE_SOURCE_DIR}/README.md")
set (CPACK_SOURCE_GENERATOR "TGZ")
set (CPACK_SOURCE_TOPLEVEL_TAG "")
set (CPACK_SYSTEM_NAME "")
set (CPACK_TOPLEVEL_TAG "")

set (CPACK_PACKAGE_VERSION "${PROJECT_VERSION_STRING}${PROJECT_VERSION_GIT}")

set (CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_PACKAGE_VENDOR "Greenbone Networks")
set (CPACK_SOURCE_IGNORE_FILES
"${CMAKE_BINARY_DIR}"
"/.git/"
"swp$"
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

if (NOT GVM_PID_DIR)
  set (GVM_PID_DIR "${LOCALSTATEDIR}/run")
endif (NOT GVM_PID_DIR)

if (NOT GVM_SYSCONF_DIR)
  set (GVM_SYSCONF_DIR "${SYSCONFDIR}/gvm")
endif (NOT GVM_SYSCONF_DIR)


if (NOT REDIS_SOCKET_PATH)
  set (REDIS_SOCKET_PATH "/run/redis/redis.sock")
endif ()

add_definitions (-DREDIS_SOCKET_PATH="${REDIS_SOCKET_PATH}")
message ("-- Using redis socket ${REDIS_SOCKET_PATH}")

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")

if (ENABLE_COVERAGE)
  set (COVERAGE_FLAGS "--coverage")
endif (ENABLE_COVERAGE)

set (HARDENING_FLAGS "-Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -fstack-protector")
set (LINKER_HARDENING_FLAGS "-Wl,-z,relro -Wl,-z,now")
set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -Wextra -Werror ${COVERAGE_FLAGS}")
set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${HARDENING_FLAGS}")


## Version

if (PROJECT_BETA_RELEASE)
  set (LIBGVMCONFIG_VERSION "${PROJECT_VERSION}")
else (PROJECT_BETA_RELEASE)
  set (LIBGVMCONFIG_VERSION "${PROJECT_VERSION_STRING}")
endif (PROJECT_BETA_RELEASE)

add_definitions(-DGVM_LIBS_VERSION="${LIBGVMCONFIG_VERSION}")

# Configure Doxyfile with version number
configure_file (doc/Doxyfile.in ${CMAKE_BINARY_DIR}/doc/Doxyfile @ONLY)
configure_file (doc/Doxyfile_full.in ${CMAKE_BINARY_DIR}/doc/Doxyfile_full @ONLY)
configure_file (doc/Doxyfile_xml.in ${CMAKE_BINARY_DIR}/doc/Doxyfile_xml @ONLY)
configure_file (VERSION.in ${CMAKE_BINARY_DIR}/VERSION @ONLY)

## Testing

if (BUILD_TESTS AND NOT SKIP_SRC)
  enable_testing ()

  find_package (cgreen REQUIRED)

  add_custom_target (tests
                    DEPENDS array-test xmlutils-test version-test)

endif (BUILD_TESTS AND NOT SKIP_SRC)

## Program

if (NOT SKIP_SRC)
  add_subdirectory (base)
  add_subdirectory (util)
  add_subdirectory (osp)
  add_subdirectory (gmp)
endif (NOT SKIP_SRC)

## Documentation

add_subdirectory (doc)

if (BUILD_TESTS AND NOT SKIP_SRC)
  add_subdirectory (tests)
  add_test (NAME testhosts COMMAND test-hosts localhost)
endif (BUILD_TESTS AND NOT SKIP_SRC)

## End
