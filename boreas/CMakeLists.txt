# Copyright (C) 2020-2021 Greenbone Networks GmbH
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

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)

## Dependency checks

message (STATUS "Looking for pcap...")
find_library (PCAP pcap)
message (STATUS "Looking for pcap... ${PCAP}")
if (NOT PCAP)
  message (SEND_ERROR "The pcap library is required.")
endif (NOT PCAP)

message (STATUS "Looking for pcap-config...")
find_program (PCAP_CONFIG pcap-config)

if (PCAP_CONFIG)
  message (STATUS "Looking for pcap-config... ${PCAP_CONFIG}")
  execute_process (COMMAND pcap-config --libs
    OUTPUT_VARIABLE PCAP_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND pcap-config --cflags
    OUTPUT_VARIABLE PCAP_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
else (PCAP_CONFIG)
  message (STATUS "pcap-config not found, using defaults...")
  set (PCAP_LDFLAGS "-L/usr/lib -lpcap")
  set (PCAP_CFLAGS "-I/usr/include")
endif (PCAP_CONFIG)

find_package (Threads)

pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)

include_directories (${GLIB_INCLUDE_DIRS})

set (FILES alivedetection.c boreas_error.c boreas_io.c cli.c ping.c sniffer.c util.c)

set (HEADERS alivedetection.h boreas_error.h boreas_io.h cli.h ping.h sniffer.h util.h)

if (BUILD_STATIC)
  set (LIBGVM_BOREAS_NAME gvm_boreas_static)
  add_library (gvm_boreas_static STATIC ${FILES})
  set_target_properties (gvm_boreas_static PROPERTIES OUTPUT_NAME "gvm_boreas")
  set_target_properties (gvm_boreas_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_boreas_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  set (LIBGVM_BOREAS_NAME gvm_boreas_shared)
  add_library (gvm_boreas_shared SHARED ${FILES})
  set_target_properties (gvm_boreas_shared PROPERTIES OUTPUT_NAME "gvm_boreas")
  set_target_properties (gvm_boreas_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (gvm_boreas_shared PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}")
  set_target_properties (gvm_boreas_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  set_target_properties (gvm_boreas_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

  target_link_libraries (gvm_boreas_shared LINK_PRIVATE
                         gvm_util_shared
                         ${GLIB_LDFLAGS}
                         ${LIBNET_LDFLAGS}
                         ${LINKER_HARDENING_FLAGS}
                         ${CMAKE_THREAD_LIBS_INIT})
endif (BUILD_SHARED)

set (LIBGVM_BOREAS_NAME
     ${LIBGVM_BOREAS_NAME}
     PARENT_SCOPE)

## Tests

add_executable (alivedetection-test
                EXCLUDE_FROM_ALL
                alivedetection_tests.c boreas_error.c boreas_io.c ping.c
                sniffer.c util.c)
add_test (alivedetection-test alivedetection-test)
target_include_directories (alivedetection-test PRIVATE ${CGREEN_INCLUDE_DIRS})
target_link_libraries (alivedetection-test gvm_base_shared gvm_util_shared
                       ${CGREEN_LIBRARIES}
                       ${GLIB_LDFLAGS}
                       ${PCAP_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS} ${CMAKE_THREAD_LIBS_INIT})

add_executable (boreas_error-test
                EXCLUDE_FROM_ALL
                boreas_error_tests.c)
add_test (boreas_error-test boreas_error-test)
target_include_directories (boreas_error-test PRIVATE ${CGREEN_INCLUDE_DIRS})
target_link_libraries (boreas_error-test
                       ${CGREEN_LIBRARIES}
                       ${GLIB_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS} ${CMAKE_THREAD_LIBS_INIT})

add_executable (boreas_io-test
                EXCLUDE_FROM_ALL
                boreas_io_tests.c boreas_error.c alivedetection.c ping.c
                sniffer.c util.c)
add_test (boreas_io-test boreas_io-test)
target_include_directories (boreas_io-test PRIVATE ${CGREEN_INCLUDE_DIRS})
target_link_libraries (boreas_io-test gvm_base_shared gvm_util_shared
                       ${PCAP_LDFLAGS}
                       ${CGREEN_LIBRARIES}
                       ${GLIB_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS} ${CMAKE_THREAD_LIBS_INIT})

add_executable (cli-test
                EXCLUDE_FROM_ALL
                cli_tests.c boreas_error.c boreas_io.c util.c)
add_test (cli-test cli-test)
target_include_directories (cli-test PRIVATE ${CGREEN_INCLUDE_DIRS})
target_link_libraries (cli-test gvm_base_shared gvm_util_shared
                      ${CGREEN_LIBRARIES}
                      ${GLIB_LDFLAGS}
                      ${LINKER_HARDENING_FLAGS} ${CMAKE_THREAD_LIBS_INIT})

add_executable (ping-test
                EXCLUDE_FROM_ALL
                ping_tests.c util.c boreas_error.c)
add_test (ping-test ping-test)
target_include_directories (ping-test PRIVATE ${CGREEN_INCLUDE_DIRS})
target_link_libraries (ping-test gvm_base_shared
                       ${CGREEN_LIBRARIES}
                       ${GLIB_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS} ${CMAKE_THREAD_LIBS_INIT})

add_executable (sniffer-test
                EXCLUDE_FROM_ALL
                sniffer_tests.c boreas_io.c util.c)
add_test (sniffer-test sniffer-test)
target_include_directories (sniffer-test PRIVATE ${CGREEN_INCLUDE_DIRS})
target_link_libraries (sniffer-test gvm_base_shared gvm_util_shared
                       ${PCAP_LDFLAGS}
                       ${CGREEN_LIBRARIES}
                       ${GLIB_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS} ${CMAKE_THREAD_LIBS_INIT})

set (UTIL_TEST_LINKER_WRAP_OPTIONS
    "-Wl,-wrap,socket,-wrap,setsockopt")
add_executable (util-test
                EXCLUDE_FROM_ALL
                util_tests.c)
add_test (util-test util-test)
target_include_directories (util-test PRIVATE ${CGREEN_INCLUDE_DIRS})
target_link_libraries (util-test gvm_base_shared
                       ${CGREEN_LIBRARIES}
                       ${GLIB_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS} ${CMAKE_THREAD_LIBS_INIT}
                       ${UTIL_TEST_LINKER_WRAP_OPTIONS})

## Install

configure_file (libgvm_boreas.pc.in ${CMAKE_BINARY_DIR}/libgvm_boreas.pc @ONLY)

install (FILES ${CMAKE_BINARY_DIR}/libgvm_boreas.pc
         DESTINATION ${LIBDIR}/pkgconfig)

if (BUILD_STATIC)
  install (TARGETS gvm_boreas_static
    RUNTIME DESTINATION ${BINDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/boreas")
endif (BUILD_STATIC)

if (BUILD_SHARED)
  install (TARGETS gvm_boreas_shared
    RUNTIME DESTINATION ${BINDIR}
    LIBRARY DESTINATION ${LIBDIR}
    ARCHIVE DESTINATION ${LIBDIR}
    PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/gvm/boreas")
endif (BUILD_SHARED)

## End
