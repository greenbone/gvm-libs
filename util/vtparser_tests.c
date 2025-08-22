/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "../base/nvti.h"
#include "vtparser.c"

#include <cgreen/assertions.h>
#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/internal/c_assertions.h>
#include <cgreen/mocks.h>

#define VT_NAME "Example: Security Advisory for eg (EXAMPLE-2025-cb7b)"

#define VT                                                                     \
  "{"                                                                          \
  "  \"oid\": \"1.3.6.1.4.1.25623.1.0.877440\","                               \
  "  \"name\": \"" VT_NAME "\","                                               \
  "  \"filename\": \"2020/fedora/gb_fedora_2020_cb7b7181a0_sox_fc30.nasl\","   \
  "  \"tag\": {"                                                               \
  "    \"affected\": \"'sox' package(s) on Fedora 30.\","                      \
  "    \"creation_date\": 1581134661,"                                         \
  "    \"cvss_base_vector\": \"AV:N/AC:L/Au:N/C:N/I:N/A:P\","                  \
  "    \"insight\": \"SoX (Sound eXchange) is a sound file format...\","       \
  "    \"last_modification\": 1626919250,"                                     \
  "    \"qod_type\": \"package\","                                             \
  "    \"severity_date\": 1624547760,"                                         \
  "    \"severity_origin\": \"NVD\","                                          \
  "    \"severity_vector\": \"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\"," \
  "    \"solution\": \"Please install the updated package(s).\","              \
  "    \"solution_type\": \"VendorFix\","                                      \
  "    \"summary\": \"The remote host is missing an update for ...\""          \
  "  },"                                                                       \
  "  \"dependencies\": ["                                                      \
  "    \"gather-package-list.nasl\""                                           \
  "  ],"                                                                       \
  "  \"required_keys\": [],"                                                   \
  "  \"mandatory_keys\": ["                                                    \
  "    \"ssh/login/fedora\","                                                  \
  "    \"ssh/login/rpms\","                                                    \
  "    \"ssh/login/release=FC30\""                                             \
  "  ],"                                                                       \
  "  \"excluded_keys\": [],"                                                   \
  "  \"required_ports\": [],"                                                  \
  "  \"required_udp_ports\": [],"                                              \
  "  \"references\": ["                                                        \
  "    {"                                                                      \
  "      \"class\": \"cve\","                                                  \
  "      \"id\": \"CVE-2017-18189\""                                           \
  "    },"                                                                     \
  "    {"                                                                      \
  "      \"class\": \"2020-cb7b7181a0\","                                      \
  "      \"id\": \"FEDORA\""                                                   \
  "    },"                                                                     \
  "    {"                                                                      \
  "      \"class\": \"https://example.org/ann/EG-IZ3CX\","                     \
  "      \"id\": \"URL\""                                                      \
  "    }"                                                                      \
  "  ],"                                                                       \
  "  \"preferences\": [],"                                                     \
  "  \"category\": \"gather_info\","                                           \
  "  \"family\": \"Fedora Local Security Checks\""                             \
  "  }"

Describe (vtparser);
BeforeEach (vtparser)
{
}

AfterEach (vtparser)
{
}

static FILE *
memopen (const gchar *str)
{
  return fmemopen ((void *) str, strlen (str), "r");
}

/* parse_vt_json */

Ensure (vtparser, parse_vt_json_parses_a_vt)
{
  gvm_json_pull_parser_t parser;
  gvm_json_pull_event_t event;
  FILE *file;
  nvti_t *nvt;

  file = memopen ("[" VT "]");
  assert_that (file, is_not_null);

  gvm_json_pull_event_init (&event);

  gvm_json_pull_parser_init (&parser, file);

  gvm_json_pull_parser_next (&parser, &event);

  parse_vt_json (&parser, &event, &nvt);
  assert_that (nvt, is_not_null);
  assert_that (nvti_name (nvt), is_equal_to_string (VT_NAME));
  assert_that (nvti_refs (nvt, NULL, NULL, 1),
               is_equal_to_string ("cve:CVE-2017-18189,"
                                   " 2020-cb7b7181a0:FEDORA,"
                                   " https://example.org/ann/EG-IZ3CX:URL"));

  gvm_json_pull_event_cleanup (&event);
  gvm_json_pull_parser_cleanup (&parser);
  fclose (file);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, vtparser, parse_vt_json_parses_a_vt);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
