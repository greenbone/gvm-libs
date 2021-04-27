/* Copyright (C) 2019-2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "passwordbasedauthentication.c"
#include "authutils.h"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <string.h>
Describe (PBA);
BeforeEach (PBA)
{
}
AfterEach (PBA)
{
}

Ensure (PBA, returns_false_on_not_phc_compliant_setting)
{
    assert_false(pba_is_phc_compliant(NULL));
    assert_false(pba_is_phc_compliant("$"));
    assert_false(pba_is_phc_compliant("password"));
}
Ensure (PBA, returns_true_on_phc_compliant_setting)
{
    assert_true(pba_is_phc_compliant("$password"));
}
Ensure (PBA, returns_NULL_on_unsupport_settings)
{
    struct PBASettings setting = { "0000", 20000, "$6$"};
    assert_false(pba_hash(NULL, "*password"));
    assert_false(pba_hash(&setting, NULL));
    setting.prefix = "$1$";
    assert_false(pba_hash(&setting, "*password"));
}
Ensure (PBA, unique_hash_without_adding_used_pepper)
{
    struct PBASettings setting = { "4242", 20000, "$6$"};
    char *cmp_hash, *hash;
    hash = pba_hash(&setting, "*password");
    assert_not_equal(hash, NULL);
    assert_false(string_contains(hash, setting.pepper));
    cmp_hash = pba_hash(&setting, "*password");
    assert_string_not_equal(hash, cmp_hash);
    free(hash);
    free(cmp_hash);
}
Ensure (PBA, verify_hash)
{
    struct PBASettings setting = { "4242" , 20000, "$6$"};
    char *hash;
    hash = pba_hash(&setting, "*password");
    assert_not_equal(hash, NULL);
    assert_equal(pba_verify_hash(&setting, hash, "*password"), VALID);
    assert_equal(pba_verify_hash(&setting, hash, "*password1"), INVALID);
    free(hash);
    struct PBASettings setting_wo_pepper = { "\0\0\0\0" , 20000, "$6$"};
    hash = pba_hash(&setting_wo_pepper, "*password");
    assert_equal(pba_verify_hash(&setting_wo_pepper, hash, "*password"), VALID);
    free(hash);
}

Ensure (PBA, defaults)
{
    int i;
    struct PBASettings *settings = pba_init(NULL, 0, 0, NULL);
    assert_equal(settings->count, 20000);
    for (i = 0; i < MAX_PEPPER_SIZE; i++)
        assert_equal_with_message(settings->pepper[i], 0, "init_without_pepper_should_not_have_pepper");
    assert_string_equal(settings->prefix, "$6$");
    pba_finalize(settings);

}
Ensure (PBA, initialization)
{
    int i;
    struct PBASettings *settings = pba_init("444", 3, 1, "$6$");
    assert_equal(settings->count, 1);
    for (i = 0; i < MAX_PEPPER_SIZE - 1; i++)
        assert_equal_with_message(settings->pepper[i], '4', "init_with_pepper_should_be_set");
    assert_equal_with_message(settings->pepper[MAX_PEPPER_SIZE -1], '\0', "last_pepper_should_be_unset_by_pepper_3");
    assert_string_equal(settings->prefix, "$6$");
    pba_finalize(settings);
    settings = pba_init("444", MAX_PEPPER_SIZE + 1, 1, "$6$");
    assert_equal_with_message(settings, NULL, "should_fail_due_to_too_much_pepper");
    settings = pba_init("444", MAX_PEPPER_SIZE, 1, "$WALDFEE$");
    assert_equal_with_message(settings, NULL, "should_fail_due_to_unknown_prefix");

}

Ensure (PBA, handle_md5_hash)
{
    struct PBASettings *settings = pba_init(NULL, 0, 0, NULL);
    char *hash;
    assert_equal(gvm_auth_init(), 0);
    hash = get_password_hashes ("admin");
    assert_equal(pba_verify_hash(settings, hash, "admin"), UPDATE_RECOMMENDED);
    pba_finalize(settings);
}

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, PBA,
                         returns_false_on_not_phc_compliant_setting);
  add_test_with_context (suite, PBA,
                         returns_true_on_phc_compliant_setting);
  add_test_with_context (suite, PBA,
                         returns_NULL_on_unsupport_settings);
  add_test_with_context (suite, PBA,
                         unique_hash_without_adding_used_pepper);
  add_test_with_context (suite, PBA,
                         verify_hash);
  add_test_with_context (suite, PBA,
                         handle_md5_hash);
  add_test_with_context (suite, PBA,
                         defaults);
  add_test_with_context (suite, PBA,
                         initialization);
  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());
  return run_test_suite (suite, create_text_reporter ());
}
