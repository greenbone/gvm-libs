/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sshutils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <glib.h>
#include <string.h>

/* PKCS#8 Private Keys */

static const char *test_rsa_pkcs8_encrypted =
  "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
  "MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIzfBGcP5wd8MCAggA\n"
  "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBBFzFqkORQCGsovV40fuoGFBIIC\n"
  "gOWIjapbrp9CSFdlzvttFDyJWuv7jqW9Go7aCXnvqXWGDbxOlJSM8fAy4mmr0+71\n"
  "CoIywoqg/3k6tmM3xMRSzql4RaZuDosoD0bAi7CPS2FKb+rMkCzOn8/v14U0QoX6\n"
  "5lzB6a9PaTc+T5d29hPy/OxJutVOq/VvmoOng9mLcGesdEZXrXbunbJNsI0MHmzi\n"
  "lwHNAdPkdGGHyMRb3DgRYVrn5XIkVINNTLk/3iKjqAAlP/uSN3cpU0L3+FW4bF3s\n"
  "xKFktcbD/AbwRd5/W8PGHrMOaSqCiWmOCSdSa1xKNecjFN8SNAiZusp7V/H+ylyL\n"
  "GPXE1sUL7FX1InwOR9NlVXRizf0696ZvH8aRrORO+j4yGT0XUxrLpS/OQ7Ea2jHs\n"
  "EitXcC+cKTb0GRMjzp/BtK/yeiOTfo4N1ilTF9wjC+AZbZoS+qWxDxyeJ2x7TDQj\n"
  "OiTiK3XWUDGzGt/9O1qn8Bguqbidc09oZ0WdRGpYGVZiRIB2Cd6adIEdU+MK58aJ\n"
  "3qg4E5wQv9uQHoC4KRdsz2wXojXvjg55XUYjerDBAsZKXBXubguGSVDH6w2Xtqf5\n"
  "DouWZwrHI4YEaF/ObzGfniUI1DXU8l7Zxmsb+BlvwG2JUoec7gVCD45ciL0JMElf\n"
  "ZdZq+pm+LZ888GEM+4HLu9M5jS+rrj2UqKIR5IpmTa/wYdvBqJi9k4TKfa6DWPjj\n"
  "ePwQ4I35Ke6rp4mKN/oqfKoH5ArLD5JIvRtqxTcpacw2dcxudf2TMVO92EZB6IgV\n"
  "dlEZR+MS94rDuR5JwlyCd4wScg8uVL0SwOe7WFXhYDPVf3NeiHQc7ae7fE+IpJGy\n"
  "RKqIeOPYWQcUa4NgMAv3qMA=\n"
  "-----END ENCRYPTED PRIVATE KEY-----";

static const char *test_rsa_pkcs8_unencrypted =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAM1akpXjXsXSgeKC\n"
  "FTc+k9x97hGN5bECPYTvP07rod0/UeDI5GQpcA8bpyB8v1QQatYRKRIIcLt+qW3r\n"
  "qBiXDVG5WN9+ei8m3hvKzjGenbPfP9a50t86df5te1RAWbncZJPHPr4TjgFVh64+\n"
  "7QVv5HrqXLVSKczVKwLtXJaHzi/fAgMBAAECgYBrTNwzPa8Tpr7/YAE98JDKMXLn\n"
  "8UEHkKgcgfaOgkj9lkxuLApK2+wVuNlG/GfswPdSC31uUsK09aYKLYyT7Lmj/Zcb\n"
  "NnrDDcVxK3AtQIlvIgEwO766riv91vPXRiig2xHkyzFJnyDjev9F5gB36LbMU5ZN\n"
  "3lJswD6lgw30BlDMYQJBAPt2W6ws1AbfoJQJTob2hLRSAmCf/x+Fvv2lb5YINogj\n"
  "2P+vq51i4YQhYOiIO1vdl0qhfhj+TdyIQ/A7jsb5+B0CQQDRDzbHhbY0p0MUT4rX\n"
  "2Ysfrt3pEe8cHVdtT6RMiw3IUODWhlWXQJrmV1BgyEM05mgbRWMGz5xgOXG8it0y\n"
  "/h8rAkBgm1YYzZgfk+aDORgcLbVJ+X/EU3OWTrHTjK1T/I/Guc7yXDEYZBazxocO\n"
  "jtgPMRCgsW5ad8i+AvPm5VqzAvHZAkEAsWLvYCycheDGkh1L+gqkeaWutWx6LqjW\n"
  "3fGNv0Td1PKLVHt3dHdk971ufjBulhxKiZk+hTDzxtH3J7vMJNBrMQJBAL/r0j0+\n"
  "DgBywIZkjLzJwn3w4/wRl6YSr8DRgu8CtTFVozjkA177NpVzznlvfQU8RdNG3bbt\n"
  "nw3vL7hUSbuvhmY=\n"
  "-----END PRIVATE KEY-----";

static const char *test_ecdsa_pkcs8_encrypted =
  "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
  "MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAjlyxUA9O2PHAICCAAw\n"
  "DAYIKoZIhvcNAgkFADAdBglghkgBZQMEAQIEEO719labTRMgZ32j+ZnBT4YEgZBm\n"
  "xdt/8ovIPzp07r4rrOJC1tZmoZXeRW8uDMm3OxHx7lV+obwqVh+ZfJHRvFe7ggvT\n"
  "riL2tGh/eyTV5F/7mtGGhOFyjMAEgE2vT9TCwYwheQ0R690G5K+Mw3vt4xvVVtgD\n"
  "6XoSuak8bnkXri/KmSFaWD650TMmLYGqGTlAzanoNuU7+8IERwYwvOg7QXaGSbA=\n"
  "-----END ENCRYPTED PRIVATE KEY-----";

static const char *test_ecdsa_openssh_private =
  "-----BEGIN OPENSSH PRIVATE KEY-----\n"
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n"
  "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTBttsbosZ3Owlvc5aumQJd1W0LMd3X\n"
  "gi3XxeQmwiGhFd0R1SahBmxMQdp6VXCyOnuUvrTGstFrQi0t3UsAII45AAAAoHkGdWV5Bn\n"
  "VlAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMG22xuixnc7CW9z\n"
  "lq6ZAl3VbQsx3deCLdfF5CbCIaEV3RHVJqEGbExB2npVcLI6e5S+tMay0WtCLS3dSwAgjj\n"
  "kAAAAhAOuN88lVWbYX99J/AgA+VPGoBkO2oN2v1kq7wRBSNI2HAAAAAAECAwQFBgc=\n"
  "-----END OPENSSH PRIVATE KEY-----";

static const char *test_ed25519_pkcs8_encrypted =
  "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
  "MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAjJzcFV4nR8QgICCAAw\n"
  "DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEELktrSEPHfD5f7p/W2OAyusEQC8R\n"
  "d20mo9N7ywH+619oLIA52Xn7jXefbT/GXBmBPo0GaQV0f0ueg9R0g9rXXu2EgIIG\n"
  "LQXgDsbD4kdN6Op41FY=\n"
  "-----END ENCRYPTED PRIVATE KEY-----";

static const char *test_ed25519_openssh_private =
  "-----BEGIN OPENSSH PRIVATE KEY-----\n"
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
  "QyNTUxOQAAACDc//VteiCk/grV3VBgQZpTZcClYUSe/Jah00ZaETd8BAAAAIgYiPkgGIj5\n"
  "IAAAAAtzc2gtZWQyNTUxOQAAACDc//VteiCk/grV3VBgQZpTZcClYUSe/Jah00ZaETd8BA\n"
  "AAAEBFmyjnCahpsDze3hjhZTQlH3o+r3/x1b+UX/Pzbx+C2tz/9W16IKT+CtXdUGBBmlNl\n"
  "wKVhRJ78lqHTRloRN3wEAAAAAAECAwQF\n"
  "-----END OPENSSH PRIVATE KEY-----";

/* Expected Public Keys */

static const char *test_rsa_public_expected =
  "ssh-rsa "
  "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDNWpKV417F0oHighU3PpPcfe4RjeWxAj2E7z9O66HdP1Hg"
  "yORkKXAPG6cgfL9UEGrWESkSCHC7fqlt66gYlw1RuVjffnovJt4bys4xnp2z3z/"
  "WudLfOnX+bXtUQFm53GSTxz6+E44BVYeuPu0Fb+R66ly1UinM1SsC7VyWh84v3w==";

static const char *test_ecdsa_public_expected =
  "ecdsa-sha2-nistp256 "
  "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMG22xuixnc7CW9zlq6ZAl3V"
  "bQsx3deCLdfF5CbCIaEV3RHVJqEGbExB2npVcLI6e5S+tMay0WtCLS3dSwAgjjk=";

static const char *test_ed25519_public_expected =
  "ssh-ed25519 "
  "AAAAC3NzaC1lZDI1NTE5AAAAINz/9W16IKT+CtXdUGBBmlNlwKVhRJ78lqHTRloRN3wE";

static const char *expected_rsa_sha256_hash =
  "a581ce248a4a7e7a49603712d9ac4c83fdc491cc908eb430af566cb1975d7f3c";

static const char *expected_ecdsa_sha256_hash =
  "e176454f3e3de11a826e3b72a7a3971fbf823dbd464512f14340378b647c209a";

static const char *expected_ed25519_sha256_hash =
  "62ff0717d25f334662fc5d0ca4ecac4db7b5c1cf57f599aa59f664014a2898ec";

Describe (sshutils);
BeforeEach (sshutils)
{
}

AfterEach (sshutils)
{
}

/* gvm_ssh_pkcs8_decrypt */

Ensure (sshutils, gvm_ssh_pkcs8_decrypt_returns_null_for_null_pkcs8_key)
{
  char *result = gvm_ssh_pkcs8_decrypt (NULL, "passphrase");
  assert_that (result, is_null);
}

Ensure (sshutils, gvm_ssh_pkcs8_decrypt_handles_empty_passphrase)
{
  // Test functional equivalence: decrypted key should produce expected public
  // key
  char *result = gvm_ssh_pkcs8_decrypt (test_rsa_pkcs8_unencrypted, "");
  assert_that (result, is_not_null);

  // Generate public key from decrypted private key
  char *pub_from_decrypted = gvm_ssh_public_from_private (result, "");

  assert_that (pub_from_decrypted, is_not_null);
  assert_that (pub_from_decrypted,
               is_equal_to_string (test_rsa_public_expected));

  g_free (result);
  g_free (pub_from_decrypted);
}

Ensure (sshutils, gvm_ssh_pkcs8_decrypt_handles_null_passphrase)
{
  char *result = gvm_ssh_pkcs8_decrypt ("invalid_key", NULL);
  assert_that (result, is_null);
}

Ensure (sshutils, gvm_ssh_pkcs8_decrypt_returns_null_for_invalid_key)
{
  char *result =
    gvm_ssh_pkcs8_decrypt ("invalid_pkcs8_key_content", "passphrase");
  assert_that (result, is_null);
}

Ensure (sshutils, gvm_ssh_pkcs8_decrypt_decrypts_rsa_key_correctly)
{
  char *result =
    gvm_ssh_pkcs8_decrypt (test_rsa_pkcs8_encrypted, "testpass123");
  assert_that (result, is_not_null);
  assert_that (strstr (result, "-----BEGIN RSA PRIVATE KEY-----"), is_not_null);
  assert_that (strstr (result, "-----END RSA PRIVATE KEY-----"), is_not_null);
  g_free (result);
}

Ensure (sshutils, gvm_ssh_pkcs8_decrypt_decrypts_ecdsa_key_correctly)
{
  char *result =
    gvm_ssh_pkcs8_decrypt (test_ecdsa_pkcs8_encrypted, "testpass123");
  assert_that (result, is_not_null);
  assert_that (strstr (result, "-----BEGIN EC PRIVATE KEY-----"), is_not_null);
  assert_that (strstr (result, "-----END EC PRIVATE KEY-----"), is_not_null);
  g_free (result);
}

Ensure (sshutils, gvm_ssh_pkcs8_decrypt_decrypts_ed25519_key_correctly)
{
  char *result =
    gvm_ssh_pkcs8_decrypt (test_ed25519_pkcs8_encrypted, "testpass123");
  assert_that (result, is_not_null);
  assert_that (strstr (result, "-----BEGIN PRIVATE KEY-----"), is_not_null);
  assert_that (strstr (result, "-----END PRIVATE KEY-----"), is_not_null);
  g_free (result);
}

Ensure (sshutils, gvm_ssh_pkcs8_decrypt_handles_unencrypted_keys)
{
  char *result = gvm_ssh_pkcs8_decrypt (test_rsa_pkcs8_unencrypted, "");
  assert_that (result, is_not_null);
  assert_that (strstr (result, "-----BEGIN RSA PRIVATE KEY-----"), is_not_null);
  assert_that (strstr (result, "-----END RSA PRIVATE KEY-----"), is_not_null);
  g_free (result);
}

/* gvm_ssh_public_from_private */

Ensure (sshutils, gvm_ssh_public_from_private_returns_null_for_null_private_key)
{
  char *result = gvm_ssh_public_from_private (NULL, "passphrase");
  assert_that (result, is_null);
}

Ensure (sshutils, gvm_ssh_public_from_private_handles_invalid_private_key)
{
  char *result =
    gvm_ssh_public_from_private ("invalid_private_key", "passphrase");
  assert_that (result, is_null);
}

Ensure (sshutils, gvm_ssh_public_from_private_handles_null_passphrase)
{
  char *result = gvm_ssh_public_from_private ("invalid_private_key", NULL);
  assert_that (result, is_null);
}

Ensure (sshutils, gvm_ssh_public_from_private_handles_empty_passphrase)
{
  // This should successfully generate the public key
  char *result = gvm_ssh_public_from_private (test_rsa_pkcs8_unencrypted, "");
  assert_that (result, is_not_null);
  assert_that (strstr (result, "ssh-rsa"), is_not_null);
  assert_that (result, is_equal_to_string (test_rsa_public_expected));
  g_free (result);
}

Ensure (sshutils, gvm_ssh_public_from_private_generates_rsa_public_key)
{
  char *result = gvm_ssh_public_from_private (test_rsa_pkcs8_unencrypted, NULL);
  assert_that (result, is_not_null);
  assert_that (strstr (result, "ssh-rsa"), is_not_null);
  // Verify it matches expected format (type + space + base64_key)
  assert_that (strchr (result, ' '), is_not_null);
  // Verify that the generated public key matches the expected value
  assert_that (result, is_equal_to_string (test_rsa_public_expected));
  g_free (result);
}

Ensure (sshutils, gvm_ssh_public_from_private_generates_ecdsa_public_key)
{
  char *result = gvm_ssh_public_from_private (test_ecdsa_openssh_private, NULL);
  assert_that (result, is_not_null);
  assert_that (strstr (result, "ecdsa-sha2-nistp256"), is_not_null);
  assert_that (strchr (result, ' '), is_not_null);
  // Verify that the generated public key matches the expected value
  assert_that (result, is_equal_to_string (test_ecdsa_public_expected));
  g_free (result);
}

Ensure (sshutils, gvm_ssh_public_from_private_generates_ed25519_public_key)
{
  char *result =
    gvm_ssh_public_from_private (test_ed25519_openssh_private, NULL);
  assert_that (result, is_not_null);
  assert_that (strstr (result, "ssh-ed25519"), is_not_null);
  assert_that (strchr (result, ' '), is_not_null);
  // Verify that the generated public key matches the expected value
  assert_that (result, is_equal_to_string (test_ed25519_public_expected));
  g_free (result);
}

Ensure (sshutils, gvm_ssh_public_from_private_handles_encrypted_keys)
{
  char *result =
    gvm_ssh_public_from_private (test_rsa_pkcs8_encrypted, "testpass123");
  assert_that (result, is_not_null);
  assert_that (strstr (result, "ssh-rsa"), is_not_null);
  g_free (result);
}

Ensure (sshutils, gvm_ssh_public_from_private_handles_wrong_passphrase)
{
  char *result =
    gvm_ssh_public_from_private (test_rsa_pkcs8_encrypted, "wrongpass");
  assert_that (result, is_null);
}

/* gvm_ssh_private_key_info */

Ensure (sshutils,
        gvm_ssh_private_key_info_returns_minus_one_for_null_private_key)
{
  const char *type = NULL;
  char *sha256_hash = NULL;
  int result =
    gvm_ssh_private_key_info (NULL, "passphrase", &type, &sha256_hash);
  assert_that (result, is_equal_to (-1));
  assert_that (type, is_null);
  assert_that (sha256_hash, is_null);
}

Ensure (sshutils, gvm_ssh_private_key_info_handles_null_type_and_hash_pointers)
{
  int result =
    gvm_ssh_private_key_info ("invalid_key", "passphrase", NULL, NULL);
  assert_that (result, is_equal_to (-1));
}

Ensure (sshutils, gvm_ssh_private_key_info_handles_null_type_pointer)
{
  char *sha256_hash = NULL;
  int result =
    gvm_ssh_private_key_info ("invalid_key", "passphrase", NULL, &sha256_hash);
  assert_that (result, is_equal_to (-1));
  assert_that (sha256_hash, is_null);
}

Ensure (sshutils, gvm_ssh_private_key_info_handles_null_hash_pointer)
{
  const char *type = NULL;
  int result =
    gvm_ssh_private_key_info ("invalid_key", "passphrase", &type, NULL);
  assert_that (result, is_equal_to (-1));
  assert_that (type, is_null);
}

Ensure (sshutils, gvm_ssh_private_key_info_handles_invalid_private_key)
{
  const char *type = NULL;
  char *sha256_hash = NULL;
  int result = gvm_ssh_private_key_info ("invalid_private_key", "passphrase",
                                         &type, &sha256_hash);
  assert_that (result, is_equal_to (-1));
  assert_that (type, is_null);
  assert_that (sha256_hash, is_null);
}

Ensure (sshutils, gvm_ssh_private_key_info_handles_null_passphrase)
{
  const char *type = NULL;
  char *sha256_hash = NULL;
  int result =
    gvm_ssh_private_key_info ("invalid_private_key", NULL, &type, &sha256_hash);
  assert_that (result, is_equal_to (-1));
  assert_that (type, is_null);
  assert_that (sha256_hash, is_null);
}

Ensure (sshutils, gvm_ssh_private_key_info_handles_empty_passphrase)
{
  const char *type = NULL;
  char *sha256_hash = NULL;
  // This should successfully extract the key information
  int result = gvm_ssh_private_key_info (test_rsa_pkcs8_unencrypted, "", &type,
                                         &sha256_hash);
  assert_that (result, is_equal_to (0));
  assert_that (type, is_not_null);
  assert_that (sha256_hash, is_not_null);
  // Verify that the extracted type and hash match the expected values
  assert_that (type, is_equal_to_string ("ssh-rsa"));
  assert_that (sha256_hash, is_equal_to_string (expected_rsa_sha256_hash));
  g_free (sha256_hash);
}

Ensure (sshutils, gvm_ssh_private_key_info_gets_rsa_key_type_and_hash)
{
  const char *type = NULL;
  char *sha256_hash = NULL;
  int result = gvm_ssh_private_key_info (test_rsa_pkcs8_unencrypted, NULL,
                                         &type, &sha256_hash);
  assert_that (result, is_equal_to (0));
  assert_that (type, is_equal_to_string ("ssh-rsa"));
  assert_that (sha256_hash, is_not_null);
  assert_that (strlen (sha256_hash),
               is_equal_to (64)); // SHA-256 hex is 64 chars
  /* Verify that the hash matches the expected value */
  assert_that (sha256_hash, is_equal_to_string (expected_rsa_sha256_hash));
  g_free (sha256_hash);
}

Ensure (sshutils, gvm_ssh_private_key_info_gets_ecdsa_key_type_and_hash)
{
  const char *type = NULL;
  char *sha256_hash = NULL;
  int result = gvm_ssh_private_key_info (test_ecdsa_openssh_private, NULL,
                                         &type, &sha256_hash);
  assert_that (result, is_equal_to (0));
  assert_that (type, is_equal_to_string ("ecdsa-sha2-nistp256"));
  assert_that (sha256_hash, is_not_null);
  assert_that (strlen (sha256_hash),
               is_equal_to (64)); // SHA-256 hex is 64 chars
  /* Verify that the hash matches the expected value */
  assert_that (sha256_hash, is_equal_to_string (expected_ecdsa_sha256_hash));
  g_free (sha256_hash);
}

Ensure (sshutils, gvm_ssh_private_key_info_gets_ed25519_key_type_and_hash)
{
  const char *type = NULL;
  char *sha256_hash = NULL;
  int result = gvm_ssh_private_key_info (test_ed25519_openssh_private, NULL,
                                         &type, &sha256_hash);
  assert_that (result, is_equal_to (0));
  assert_that (type, is_equal_to_string ("ssh-ed25519"));
  assert_that (sha256_hash, is_not_null);
  assert_that (strlen (sha256_hash),
               is_equal_to (64)); // SHA-256 hex is 64 chars
  /* Verify that the hash matches the expected value */
  assert_that (sha256_hash, is_equal_to_string (expected_ed25519_sha256_hash));
  g_free (sha256_hash);
}

Ensure (sshutils, gvm_ssh_private_key_info_handles_encrypted_keys)
{
  const char *type = NULL;
  char *sha256_hash = NULL;
  int result = gvm_ssh_private_key_info (test_rsa_pkcs8_encrypted,
                                         "testpass123", &type, &sha256_hash);
  assert_that (result, is_equal_to (0));
  assert_that (type, is_equal_to_string ("ssh-rsa"));
  assert_that (sha256_hash, is_not_null);
  g_free (sha256_hash);
}

Ensure (sshutils, gvm_ssh_private_key_info_handles_wrong_passphrase)
{
  const char *type = NULL;
  char *sha256_hash = NULL;
  int result = gvm_ssh_private_key_info (test_rsa_pkcs8_encrypted, "wrongpass",
                                         &type, &sha256_hash);
  assert_that (result, is_equal_to (-1));
  assert_that (type, is_null);
  assert_that (sha256_hash, is_null);
}

Ensure (sshutils, gvm_ssh_private_key_info_can_get_just_type)
{
  const char *type = NULL;
  int result =
    gvm_ssh_private_key_info (test_rsa_pkcs8_unencrypted, NULL, &type, NULL);
  assert_that (result, is_equal_to (0));
  assert_that (type, is_equal_to_string ("ssh-rsa"));
}

Ensure (sshutils, gvm_ssh_private_key_info_can_get_just_hash)
{
  char *sha256_hash = NULL;
  int result = gvm_ssh_private_key_info (test_rsa_pkcs8_unencrypted, NULL, NULL,
                                         &sha256_hash);
  assert_that (result, is_equal_to (0));
  assert_that (sha256_hash, is_not_null);
  assert_that (strlen (sha256_hash),
               is_equal_to (64)); // SHA-256 hex is 64 chars
  g_free (sha256_hash);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  /* TODO segv
  add_test_with_context (suite, sshutils,
                         gvm_ssh_pkcs8_decrypt_returns_null_for_null_pkcs8_key);
  */
  add_test_with_context (suite, sshutils,
                         gvm_ssh_pkcs8_decrypt_handles_empty_passphrase);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_pkcs8_decrypt_handles_null_passphrase);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_pkcs8_decrypt_returns_null_for_invalid_key);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_pkcs8_decrypt_decrypts_rsa_key_correctly);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_pkcs8_decrypt_decrypts_ecdsa_key_correctly);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_pkcs8_decrypt_decrypts_ed25519_key_correctly);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_pkcs8_decrypt_handles_unencrypted_keys);

  add_test_with_context (
    suite, sshutils,
    gvm_ssh_public_from_private_returns_null_for_null_private_key);
  add_test_with_context (
    suite, sshutils, gvm_ssh_public_from_private_handles_invalid_private_key);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_public_from_private_handles_null_passphrase);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_public_from_private_handles_empty_passphrase);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_public_from_private_generates_rsa_public_key);
  add_test_with_context (
    suite, sshutils, gvm_ssh_public_from_private_generates_ecdsa_public_key);
  add_test_with_context (
    suite, sshutils, gvm_ssh_public_from_private_generates_ed25519_public_key);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_public_from_private_handles_encrypted_keys);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_public_from_private_handles_wrong_passphrase);

  add_test_with_context (
    suite, sshutils,
    gvm_ssh_private_key_info_returns_minus_one_for_null_private_key);
  add_test_with_context (
    suite, sshutils,
    gvm_ssh_private_key_info_handles_null_type_and_hash_pointers);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_private_key_info_handles_null_type_pointer);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_private_key_info_handles_null_hash_pointer);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_private_key_info_handles_invalid_private_key);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_private_key_info_handles_null_passphrase);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_private_key_info_handles_empty_passphrase);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_private_key_info_gets_rsa_key_type_and_hash);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_private_key_info_gets_ecdsa_key_type_and_hash);
  add_test_with_context (
    suite, sshutils, gvm_ssh_private_key_info_gets_ed25519_key_type_and_hash);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_private_key_info_handles_encrypted_keys);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_private_key_info_handles_wrong_passphrase);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_private_key_info_can_get_just_type);
  add_test_with_context (suite, sshutils,
                         gvm_ssh_private_key_info_can_get_just_hash);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
