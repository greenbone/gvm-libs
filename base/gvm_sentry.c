/* SPDX-FileCopyrightText: 2017-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Implementation of sentry methods.
 *
 * This file contains all methods needed for sentry. To enable sentry and log
 * log in the sentry server, methods in this file are called.
 *
 */

#include "gvm_sentry.h"

#include <stdio.h>

/**
 * @brief Check for sentry support
 *
 * @return 1 if gvm-libs has been built with sentry support, 0 otherwise.
 *
 */
int
gvm_has_sentry_support ()
{
#ifdef HAVE_SENTRY
  return 1;
#endif /* HAVE_SENTRY */
  return 0;
}

#ifdef HAVE_SENTRY
int global_init_sentry = 0;

/**
 * @brief Set global_init_sentry
 */
static void
set_init_sentry ()
{
  global_init_sentry = 1;
}

/**
 * @brief Reset global_init_sentry
 */
static void
reset_init_sentry ()
{
  global_init_sentry = 0;
}

/**
 * @brief Return if sentry was initialized or not
 */
static int
is_sentry_initialized ()
{
  return global_init_sentry;
}
#endif /* HAVE_SENTRY */

/**
 * @brief Initialize Sentry
 *
 * The function does nothing if HAVE_SENTRY is not defined
 *
 * @param[in] dsn Sentry DSN
 * @param[in] release Module release to be sent to Sentry.
 */
void
gvm_sentry_init (const char *dsn, const char *release)
{
#ifdef HAVE_SENTRY
  sentry_options_t *options = sentry_options_new ();
  sentry_options_set_dsn (options, dsn);
  sentry_options_set_release (options, release);
  sentry_options_set_sample_rate (options, 1.0);
  sentry_init (options);
  set_init_sentry ();
#else
  (void) dsn;
  (void) release;
#endif /* HAVE_SENTRY */
}

/**
 * @brief Send a message to Sentry server if it was initialized
 *
 * The function does nothing if HAVE_SENTRY is not defined
 *
 * @param[in] message Message to send
 */
void
gvm_sentry_log (const char *message)
{
#ifdef HAVE_SENTRY
  if (is_sentry_initialized ())
    {
      sentry_capture_event (sentry_value_new_message_event (
        /*   level */ SENTRY_LEVEL_INFO,
        /*  logger */ "custom",
        /* message */ message));
    }
#else
  (void) message;
#endif /* HAVE_SENTRY */
}

/**
 * @brief Shutdown Sentry if it was initialized.
 *
 * This function must be called before exiting to ensure that all
 * message has been sent to Sentry.
 *
 * The function does nothing if HAVE_SENTRY is not defined
 *
 */
void
gvm_close_sentry (void)
{
#ifdef HAVE_SENTRY
  if (is_sentry_initialized ())
    {
      sentry_close ();
      reset_init_sentry ();
    }
#endif /* HAVE_SENTRY */
}
