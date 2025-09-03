/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "logging_domain.h"

/**
 * @struct gvm_logging_t
 * @brief Logging stores the parameters loaded from a log configuration
 * @brief file, to be used internally by the gvm_logging module only.
 */
struct gvm_logging_domain
{
  gchar *log_domain;          ///< Affected logdomain e.g libnasl.
  gchar *prepend_string;      ///< Prepend this string before every message.
  gchar *prepend_time_format; ///< If prependstring has %t, format for strftime.
  gchar *log_file;            ///< Where to log to.
  GLogLevelFlags *default_level; ///< What severity level to use as default.
  GIOChannel *log_channel;       ///< Gio Channel - FD holder for logfile.
  gchar *syslog_facility;        ///< Syslog facility to use for syslog logging.
  gchar *syslog_ident;           ///< Syslog ident to use for syslog logging.
  gchar *prepend_separator; ///< If prependstring has %s, used this symbol as
                            ///< separator.
};

/**
 * @brief Function to initialize logging instance.
 *
 * This function is responsible for setting up the logging mechanism
 * and returning a pointer to the logging struct. It ensures that
 * the logging struct is properly configured before use.
 *
 * @param log_domain A string containing the log domain to be used.
 *                   Gets owned by the logging domain and must not be freed.
 *
 * @return gvm_logging_t* Pointer to the new logging struct.
 */
gvm_logging_domain_t *
gvm_logging_domain_new (gchar *log_domain)
{
  gvm_logging_domain_t *log_domain_entry;
  /* Create the struct. */
  log_domain_entry = g_malloc (sizeof (gvm_logging_domain_t));
  /* Set the logdomain. */
  log_domain_entry->log_domain = log_domain;
  /* Initialize everything else to NULL. */
  log_domain_entry->prepend_string = NULL;
  log_domain_entry->prepend_time_format = NULL;
  log_domain_entry->log_file = NULL;
  log_domain_entry->default_level = NULL;
  log_domain_entry->log_channel = NULL;
  log_domain_entry->syslog_facility = NULL;
  log_domain_entry->syslog_ident = NULL;
  log_domain_entry->prepend_separator = NULL;

  return log_domain_entry;
}

/**
 * @brief Frees the resources associated with the given logging domain
 *
 * Frees the resources associated with the given logging domain.
 * This function should be called when the logging domain is no longer needed
 * to ensure that all allocated resources are properly released.
 *
 * @param log_domain A pointer to a gvm_logging_t structure representing the
 *                   logging domain to be freed.
 *
 */
void
gvm_logging_domain_free (gvm_logging_domain_t *log_domain)
{
  g_free (log_domain->log_domain);
  g_free (log_domain->prepend_string);
  g_free (log_domain->prepend_time_format);
  g_free (log_domain->log_file);
  g_free (log_domain->default_level);
  g_free (log_domain->syslog_facility);
  g_free (log_domain->syslog_ident);
  g_free (log_domain->prepend_separator);

  /* Drop the reference to the GIOChannel. */
  if (log_domain->log_channel)
    g_io_channel_unref (log_domain->log_channel);

  /* Free the struct. */
  g_free (log_domain);
}

/**
 * Retrieves the log domain associated with the given logging domain.
 *
 * The returned log domain is still owned by the logging domain and should not
 * be freed by the caller.
 *
 * @param log_domain A pointer to a gvm_logging_domain_t structure.
 *
 * @return The log domain associated with the logging domain or NULL
 */
gchar *
gvm_logging_domain_get_log_domain (gvm_logging_domain_t *log_domain)
{
  return log_domain->log_domain;
}

/**
 * Retrieves the log file associated with the given logging domain.
 *
 * The returned log file is still owned by the logging domain and should not
 * be freed by the caller.
 *
 * @param log_domain A pointer to a gvm_logging_domain_t structure.
 *
 * @return The log file associated with the logging domain or NULL
 */
gchar *
gvm_logging_domain_get_log_file (gvm_logging_domain_t *log_domain)
{
  return log_domain->log_file;
}

/**
 * @brief Sets the log file for the logging domain.
 *
 * This function sets the file to which log messages for the specified logging
 * domain will be written.
 *
 * @param log_domain The logging domain for which the log file is to be set.
 * @param log_file The path to the log file. Gets owned by the logging domain
 *                 and must not be freed.
 */
void
gvm_logging_domain_set_log_file (gvm_logging_domain_t *log_domain,
                                 gchar *log_file)
{
  g_free (log_domain->log_file);
  log_domain->log_file = log_file;
}

/**
 * Retrieves the prepend string associated with the given logging domain.
 *
 * The returned prepend string is still owned by the logging domain and should
 * not be freed by the caller.
 *
 * @param log_domain A pointer to a gvm_logging_domain_t structure.
 *
 * @return The prepend string associated with the logging domain or NULL
 */
gchar *
gvm_logging_domain_get_prepend_string (gvm_logging_domain_t *log_domain)
{
  return log_domain->prepend_string;
}

/**
 * @brief Sets the preprend string for the logging domain.
 *
 * This function sets the string that will be prepended to every log message
 *
 * @param log_domain The logging domain for which the prepend string is to be
 *                   set.
 * @param prepend_string The string to prepend. Gets owned by the logging domain
 *                       and must not be freed.
 */
void
gvm_logging_domain_set_prepend_string (gvm_logging_domain_t *log_domain,
                                       gchar *prepend_string)
{
  g_free (log_domain->prepend_string);
  log_domain->prepend_string = prepend_string;
}

/**
 * Retrieves the prepend time format associated with the given logging domain.
 *
 * The returned prepend time format is still owned by the logging domain and
 * should not be freed by the caller.
 *
 * @param log_domain A pointer to a gvm_logging_domain_t structure.
 *
 * @return The prepend time format associated with the logging domain or NULL
 */
gchar *
gvm_logging_domain_get_prepend_time_format (gvm_logging_domain_t *log_domain)
{
  return log_domain->prepend_time_format;
}

/**
 * @brief Sets the prepend time format for the logging domain.
 *
 * This function sets the time format that will be used when %t is present in
 * the prepend string.
 *
 * @param log_domain The logging domain for which the prepend time format is to
 *                   be set.
 * @param prepend_time_format The time format to set. Gets owned by the logging
 *                            domain and must not be freed.
 */
void
gvm_logging_domain_set_prepend_time_format (gvm_logging_domain_t *log_domain,
                                            gchar *prepend_time_format)
{
  g_free (log_domain->prepend_time_format);
  log_domain->prepend_time_format = prepend_time_format;
}

/**
 * Retrieves the default log level associated with the given logging domain.
 *
 * The returned default log level is still owned by the logging domain and
 * should not be freed by the caller.
 *
 * @param log_domain A pointer to a gvm_logging_domain_t structure.
 *
 * @return The default log level associated with the logging domain or NULL
 */
GLogLevelFlags *
gvm_logging_domain_get_default_level (gvm_logging_domain_t *log_domain)
{
  return log_domain->default_level;
}

/**
 * @brief Sets the default log level for the logging domain.
 *
 * This function sets the default log level for the specified logging domain.
 *
 * @param log_domain The logging domain for which the default log level is to be
 *                   set.
 * @param default_level The default log level to set.
 */
void
gvm_logging_domain_set_default_level (gvm_logging_domain_t *log_domain,
                                      GLogLevelFlags default_level)
{
  g_free (log_domain->default_level);
  log_domain->default_level = g_malloc (sizeof (gint));
  *log_domain->default_level = default_level;
}

/**
 * Retrieves the syslog facility associated with the given logging domain.
 *
 * The returned syslog facility is still owned by the logging domain and should
 * not be freed by the caller.
 *
 * @param log_domain A pointer to a gvm_logging_domain_t structure.
 *
 * @return The syslog facility associated with the logging domain or NULL
 */
gchar *
gvm_logging_domain_get_syslog_facility (gvm_logging_domain_t *log_domain)
{
  return log_domain->syslog_facility;
}

/**
 * @brief Sets the syslog facility for the logging domain.
 *
 * This function sets the syslog facility for the specified logging domain.
 *
 * @param log_domain The logging domain for which the syslog facility is to be
 *                   set.
 * @param syslog_facility The syslog facility to set. Gets owned by the logging
 *                        domain and must not be freed.
 */
void
gvm_logging_domain_set_syslog_facility (gvm_logging_domain_t *log_domain,
                                        gchar *syslog_facility)
{
  g_free (log_domain->syslog_facility);
  log_domain->syslog_facility = syslog_facility;
}

/**
 * Retrieves the syslog ident associated with the given logging domain.
 *
 * The returned syslog ident is still owned by the logging domain and should
 * not be freed by the caller.
 *
 * @param log_domain A pointer to a gvm_logging_domain_t structure.
 *
 * @return The syslog ident associated with the logging domain or NULL
 */
gchar *
gvm_logging_domain_get_syslog_ident (gvm_logging_domain_t *log_domain)
{
  return log_domain->syslog_ident;
}

/**
 * @brief Sets the syslog ident for the logging domain.
 *
 * This function sets the syslog ident for the specified logging domain.
 *
 * @param log_domain The logging domain for which the syslog ident is to be set.
 * @param syslog_ident The syslog ident to set. Gets owned by the logging domain
 *                     and must not be freed.
 */
void
gvm_logging_domain_set_syslog_ident (gvm_logging_domain_t *log_domain,
                                     gchar *syslog_ident)
{
  g_free (log_domain->syslog_ident);
  log_domain->syslog_ident = syslog_ident;
}

/**
 * Retrieves the prepend separator associated with the given logging domain.
 *
 * The returned prepend separator is still owned by the logging domain and
 * should not be freed by the caller.
 *
 * @param log_domain A pointer to a gvm_logging_domain_t structure.
 *
 * @return The prepend separator associated with the logging domain or NULL
 */
gchar *
gvm_logging_domain_get_prepend_separator (gvm_logging_domain_t *log_domain)
{
  return log_domain->prepend_separator;
}

/**
 * @brief Sets the prepend separator for the logging domain.
 *
 * This function sets the prepend separator for the specified logging domain.
 *
 * @param log_domain The logging domain for which the prepend separator is to be
 *                   set.
 * @param prepend_separator The prepend separator to set. Gets owned by the
 *                          logging domain and must not be freed.
 */
void
gvm_logging_domain_set_prepend_separator (gvm_logging_domain_t *log_domain,
                                          gchar *prepend_separator)
{
  g_free (log_domain->prepend_separator);
  log_domain->prepend_separator = prepend_separator;
}

/**
 * Retrieves the log channel associated with the given logging domain.
 *
 * The returned log channel is still owned by the logging domain and should
 * not be freed by the caller.
 *
 * @param log_domain A pointer to a gvm_logging_domain_t structure.
 *
 * @return The log channel associated with the logging domain or NULL
 */
GIOChannel *
gvm_logging_domain_get_log_channel (gvm_logging_domain_t *log_domain)
{
  return log_domain->log_channel;
}

/**
 * @brief Sets the log channel for the logging domain.
 *
 * This function sets the log channel for the specified logging domain.
 *
 * @param log_domain The logging domain for which the log channel is to be set.
 * @param log_channel The log channel to set. Gets referenced by the logging and
 *                    unreferenced when the logging domain is freed.
 */
void
gvm_logging_domain_set_log_channel (gvm_logging_domain_t *log_domain,
                                    GIOChannel *log_channel)
{
  if (log_domain->log_channel)
    g_io_channel_unref (log_domain->log_channel);
  log_domain->log_channel = log_channel;
  if (log_channel)
    g_io_channel_ref (log_channel);
}
