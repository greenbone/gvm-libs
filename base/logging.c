/* SPDX-FileCopyrightText: 2017-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Implementation of logging methods.
 *
 * This file contains all methods needed for logging. To enable logging,
 * methods in this file are called.
 *
 * The module reuses glib datatypes and api for memory management and logging.
 */

#include "logging.h"

#include "gvm_sentry.h" /* for gvm_sentry_log */
#include "logging_domain.h"

#include <errno.h>  /* for errno */
#include <libgen.h> /* for dirname */
#include <stdio.h>  /* for fflush, fprintf, stderr */
#include <stdlib.h> /* for atoi */
#include <string.h> /* for strcasecmp, strlen, strerror */
#define SYSLOG_NAMES
#include <syslog.h> /* for LOG_INFO, facilitynames, closelog, openlog */
#undef SYSLOG_NAMES
#include <time.h>   /* for localtime, time, time_t */
#include <unistd.h> /* for getpid */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm base"

/**
 * @brief Timezone to use for logs.
 *
 * NULL means to use the current timezone.
 */
static gchar *log_tz = NULL;

/**
 * @brief Returns time as specified in time_fmt strftime format.
 *
 * @param time_fmt ptr to the string format to use. The strftime
 *        man page documents the conversion specification. An
 *        example time_fmt string is "%Y-%m-%d %H:%M:%S".
 *
 * @return NULL in case the format string is NULL. A ptr to a
 *         string that contains the formatted date time value.
 *         This value must be freed using glib's g_free.
 */
gchar *
get_time (gchar *time_fmt)
{
  time_t now;
  struct tm ts;
  gchar buf[80], *original_tz;

  if (!time_fmt)
    return NULL;

  if (log_tz)
    {
      original_tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;
      setenv ("TZ", log_tz, 1);
      tzset ();
    }

  /* Get the current time. */
  now = time (NULL);

  /* Format and print the time, "ddd yyyy-mm-dd hh:mm:ss zzz." */
  localtime_r (&now, &ts);
  strftime (buf, sizeof (buf), time_fmt, &ts);

  if (log_tz)
    {
      /* Revert to stored TZ. */
      if (original_tz)
        {
          setenv ("TZ", original_tz, 1);
          g_free (original_tz);
          tzset ();
        }
      else
        unsetenv ("TZ");
    }

  return g_strdup_printf ("%s", buf);
}

/**
 * @brief Return the integer corresponding to a log level string.
 *
 * @param level Level name or integer.
 *
 * @return Log level integer if level matches a level name, else 0.
 */
static gint
level_int_from_string (const gchar *level)
{
  if (level && strlen (level) > 0)
    {
      if (level[0] >= '0' && level[0] <= '9')
        return atoi (level);
      if (strcasecmp (level, "critical") == 0)
        return G_LOG_LEVEL_CRITICAL;
      if (strcasecmp (level, "debug") == 0)
        return G_LOG_LEVEL_DEBUG;
      if (strcasecmp (level, "error") == 0)
        return G_LOG_LEVEL_ERROR;
      if (strcasecmp (level, "info") == 0)
        return G_LOG_LEVEL_INFO;
      if (strcasecmp (level, "message") == 0)
        return G_LOG_LEVEL_MESSAGE;
      if (strcasecmp (level, "warning") == 0)
        return G_LOG_LEVEL_WARNING;
    }
  return 0;
}

/**
 * @brief Return the integer corresponding to a syslog facility string.
 *
 * @param facility Facility name.
 *
 * @return Facility integer if facility matches a facility name, else
 * LOG_LOCAL0.
 */
static gint
facility_int_from_string (const gchar *facility)
{
  if (facility && strlen (facility) > 0)
    {
      int i = 0;
      while (facilitynames[i].c_name != NULL)
        {
          if (g_ascii_strcasecmp (facility, facilitynames[i].c_name) == 0)
            return facilitynames[i].c_val;
          i++;
        }
    }
  return LOG_LOCAL0;
}

/**
 * @brief Loads parameters from a config file into a linked list.
 *
 * @param config_file A string containing the path to the configuration file
 *                   to load.
 *
 * @return NULL in case the config file could not be loaded or an error
 *         occurred otherwise, a singly linked list of parameter groups
 *         is returned.
 */
GSList *
load_log_configuration (gchar *config_file)
{
  GKeyFile *key_file;
  GKeyFileFlags flags;
  GError *error = NULL;
  /* key_file *_has_* functions requires this. */

  // FIXME: If a g_* function that takes error fails, then free error.

  /* Groups found in the conf file. */
  gchar **groups;
  /* Temp variable to iterate over groups. */
  gchar **group;

  /* The link list for the structure above and it's tmp helper */
  GSList *log_domain_list = NULL;

  /* Create a new GKeyFile object and a bitwise list of flags. */
  key_file = g_key_file_new ();
  flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;

  /* Load the GKeyFile from conf or return. */
  if (!g_key_file_load_from_file (key_file, config_file, flags, &error))
    {
      g_error ("%s:  %s", config_file, error->message);
    }

  /* Get all the groups available. */
  groups = g_key_file_get_groups (key_file, NULL);

  /* Point to the group head. */
  group = groups;
  /* Iterate till we get to the end of the array. */
  while (*group != NULL)
    {
      /* Structure to hold per group settings. */
      gvm_logging_domain_t *log_domain_entry =
        gvm_logging_domain_new (g_strdup (*group));

      /* Look for the prepend string. */
      if (g_key_file_has_key (key_file, *group, "prepend", &error))
        {
          gvm_logging_domain_set_prepend_string (
            log_domain_entry,
            g_key_file_get_value (key_file, *group, "prepend", &error));
        }

      /* Look for the log_separator string. */
      if (g_key_file_has_key (key_file, *group, "separator", &error))
        {
          gvm_logging_domain_set_prepend_separator (
            log_domain_entry,
            g_key_file_get_value (key_file, *group, "separator", &error));
        }

      /* Look for the prepend time format string. */
      if (g_key_file_has_key (key_file, *group, "prepend_time_format", &error))
        {
          gvm_logging_domain_set_prepend_time_format (
            log_domain_entry,
            g_key_file_get_value (key_file, *group, "prepend_time_format",
                                  &error));
        }

      /* Look for the log file string. */
      if (g_key_file_has_key (key_file, *group, "file", &error))
        {
          gvm_logging_domain_set_log_file (
            log_domain_entry,
            g_key_file_get_value (key_file, *group, "file", &error));
        }

      /* Look for the prepend log level string. */
      if (g_key_file_has_key (key_file, *group, "level", &error))
        {
          gchar *level;

          level = g_key_file_get_value (key_file, *group, "level", &error);
          level = g_strchug (level);
          gvm_logging_domain_set_default_level (log_domain_entry,
                                                level_int_from_string (level));
          g_free (level);
        }

      /* Look for the syslog_facility string. */
      if (g_key_file_has_key (key_file, *group, "syslog_facility", &error))
        {
          gvm_logging_domain_set_syslog_facility (
            log_domain_entry,
            g_key_file_get_value (key_file, *group, "syslog_facility", &error));
        }
      else
        gvm_logging_domain_set_syslog_facility (log_domain_entry,
                                                g_strdup ("local0"));

      /* Look for the syslog_ident string. */
      if (g_key_file_has_key (key_file, *group, "syslog_ident", &error))
        {
          gvm_logging_domain_set_syslog_ident (
            log_domain_entry,
            g_key_file_get_value (key_file, *group, "syslog_ident", &error));
        }
      else
        gvm_logging_domain_set_syslog_ident (log_domain_entry,
                                             g_strdup (*group));

      /* Attach the struct to the list. */
      log_domain_list = g_slist_prepend (log_domain_list, log_domain_entry);
      group++;
    }
  /* Free the groups array. */
  g_strfreev (groups);

  /* Free the key file. */
  g_key_file_free (key_file);

  return log_domain_list;
}

/**
 * @brief Frees all resources loaded by the config loader.
 *
 * @param log_domain_list Head of the link list.
 */
void
free_log_configuration (GSList *log_domain_list)
{
  GSList *log_domain_list_tmp;

  /* Free the struct fields then the struct and then go the next
   * item in the link list.
   */

  /* Go to the head of the list. */
  log_domain_list_tmp = log_domain_list;
  while (log_domain_list_tmp != NULL)
    {
      gvm_logging_domain_t *log_domain_entry;

      /* Get the list data which is an gvm_logging_t struct. */
      log_domain_entry = log_domain_list_tmp->data;

      /* Free the struct contents. */
      gvm_logging_domain_free (log_domain_entry);

      /* Go to the next item. */
      log_domain_list_tmp = g_slist_next (log_domain_list_tmp);
    }
  /* Free the link list. */
  g_slist_free (log_domain_list);
}

/**
 * @brief Returns immediately.
 *
 * @param log_domain A string containing the message's log domain.
 * @param log_level  Flags defining the message's log level.
 * @param message    A string containing the log message.
 * @param gvm_log_config_list A pointer to the configuration linked list.
 */
void
gvm_log_silent (const char *log_domain, GLogLevelFlags log_level,
                const char *message, gpointer gvm_log_config_list)
{
  (void) log_domain;
  (void) log_level;
  (void) message;
  (void) gvm_log_config_list;
  return;
}

static GMutex *logger_mutex = NULL;

/**
 * @brief Initialize logger_mutex mutex if it was not done before.
 */
static void
gvm_log_lock_init (void)
{
  if (logger_mutex == NULL)
    {
      logger_mutex = g_malloc (sizeof (*logger_mutex));
      g_mutex_init (logger_mutex);
    }
}

/**
 * @brief Try to lock logger_mutex.
 */
void
gvm_log_lock (void)
{
  /* Initialize logger lock if not done already. */
  gvm_log_lock_init ();

  g_mutex_lock (logger_mutex);
}

/**
 * @brief Unlock logger_mutex.
 */
void
gvm_log_unlock (void)
{
  g_mutex_unlock (logger_mutex);
}

static char *reference = NULL;

/**
 * @brief Set the log reference object.
 *
 * In order to be able to see which logs are related to each other, we define a
 * common reference for them. E.g. when multiple scans in OpenVAS are running
 * simultaniousely it is possible to detect all log corresponding to the same
 * scan. The log reference is optional and must be set before calling
 * setup_log_handlers. The data given must be freed by calling
 * free_log_reference(). If called multiple times the old reference gets freed
 * and the new one is set instead.
 *
 * @param ref
 */
void
set_log_reference (char *ref)
{
  if (reference)
    g_free ((char *) reference);
  reference = ref;
}

/**
 * @brief Get the log reference object
 *
 * This function returns the current log reference. This enables the possibility
 * to save or modify the current reference value.
 *
 * @return char*
 */
char *
get_log_reference (void)
{
  return (char *) reference;
}

/**
 * @brief Free the log reference object
 *
 * The reference object is used to detect corresponding logs.
 *
 */
void
free_log_reference (void)
{
  if (reference)
    g_free ((char *) reference);
  reference = NULL;
}

/**
 * @brief Creates the formatted string and outputs it to the log destination.
 *
 * @param log_domain A string containing the message's log domain.
 * @param log_level  Flags defining the message's log level.
 * @param message    A string containing the log message.
 * @param gvm_log_config_list A pointer to the configuration linked list.
 */
void
gvm_log_func (const char *log_domain, GLogLevelFlags log_level,
              const char *message, gpointer gvm_log_config_list)
{
  gchar *prepend;
  gchar *prepend_buf;
  gchar *prepend_tmp;
  gchar *prepend_tmp1;
  gchar *tmp;
  gchar *tmpstr;
  int messagelen;

  /* For link list operations. */
  GSList *log_domain_list_tmp;
  gvm_logging_domain_t *log_domain_entry = NULL;

  /* Channel to log through. */
  GIOChannel *channel = NULL;
  GError *error = NULL;

  /* The default parameters to be used. The group '*' will override
   * these defaults if it's found.
   */
  gchar *prepend_format = "%t %s %p - ";
  gchar *time_format = "%Y-%m-%d %Hh%M.%S %Z";
  gchar *log_separator = ":";
  gchar *log_file = "-";
  GLogLevelFlags default_level = G_LOG_LEVEL_DEBUG;
  gchar *syslog_facility = "local0";
  gchar *syslog_ident = NULL;

  /* Let's load the default configuration file directives from the
   * linked list. Scanning the link list twice is inefficient but
   * leaves the source cleaner.
   */
  if (gvm_log_config_list != NULL && log_domain != NULL)
    {
      /* Go to the head of the list. */
      log_domain_list_tmp = (GSList *) gvm_log_config_list;

      while (log_domain_list_tmp != NULL)
        {
          gvm_logging_domain_t *entry;

          entry = log_domain_list_tmp->data;

          /* Override defaults if the current linklist group name is '*'. */
          if (g_ascii_strcasecmp (gvm_logging_domain_get_log_domain (entry),
                                  "*")
              == 0)
            {
              /* Get the list data for later use. */
              log_domain_entry = entry;

              /* Override defaults if the group items are not null. */
              if (gvm_logging_domain_get_prepend_string (log_domain_entry))
                prepend_format =
                  gvm_logging_domain_get_prepend_string (log_domain_entry);
              if (gvm_logging_domain_get_prepend_time_format (log_domain_entry))
                time_format =
                  gvm_logging_domain_get_prepend_time_format (log_domain_entry);
              if (gvm_logging_domain_get_log_file (log_domain_entry))
                log_file = gvm_logging_domain_get_log_file (log_domain_entry);
              if (gvm_logging_domain_get_default_level (log_domain_entry))
                default_level =
                  *gvm_logging_domain_get_default_level (log_domain_entry);
              if (gvm_logging_domain_get_log_channel (log_domain_entry))
                channel = gvm_logging_domain_get_log_channel (log_domain_entry);
              if (gvm_logging_domain_get_syslog_facility (log_domain_entry))
                syslog_facility =
                  gvm_logging_domain_get_syslog_facility (log_domain_entry);
              if (gvm_logging_domain_get_prepend_separator (log_domain_entry))
                log_separator =
                  gvm_logging_domain_get_prepend_separator (log_domain_entry);
              break;
            }

          /* Go to the next item. */
          log_domain_list_tmp = g_slist_next (log_domain_list_tmp);
        }
    }

  /* Let's load the configuration file directives if a linked list item for
   * the log domain group exists.
   */
  if (gvm_log_config_list != NULL && log_domain != NULL)
    {
      /* Go to the head of the list. */
      log_domain_list_tmp = (GSList *) gvm_log_config_list;

      while (log_domain_list_tmp != NULL)
        {
          gvm_logging_domain_t *entry;

          entry = log_domain_list_tmp->data;

          /* Search for the log domain in the link list. */
          if (g_ascii_strcasecmp (gvm_logging_domain_get_log_domain (entry),
                                  log_domain)
              == 0)
            {
              /* Get the list data which is an gvm_logging_t struct. */
              log_domain_entry = entry;

              /* Get the struct contents. */
              if (gvm_logging_domain_get_prepend_string (log_domain_entry))
                prepend_format =
                  gvm_logging_domain_get_prepend_string (log_domain_entry);
              if (gvm_logging_domain_get_prepend_time_format (log_domain_entry))
                time_format =
                  gvm_logging_domain_get_prepend_time_format (log_domain_entry);
              if (gvm_logging_domain_get_log_file (log_domain_entry))
                log_file = gvm_logging_domain_get_log_file (log_domain_entry);
              if (gvm_logging_domain_get_default_level (log_domain_entry))
                default_level =
                  *gvm_logging_domain_get_default_level (log_domain_entry);
              if (gvm_logging_domain_get_log_channel (log_domain_entry))
                channel = gvm_logging_domain_get_log_channel (log_domain_entry);
              if (gvm_logging_domain_get_syslog_facility (log_domain_entry))
                syslog_facility =
                  gvm_logging_domain_get_syslog_facility (log_domain_entry);
              if (gvm_logging_domain_get_syslog_ident (log_domain_entry))
                syslog_ident =
                  gvm_logging_domain_get_syslog_ident (log_domain_entry);
              if (gvm_logging_domain_get_prepend_separator (log_domain_entry))
                log_separator =
                  gvm_logging_domain_get_prepend_separator (log_domain_entry);
              break;
            }

          /* Go to the next item. */
          log_domain_list_tmp = g_slist_next (log_domain_list_tmp);
        }
    }

  /* If the current log entry is less severe than the specified log level,
   * let's exit.
   */
  if (default_level < log_level)
    return;

  /* Prepend buf is a newly allocated empty string. Makes life easier. */
  prepend_buf = g_strdup ("");

  /* Make the tmp pointer (for iteration) point to the format string. */
  tmp = prepend_format;

  while (*tmp != '\0')
    {
      /* If the current char is a % and the next one is a p, get the pid. */
      if ((*tmp == '%') && (*(tmp + 1) == 'p'))
        {
          if (reference)
            {
              prepend_tmp =
                g_strdup_printf ("%s%d%s%s", prepend_buf, (int) getpid (),
                                 log_separator, reference);
            }
          else
            {
              /* Use g_strdup, a new string returned. Store it in a tmp var
               * until we free the old one. */
              prepend_tmp =
                g_strdup_printf ("%s%d", prepend_buf, (int) getpid ());
            }
          /* Free the old string. */
          g_free (prepend_buf);
          /* Point the buf ptr to the new string. */
          prepend_buf = prepend_tmp;
          /* Skip over the two chars we've processed '%p'. */
          tmp += 2;
        }
      else if ((*tmp == '%') && (*(tmp + 1) == 't'))
        {
          /* Get time returns a newly allocated string.
           * Store it in a tmp var.
           */
          prepend_tmp1 = get_time (time_format);
          if (!prepend_tmp1)
            {
              prepend_tmp1 = g_strdup ("");
            }
          /* Use g_strdup. New string returned. Store it in a tmp var until
           * we free the old one.
           */
          prepend_tmp = g_strdup_printf ("%s%s", prepend_buf, prepend_tmp1);
          /* Free the time tmp var. */
          g_free (prepend_tmp1);
          /* Free the old string. */
          g_free (prepend_buf);
          /* Point the buf ptr to the new string. */
          prepend_buf = prepend_tmp;
          /* Skip over the two chars we've processed '%t.' */
          tmp += 2;
        }
      else if ((*tmp == '%') && (*(tmp + 1) == 's'))
        {
          /* Use g_strdup. New string returned. Store it in a tmp var until
           * we free the old one.
           */
          prepend_tmp = g_strdup_printf ("%s%s", prepend_buf, log_separator);
          /* Free the old string. */
          g_free (prepend_buf);
          /* Point the buf ptr to the new string. */
          prepend_buf = prepend_tmp;
          /* Skip over the two chars we've processed '%s.' */
          tmp += 2;
        }
      else
        {
          /* Jump to the next character. */
          tmp++;
        }
    }

  /* Step through all possible messages prefixing them with an appropriate
   * tag.
   */
  switch (log_level)
    {
    case G_LOG_FLAG_RECURSION:
      prepend = g_strdup_printf ("RECURSION%s%s", log_separator, prepend_buf);
      break;

    case G_LOG_FLAG_FATAL:
      prepend = g_strdup_printf ("FATAL%s%s", log_separator, prepend_buf);
      break;

    case G_LOG_LEVEL_ERROR:
      prepend = g_strdup_printf ("ERROR%s%s", log_separator, prepend_buf);
      break;

    case G_LOG_LEVEL_CRITICAL:
      prepend = g_strdup_printf ("CRITICAL%s%s", log_separator, prepend_buf);
      break;

    case G_LOG_LEVEL_WARNING:
      prepend = g_strdup_printf ("WARNING%s%s", log_separator, prepend_buf);
      break;

    case G_LOG_LEVEL_MESSAGE:
      prepend = g_strdup_printf ("MESSAGE%s%s", log_separator, prepend_buf);
      break;

    case G_LOG_LEVEL_INFO:
      prepend = g_strdup_printf ("   INFO%s%s", log_separator, prepend_buf);
      break;

    case G_LOG_LEVEL_DEBUG:
      prepend = g_strdup_printf ("  DEBUG%s%s", log_separator, prepend_buf);
      break;

    default:
      prepend = g_strdup_printf ("UNKNOWN%s%s", log_separator, prepend_buf);
      break;
    }

  /* If the current log entry is more severe than the specified log
   * level, print out the message.  In case MESSAGE already ends in a
   * LF and there is not only the LF, remove the LF to avoid empty
   * lines in the log.
   */
  messagelen = message ? strlen (message) : 0;
  if (messagelen > 1 && message[messagelen - 1] == '\n')
    messagelen--;
  tmpstr = g_strdup_printf ("%s%s%s%s %.*s\n", log_domain ? log_domain : "",
                            log_separator, prepend, log_separator, messagelen,
                            message);
  g_free (prepend);

  if (log_level <= G_LOG_LEVEL_WARNING)
    gvm_sentry_log (message);

  gvm_log_lock ();
  /* Output everything to stderr if logfile is NULL, an empty string or "-". */
  if (!log_file || g_ascii_strcasecmp (log_file, "-") == 0
      || !g_strcmp0 (log_file, ""))
    {
      fprintf (stderr, "%s", tmpstr);
      fflush (stderr);
    }
  /* Output everything to syslog if logfile is "syslog" */
  else if (g_ascii_strcasecmp (log_file, "syslog") == 0)
    {
      int facility = facility_int_from_string (syslog_facility);
      int syslog_level = LOG_INFO;

      openlog (syslog_ident, LOG_CONS | LOG_PID | LOG_NDELAY, facility);

      switch (log_level)
        {
        case G_LOG_FLAG_FATAL:
          syslog_level = LOG_ALERT;
          break;
        case G_LOG_LEVEL_ERROR:
          syslog_level = LOG_ERR;
          break;
        case G_LOG_LEVEL_CRITICAL:
          syslog_level = LOG_CRIT;
          break;
        case G_LOG_LEVEL_WARNING:
          syslog_level = LOG_WARNING;
          break;
        case G_LOG_LEVEL_MESSAGE:
          syslog_level = LOG_NOTICE;
          break;
        case G_LOG_LEVEL_INFO:
          syslog_level = LOG_INFO;
          break;
        case G_LOG_LEVEL_DEBUG:
          syslog_level = LOG_DEBUG;
          break;
        default:
          syslog_level = LOG_INFO;
          break;
        }

      /* Syslog doesn't support messages longer than 1kb. The overflow data
         will not be logged or will be shown in the hypervisor console
         if it runs on a virtual machine. */
      if (messagelen > 1000)
        {
          int pos;
          char *message_aux, *message_aux2;
          char buffer[1000];

          message_aux2 = g_strdup (message);
          message_aux = message_aux2;
          for (pos = 0; pos <= messagelen; pos = pos + sizeof (buffer) - 1)
            {
              memcpy (buffer, message_aux, sizeof (buffer) - 1);
              buffer[sizeof (buffer) - 1] = '\0';
              message_aux = &(message_aux[sizeof (buffer) - 1]);
              syslog (syslog_level, "%s", buffer);
            }
          g_free (message_aux2);
        }
      else
        syslog (syslog_level, "%s", message);

      closelog ();
    }
  else
    {
      /* Open a channel and store it in the struct or
       * retrieve and use an already existing channel.
       */
      if (channel == NULL)
        {
          channel = g_io_channel_new_file (log_file, "a", &error);
          if (!channel)
            {
              gchar *log = g_strdup (log_file);
              gchar *dir = dirname (log);

              /* Check error. In case of the directory does not exist, it will
               * be handle below. In other case a message is printed to the
               * stderr since the channel is still not created/accessible.
               */
              if (error->code != G_FILE_ERROR_NOENT)
                fprintf (stderr, "Can not open '%s' logfile: %s\n", log_file,
                         error->message);
              g_error_free (error);

              /* Ensure directory exists. */
              if (g_mkdir_with_parents (dir, 0755)) /* "rwxr-xr-x" */
                {
                  g_warning ("Failed to create log file directory %s: %s", dir,
                             strerror (errno));
                  g_free (log);
                  g_free (tmpstr);
                  g_free (prepend_buf);
                  return;
                }
              g_free (log);

              /* Try again. */
              error = NULL;
              channel = g_io_channel_new_file (log_file, "a", &error);
              if (!channel)
                {
                  g_error ("Can not open '%s' logfile: %s", log_file,
                           error->message);
                }
            }

          /* Store it in the struct for later use. */
          if (log_domain_entry != NULL)
            gvm_logging_domain_set_log_channel (log_domain_entry, channel);
        }
      g_io_channel_write_chars (channel, (const gchar *) tmpstr, -1, NULL,
                                &error);
      g_io_channel_flush (channel, NULL);
    }
  gvm_log_unlock ();
  g_free (tmpstr);
  g_free (prepend_buf);
}

/**
 * @brief This function logs debug messages from gnutls.
 *
 * @param level GnuTLS log level (integer from 0 to 99 according to GnuTLS
 * documentation.
 * @param message GnuTLS log message.
 *
 * To enable GNUTLS debug messages, the environment variable @c
 * OPENVAS_GNUTLS_DEBUG is to be set to the desired log level as
 * described in the GNUTLS manual.
 */
void
log_func_for_gnutls (int level, const char *message)
{
  g_log ("x  gnutls", G_LOG_LEVEL_INFO, "tls(%d): %s", level, message);
}

/**
 * @brief Check permissions of log file and log file directory.
 *
 * Do not check permissions if log file is syslog or empty string.
 *
 * @param log_domain_entry  Log domain entry.
 *
 * @return 0 on success, -1 on error.
 */
static int
check_log_file (gvm_logging_domain_t *log_domain_entry)
{
  GIOChannel *channel = NULL;
  GError *error = NULL;
  const gchar *log_file;

  log_file = gvm_logging_domain_get_log_file (log_domain_entry);

  // No log file was specified, log file is empty or set to "-" then
  // stderr will be used as default later on. See gvm_log_func.
  if (!log_file || g_ascii_strcasecmp (log_file, "-") == 0
      || !g_strcmp0 (log_file, ""))
    return 0;

  // If syslog is used we do not need to check the log file permissions.
  if (g_ascii_strcasecmp (log_file, "syslog") == 0)
    return 0;

  channel = g_io_channel_new_file (log_file, "a", &error);
  if (!channel)
    {
      gchar *log = g_strdup (log_file);
      gchar *dir = dirname (log);

      /* Ensure directory exists. */
      if (g_mkdir_with_parents (dir, 0755)) /* "rwxr-xr-x" */
        {
          g_free (log);
          return -1;
        }
      g_free (log);

      /* Try again. */
      error = NULL;
      channel = g_io_channel_new_file (log_file, "a", &error);
      if (!channel)
        return -1;
    }
  return 0;
}

/**
 * @brief Set the log timezone.
 *
 * This is the timezone used for dates in log messages. If NULL then
 * the current timezone is used.
 *
 * @param tz Timezone.
 */
void
set_log_tz (const gchar *tz)
{
  g_free (log_tz);
  log_tz = tz ? g_strdup (tz) : NULL;
}

static int
setup_log_handlers_internal (GSList *gvm_log_config_list, GLogFunc log_func,
                             GLogFunc default_log_func,
                             GLogFunc default_domain_log_func)
{
  GSList *log_domain_list_tmp;
  int err;
  int ret = 0;

  if (gvm_log_config_list != NULL)
    {
      /* Go to the head of the list. */
      log_domain_list_tmp = (GSList *) gvm_log_config_list;

      while (log_domain_list_tmp != NULL)
        {
          gvm_logging_domain_t *log_domain_entry;

          /* Get the list data which is an gvm_logging_t struct. */
          log_domain_entry = log_domain_list_tmp->data;

          err = check_log_file (log_domain_entry);
          if (err)
            {
              ret = -1;
              /* Go to the next item. */
              log_domain_list_tmp = g_slist_next (log_domain_list_tmp);
              continue;
            }

          if (g_ascii_strcasecmp (
                gvm_logging_domain_get_log_domain (log_domain_entry), "*"))
            {
              g_log_set_handler (
                gvm_logging_domain_get_log_domain (log_domain_entry),
                (GLogLevelFlags) (G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO
                                  | G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_WARNING
                                  | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR
                                  | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION),
                (GLogFunc) log_func, gvm_log_config_list);
            }
          else
            {
              g_log_set_default_handler (default_log_func, gvm_log_config_list);
            }

          /* Go to the next item. */
          log_domain_list_tmp = g_slist_next (log_domain_list_tmp);
        }
    }
  g_log_set_handler (
    "",
    (GLogLevelFlags) (G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE
                      | G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL
                      | G_LOG_LEVEL_ERROR | G_LOG_FLAG_FATAL
                      | G_LOG_FLAG_RECURSION),
    default_domain_log_func, gvm_log_config_list);

  return ret;
}

/**
 * @brief Sets up routing of logdomains to log handlers.
 *
 * Iterates over the link list and adds the groups to the handler.
 *
 * @param gvm_log_config_list A pointer to the configuration linked list.
 *
 * @return 0 on success, -1 if not able to create log file directory or open log
 * file for some domain.
 */
int
setup_log_handlers (GSList *gvm_log_config_list)
{
  return setup_log_handlers_internal (gvm_log_config_list, gvm_log_func,
                                      gvm_log_func, gvm_log_func);
}
