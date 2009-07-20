/* openvas-libraries/libopenvas
 * $Id$
 * Description: Implementation of logging methods for openvas
 *
 * Authors:
 * Laban Mwangi <lmwangi@penguinlabs.co.ke>
 *
 * Copyright:
 * Copyright (C) 2009 PenguinLabs Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
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

/**
 * @file openvas_logging.c
 * @brief Implementation of logging methods for OpenVAS.
 *
 * This file contains all methods needed for openvas logging. To enable logging,
 * methods in this file are called. Have a look at
 * openvas-server/openvasd/openvasd.c for an example.
 *
 * The module reuses glib datatypes and api for memory management and logging.
 */



#include "includes.h"

#include "openvas_logging.h"

/**
 * @brief Returns time as specified in time_fmt strftime format.
 *
 * @param time_fmt ptr to the string format to use. The strftime
 * 	  man page documents the conversion specification. An
 * 	  example time_fmt string is "%Y-%m-%d %H:%M:%S".
 *
 * @return NULL in case the format string is NULL. A ptr to a
 *  	   string that contains the formatted date time value.
 *  	   This value must be freed using glib's g_free.
 */
gchar *gettime(gchar *time_fmt)
{
  time_t     now;
  struct tm  *ts;
  gchar       buf[80];

  /* Get the current time */
  now = time(NULL);

  /* Format and print the time, "ddd yyyy-mm-dd hh:mm:ss zzz" */
  ts = localtime(&now);
  strftime(buf, sizeof(buf), time_fmt, ts);

  return  g_strdup_printf("%s", buf);
}


/**
 * @brief Loads parameters from a config file into a linked list.
 *
 * @param configfile A string containing the path to the configuration file
 * 	             to load.
 *
 * @return NULL in case the config file could not be loaded or an error
 * 	   occurred otherwise, a singly linked list of parameter groups
 * 	   is returned.
 */
GSList *load_log_configuration (gchar * configfile)
{

  GKeyFile *keyfile;
  GKeyFileFlags flags;
  GError *error = NULL;
  /* keyfile *_has_* functions requires this */

  /* Groups found in the conf file*/
  gchar **groups;
  /* Temp variable to iterate over groups */
  gchar **group;

  /* Structure to hold per group settings */
  openvasd_logging *logdomainentry;
  /* The link list for the structure above and it's tmp helper */
  GSList *logdomainlist = NULL;

  /* Create a new GKeyFile object and a bitwise list of flags. */
  keyfile = g_key_file_new ();
  flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;


  /* Load the GKeyFile from conf or return. */
  if (!g_key_file_load_from_file (keyfile, configfile, flags, &error))
  {
    g_error ("%s:  %s",configfile,error->message);
  }

  /* Get all the groups available */
  groups = g_key_file_get_groups (keyfile,NULL);

  /* Point to the group head */
  group = groups;
  /* Iterate till we get to the end of the array. == NULL */
  while (*group != NULL)
  {
    /* Create the struct */
    logdomainentry = g_malloc(sizeof(openvasd_logging));
    /* Set the logdomain */
    logdomainentry->logdomain = g_strdup(*group);
    /* Initialize everything else to NULL */
    logdomainentry->prependstring = NULL;
    logdomainentry->prependtimeformat = NULL;
    logdomainentry->logfile = NULL;
    logdomainentry->defaultlevel = 0;
    logdomainentry->logchannel = NULL;


    /* Look for the prepend string */
    if (g_key_file_has_key (keyfile, *group,"prepend",&error)){
      logdomainentry->prependstring = g_key_file_get_value (keyfile, *group,"prepend",&error);
    }

    /* Look for the prepend time format string */
    if (g_key_file_has_key (keyfile, *group,"prepend_time_format",&error)){
      logdomainentry->prependtimeformat = g_key_file_get_value (keyfile, *group,"prepend_time_format",&error);
    }

    /* Look for the log file string */
    if (g_key_file_has_key (keyfile, *group,"file",&error)){
      logdomainentry->logfile = g_key_file_get_value (keyfile, *group,"file",&error);
    }


    /* Look for the prepend log level string */
    if (g_key_file_has_key (keyfile, *group,"level",&error)){
      logdomainentry->defaultlevel = g_key_file_get_integer (keyfile, *group,"level",&error);
    }

    /* Attach the struct to the list */
    logdomainlist =  g_slist_prepend(logdomainlist, logdomainentry);
    group++;
  }
  /* Free the groups array */
  g_strfreev(groups);

  /* Free the keyfile */
  g_key_file_free (keyfile);

  return logdomainlist;
}

/**
 * @brief Frees all resources loaded by the config loader.
 *
 * @param logdomainlist Head of the link list.
 *
 * @return Nothing - void function.
 */
void free_log_configuration(GSList *logdomainlist)
{
  GSList *logdomainlisttmp;
  openvasd_logging *logdomainentry;

  /*
   *  Free the struct fields then the struct and then go the next
   *  item in the LL
   */

  /* Go the the head of the list */
  logdomainlisttmp = logdomainlist;
        while (logdomainlisttmp != NULL)
  {
    /* Get the list data = Struct */
    logdomainentry = logdomainlisttmp->data;

    /* Free the struct contents */
    g_free(logdomainentry->logdomain);
    g_free(logdomainentry->prependstring);
    g_free(logdomainentry->prependtimeformat);
    g_free(logdomainentry->logfile);
    //g_free(logdomainentry->defaultlevel);

    /* Free the struct */
    g_free(logdomainentry);

    /* Go to the next item */
    logdomainlisttmp = g_slist_next(logdomainlisttmp);

  }
  /* Free the link list */
  g_slist_free(logdomainlist);

}


/**
 * @brief Creates the formatted string and outputs it to the log destination.
 *
 * @param log_domain A string containing the message's log domain.
 *
 * @param log_level A string containing the message's log level.
 *
 * @param message A string containing the log message.
 *
 * @param openvaslogconfiglist A pointer to the configuration linked list.
 *
 *
 * @return Nothing - void function.
 */
void openvas_log_func(const char *log_domain, GLogLevelFlags log_level, const char *message, gpointer openvaslogconfiglist)
{
  gchar *prepend;
  gchar *prepend_buf;
  gchar *prepend_tmp;
  gchar *prepend_tmp1;
  gchar *tmp;

  /* For link list operations */
  GSList  *logdomainlisttmp;
  openvasd_logging *logdomainentry;

  /* For logging to a file */
  GError *error=NULL;
  GIOChannel *channel;

  /*
   * The default parameters if this logdomain is not defined
   * A pid then a strftime timestamp.
   * TODO: These should be overriden by the group [*]
   */
  gchar *prependformat = "%p %t - ";
  gchar *timeformat = "%a %Y-%m-%d %Hh%M.%S %Z";

  /* TODO Move log_separator to the conf file too */
  gchar *log_separator = ":";
  gchar *logfile = "-";
  guint default_level = G_LOG_LEVEL_INFO;
  channel = NULL;
  gboolean foundlogdomainentry = FALSE;

  /*
   * Let's load the configuration file directives if a linked list to it
   * exists... Otherwise the defaults above will be left untouched
   */
  if(openvaslogconfiglist != NULL && log_domain != NULL)
  {

    /* Go the the head of the list*/
    logdomainlisttmp = ( GSList  *) openvaslogconfiglist;

    while ( logdomainlisttmp != NULL && foundlogdomainentry == FALSE )
    {
      /* Get the list data = Struct */
      logdomainentry = logdomainlisttmp->data;

      /* search for the log domain in the link list */
      if (g_ascii_strcasecmp (logdomainentry->logdomain, log_domain ) == 0)
      {
        /* print the struct contents */
        prependformat = logdomainentry->prependstring;
        timeformat = logdomainentry->prependtimeformat;
        logfile = logdomainentry->logfile;
        default_level = logdomainentry->defaultlevel;
        channel = logdomainentry->logchannel;
        foundlogdomainentry  = TRUE ;
      }

      /* Go to the next item */
      logdomainlisttmp = g_slist_next(logdomainlisttmp);
    }
  }

  /* If the current log entry is less severe than the specified log level,
   * let's exit
   */
  if (default_level < log_level)
    return;


 /* Prepend buf is  a newly allocated empty string. Makes life easier. */
 prepend_buf = g_strdup ("");


 /*Make the tmp pointer (for iteration) point to the format string*/
 tmp = prependformat;

 while( *tmp != '\0' )
 {
    /* If the current char is a % and the next one is a p, get the pid */
    if ((*tmp=='%') && (*(tmp+1) == 'p'))
    {
      /* Use g_strdup. New string returned. Store it in a tmp var until we free the old one */
      prepend_tmp = g_strdup_printf ("%s%s%d",prepend_buf, log_separator, (int)getpid());
      /* Free the old string */
      g_free(prepend_buf);
      /* Point the buf ptr to the new string */
      prepend_buf = prepend_tmp;
      /* Skip over the two chars we've processed '%p' */
      tmp+=2;
    }
    else if ((*tmp=='%') && (*(tmp+1) == 't'))
    {
      /* Get time returns a newly allocated string. Store it in a tmp var */
      prepend_tmp1 =  gettime(timeformat);
      /* Use g_strdup. New string returned. Store it in a tmp var until we free the old one */
      prepend_tmp = g_strdup_printf ("%s%s%s",prepend_buf, log_separator, prepend_tmp1);
      /* Free the time tmp var */
      g_free(prepend_tmp1);
      /* Free the old string */
      g_free(prepend_buf);
      /* Point the buf ptr to the new string */
      prepend_buf = prepend_tmp;
      /* Skip over the two chars we've processed '%t' */
      tmp+=2;
    }
    else
    {
      /* Jump to the next character */
      tmp++;
    }
  }

  /* Step through all possible messages prefixing them with an appropriate tag. */
  switch (log_level) {
    case G_LOG_FLAG_RECURSION:
      prepend = g_strdup_printf("RECURSION%s", prepend_buf);
      break;

    case G_LOG_FLAG_FATAL:
      prepend = g_strdup_printf("FATAL%s", prepend_buf);
      break;

    case G_LOG_LEVEL_ERROR:
      prepend = g_strdup_printf("ERROR%s", prepend_buf);
      break;

    case G_LOG_LEVEL_CRITICAL:
      prepend = g_strdup_printf("CRITICAL%s", prepend_buf);
        break;
    case G_LOG_LEVEL_WARNING:
      prepend = g_strdup_printf("WARNING%s", prepend_buf);
      break;

    case G_LOG_LEVEL_MESSAGE:
      prepend = g_strdup_printf("MSG%s", prepend_buf);
      break;

    case G_LOG_LEVEL_INFO:
      prepend = g_strdup_printf("INFO%s", prepend_buf);
      break;

    case G_LOG_LEVEL_DEBUG:
      prepend = g_strdup_printf("DEBUG%s", prepend_buf);
      break;

    default:
      prepend = g_strdup_printf("UNKWOWN%s", prepend_buf);
      break;
  }

  /* If the current log entry is more severe than the specified log level,
   * print out the message.
   */
  GString *logstr = g_string_new("");
  g_string_append_printf(logstr,
  "%s%s%s%s %s",
  log_domain ? log_domain : "", log_separator,
  prepend,log_separator,
  message);

  gchar *tmpstr = g_string_free(logstr, FALSE);
  /* Output everything to stderr if logfile = "-" */
  if (g_ascii_strcasecmp(logfile,"-") == 0)
  {
    fprintf(stderr, "%s", tmpstr);
    fflush(stderr);
  }else{
    /*
     * Open a channel and store it in the struct or
     * retrieve and use an already existing channel.
     */
    if (channel == NULL){
      channel = g_io_channel_new_file( logfile, "a", &error);
      if(!channel){
        g_error("Can not open '%s' logfile. %s", logfile, error->message);
      }

      /* Store it in the struct for later use. */
      if (logdomainentry != NULL)
        logdomainentry->logchannel = channel;
    }
    g_io_channel_write_chars(channel,(const gchar *)tmpstr,-1, NULL, &error);
    g_io_channel_flush(channel, NULL);

  }
  g_free(tmpstr);
  g_free(prepend_buf);

}

/**
 * @brief Sets up routing of logdomains to log handlers.
 *
 * @param openvaslogconfiglist A pointer to the log configuration linked list.
 *
 * @return Nothing - void function.
 *
 * TODO: Iterate over the link list and add the domains here.
 *
 */
void setup_log_handlers(  GSList *openvaslogconfiglist )
{
  g_log_set_handler("libnasl",(GLogLevelFlags) (G_LOG_LEVEL_DEBUG|G_LOG_LEVEL_INFO|G_LOG_LEVEL_MESSAGE |G_LOG_LEVEL_WARNING|G_LOG_LEVEL_CRITICAL|G_LOG_LEVEL_ERROR|G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION ), (GLogFunc) openvas_log_func, openvaslogconfiglist);
  g_log_set_handler("openvasd",(GLogLevelFlags) (G_LOG_LEVEL_DEBUG|G_LOG_LEVEL_INFO|G_LOG_LEVEL_MESSAGE |G_LOG_LEVEL_WARNING|G_LOG_LEVEL_CRITICAL|G_LOG_LEVEL_ERROR|G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION ), (GLogFunc) openvas_log_func, openvaslogconfiglist);
  g_log_set_handler("",(GLogLevelFlags) (G_LOG_LEVEL_DEBUG|G_LOG_LEVEL_INFO|G_LOG_LEVEL_MESSAGE |G_LOG_LEVEL_WARNING|G_LOG_LEVEL_CRITICAL|G_LOG_LEVEL_ERROR|G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION ), (GLogFunc) openvas_log_func, openvaslogconfiglist);
}
