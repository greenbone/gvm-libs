#ifndef _GVM_CYBERARK_CYBERARK_H
#define _GVM_CYBERARK_CYBERARK_H


#include <glib.h>
#include <stdio.h>

/**
 * @brief CyberArk credential store options for the connector
 */
typedef enum
{
  CYBERARK_CA_CERT,   /**< Path to the CA certificate directory */
  CYBERARK_CERT,      /**< Client certificate file */
  CYBERARK_KEY,       /**< Client private key file */
  CYBERARK_API_KEY,   /**< API key for authentication  */
  CYBERARK_HOST,      /**< Hostname or IP address */
  CYBERARK_PATH,      /**< Base path of credential store API */
  CYBERARK_PORT,      /**< Port number */
  CYBERARK_PROTOCOL,  /**< "http" or "https" */
  CYBERARK_APP_ID,    /**< Application ID */
} cyberark_connector_opts_t;

/**
 * @brief Error codes for CyberArk credential store.
 */
typedef enum
{
  CYBERARK_OK = 0,            /**< No error */
  CYBERARK_INVALID_OPT = -1,  /**< Invalid option specified */
  CYBERARK_INVALID_VALUE = -2 /**< Invalid value specified */
} cyberark_error_t;

struct cyberark_object
{
  gchar *username;                   /**< Username field. */
  gchar *content;                    /**< Password field. */
  int password_change_in_process;    /**< Password change in process field. */
  gchar *object;                     /**< Object field. */
  gchar *safe;                       /**< Safe field. */
  gchar *folder;                     /**< Folder field. */
};

typedef struct cyberark_object *cyberark_object_t;
typedef struct cyberark_connector *cyberark_connector_t;

cyberark_object_t
cyberark_object_new (void);

void
cyberark_object_free (cyberark_object_t);

cyberark_connector_t
cyberark_connector_new (void);

cyberark_error_t
cyberark_connector_builder (cyberark_connector_t,
                            cyberark_connector_opts_t,
                            const void *);

void
cyberark_connector_free (cyberark_connector_t);

int
cyberark_verify_connection (cyberark_connector_t,
                            const gchar *, const gchar *, const gchar *);

cyberark_object_t
cyberark_get_object (cyberark_connector_t,
                     const gchar *, const gchar *, const gchar *);

#endif /* not _GVM_CYBERARK_CYBERARK_H */