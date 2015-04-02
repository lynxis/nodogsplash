#include <microhttpd.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "client_list.h"
#include "conf.h"
#include "debug.h"
#include "firewall.h"
#include "auth.h"
#include "http_microhttpd.h"
#include "safe.h"

static t_client *add_client(const char *ip_addr);
static int preauthenticated(struct MHD_Connection *connection, const char *ip_addr, const char *mac, const char *url, t_client *client);
static int authenticated(struct MHD_Connection *connection, const char *ip_addr, const char *mac, const char *url, t_client *client);
static int get_host_value_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value);
static int serve_file(struct MHD_Connection *connection, t_client *client);
static int show_splashpage(struct MHD_Connection *connection, t_client *client);
static int show_redirect(struct MHD_Connection *connection, t_client *client, const char *host, const char *url);
static int need_a_redirect(struct MHD_Connection *connection, const char *host);

static int need_a_redirect(struct MHD_Connection *connection, const char *host) {
  if (host)
    return 1;
}

/**
 * @brief get_ip
 * @param connection
 * @return ip address - must be freed by caller
 */
static char *
get_ip(struct MHD_Connection *connection) {
  const union MHD_ConnectionInfo *connection_info;
  char *ip_addr = NULL;
  int size;
  const struct sockaddr *client_addr;
  const struct sockaddr_in  *addrin;
  const struct sockaddr_in6 *addrin6;
  if (!(connection_info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS))) {
    return NULL;
  }

  /* cast required for legacy MHD API < 0.9.6*/
  client_addr = (const struct sockaddr *)connection_info->client_addr;
  addrin = (const struct sockaddr_in *) client_addr;
  addrin6 = (const struct sockaddr_in6 *) client_addr;

  switch(client_addr->sa_family) {
  case AF_INET:
    ip_addr = calloc(1, INET_ADDRSTRLEN+1);
    if(!inet_ntop(addrin->sin_family, &(addrin->sin_addr), ip_addr , sizeof(struct sockaddr_in))) {
      free(ip_addr);
      return NULL;
    }
    break;

  case AF_INET6:
    ip_addr = calloc(1, INET6_ADDRSTRLEN+1);
    if(!inet_ntop(addrin6->sin6_family, &(addrin6->sin6_addr), ip_addr , sizeof(struct sockaddr_in6))){
      free(ip_addr);
      return NULL;
    }
    break;
  }

  return ip_addr;
}

int
libmicrohttpd_cb(void *cls,
                  struct MHD_Connection *connection,
                  const char *url,
                  const char *method,
                  const char *version,
                  const char *upload_data, size_t *upload_data_size, void **ptr) {

  struct MHD_Response *response;
  s_config *config;
  t_client *client;
  char *ip_addr;
  char *mac;
  int ret;

  /* only allow get */
  if(0 != strcmp(method, "GET"))
    return send_error(connection, 503);

  /* switch between preauth, authenticated */
  /* - always - set caching headers
   * a) possible implementation - redirect first and serve them using a tempo redirect
   * b) serve direct
   * should all requests redirected? even those to .css, .js, ... or respond with 404/503/...
   */


  /* check if we need to redirect this client */
  config = config_get_config();
  ip_addr = get_ip(connection);
  mac = arp_get(ip_addr);

  client = client_list_find(ip_addr, mac);
  if(client) {
    if(client->fw_connection_state == FW_MARK_AUTHENTICATED ||
         client->fw_connection_state == FW_MARK_TRUSTED)
      {
      /* client already authed */
        ret = authenticated(connection, ip_addr, mac, url, client);
        free(mac);
        free(ip_addr);
        return ret;
      }
  }
  ret = preauthenticated(connection, ip_addr, mac, url, client);
  free(mac);
  free(ip_addr);
  return ret;
}

/**
 * @brief authenticated - client already authed
 * @param connection
 * @param ip_addr - needs to be freed
 * @param mac - needs to be freed
 * @return
 */
static int authenticated(struct MHD_Connection *connection,
                         const char *ip_addr,
                         const char *mac,
                         const char *url,
                         t_client *client) {
  auth_client_action(ip_addr, mac, AUTH_MAKE_AUTHENTICATED);
  return send_redirect_temp(connection, "http://www.google.com");
}

/**
 * @brief preauthenticated - called when a client is in this state.
 * @param connection
 * @param ip_addr - needs to be freed
 * @param mac - needs to be freed
 * @return
 */
static int preauthenticated(struct MHD_Connection *connection,
                            const char *ip_addr,
                            const char *mac,
                            const char *url,
                            t_client *client) {
  struct MHD_Response *response;
  s_config *config;
  char *host = NULL;
  char *query = "";

  if (!client) {
    client = add_client(ip_addr);
    if (!client)
      return send_error(connection, 503);
  }

  MHD_get_connection_values(connection, MHD_HEADER_KIND, get_host_value_callback, &host);

  if(!strncmp(url, "/accept", strlen("/accept"))) {
    return authenticated(connection, ip_addr, mac, url, client);
  }
  /* we check here if we have to serve this request or we redirect it. */
  if(host == NULL || need_a_redirect(connection, host))
    return show_splashpage(connection, client);
  else
    return show_redirect(connection, client, host, url);
}

static int show_redirect(struct MHD_Connection *connection, t_client *client, const char *host, const char *url) {
  char *redirecturl;
  char *query = "?";
  int ret;

  if (config_get_config()->redirectURL)
    redirecturl = safe_strdup(config_get_config()->redirectURL);
  else
    safe_asprintf(&redirecturl, "http://%s%s%s%s", host, url, query);

  ret = send_redirect_temp(connection, redirecturl);
  free(redirecturl);
  return ret;
}

/**
 *  Add client making a request to client list.
 *  Return pointer to the client list entry for this client.
 *
 *  N.B.: This does not authenticate the client; it only makes
 *  their information available on the client list.
 */
static t_client *
add_client(const char *ip_addr)
{
  t_client	*client;

  LOCK_CLIENT_LIST();
  client = client_list_add_client(ip_addr);
  UNLOCK_CLIENT_LIST();
  return client;
}

int send_redirect_temp(struct MHD_Connection *connection, const char *url) {
  struct MHD_Response *response;
  int ret;
  char *redirect;

  const char *redirect_body = "<html><head></head><body><a href='%s'>Click here to continue to<br>%s</a></body></html>";
  safe_asprintf(&redirect, redirect_body, url);

  response = MHD_create_response_from_data(strlen(redirect), redirect, MHD_YES, MHD_NO);
  MHD_add_response_header(response, "Location", url);
  ret = MHD_queue_response(connection, MHD_HTTP_TEMPORARY_REDIRECT, response);

  MHD_destroy_response(response);

  return ret;
}

int send_error(struct MHD_Connection *connection, int error)
{
  struct MHD_Response *response;
  // cannot automate since cannot translate automagically between error number and MHD's status codes -- and cannot rely on MHD_HTTP_ values to provide an upper bound for an array
  const char *page_400 = "<html><head><title>Error 400</title></head><body><h1>Error 400 - Bad Request</h1></body></html>";
  const char *page_403 = "<html><head><title>Error 403</title></head><body><h1>Error 403 - Forbidden</h1></body></html>";
  const char *page_404 = "<html><head><title>Error 404</title></head><body><h1>Error 404 - Not Found</h1></body></html>";
  const char *page_500 = "<html><head><title>Error 500</title></head><body><h1>Error 500 - Internal Server Error. Oh no!</body></html>";
  const char *page_501 = "<html><head><title>Error 501</title></head><body><h1>Error 501 - Not Implemented</h1></body></html>";

  int ret;

  switch (error)
  {
  case 400:
    response = MHD_create_response_from_data(strlen(page_400), (char *)page_400, MHD_NO, MHD_NO);
    ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
    break;

  case 403:
    response = MHD_create_response_from_data(strlen(page_403), (char *)page_403, MHD_NO, MHD_NO);
    ret = MHD_queue_response(connection, MHD_HTTP_FORBIDDEN, response);
    break;

  case 404:
    response = MHD_create_response_from_data(strlen(page_404), (char *)page_404, MHD_NO, MHD_NO);
    ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
    break;

  case 500:
    response = MHD_create_response_from_data(strlen(page_500), (char *)page_500, MHD_NO, MHD_NO);
    ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
    break;

  case 501:
    response = MHD_create_response_from_data(strlen(page_501), (char *)page_501, MHD_NO, MHD_NO);
    ret = MHD_queue_response(connection, MHD_HTTP_NOT_IMPLEMENTED, response);
    break;
  }

  MHD_destroy_response(response);
  return ret;
}

/**
 * @brief get_host_value_callback safe Host into cls which is a char**
 * @param cls - a char ** pointer to our target buffer. This buffer will be alloc in this function.
 * @param kind - see doc of  MHD_KeyValueIterator's
 * @param key
 * @param value
 * @return MHD_YES or MHD_NO. MHD_NO means we found our item and this callback will not called again.
 */
static int get_host_value_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value) {
  char **host = (char **)cls;
  if (MHD_HEADER_KIND != kind) {
    *host = NULL;
    return MHD_NO;
  }

  if (key == "Host") {
    *host = safe_strdup(value);
    return MHD_NO;
  }

  return MHD_YES;
}
/**
 * @brief show_splashpage will be called when the client clicked on Ok as well when the client haven't know us yet.
 * @param connection
 * @param client
 * @return
 */
static int show_splashpage(struct MHD_Connection *connection, t_client *client) {
  const char *testsplash = "<html><body><h1>juhuuuu</h1></body></html>";
  struct MHD_Response *response;
  int ret;

  response = MHD_create_response_from_buffer(strlen(testsplash), (void *)testsplash, MHD_RESPMEM_PERSISTENT);
  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
  return ret;

  /* generate splashpage from template */
  /* send it to client */
}

/**
 * @brief general_file_handler try to serve a request via filesystem
 * @param connection
 * @param client
 * @return
 */
static int serve_file(struct MHD_Connection *connection, t_client *client) {
  s_config *config = config_get_config();
  // config->pagesdir
  /* check if file exists */
  /* match file against mime type */
  /* serve the file */
}
