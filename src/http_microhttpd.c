#include <microhttpd.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "client_list.h"
#include "http_microhttpd.h"
#include "conf.h"
#include "debug.h"

static t_client *add_client(struct MHD_Connection *connection);

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

  /* only allow get */
  if (0 != strcmp (method, "GET"))
    return send_error(connection, 503);

  /* switch between preauth, authenticated */
  /* - always - set caching headers
   * a) possible implementation - redirect first and serve them using a tempo redirect
   * b) serve direct
   * should all requests redirected? even those to .css, .js, ... or respond with 404/503/...
   */

  config = config_get_config();

  client = add_client(connection);
}

/**
 *  Add client making a request to client list.
 *  Return pointer to the client list entry for this client.
 *
 *  N.B.: This does not authenticate the client; it only makes
 *  their information available on the client list.
 */
static t_client *
add_client(struct MHD_Connection *connection)
{
  t_client	*client;
  const union MHD_ConnectionInfo *connection_info;
  char *ip_addr;
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

  if (AF_INET == client_addr->sa_family) {
    ip_addr = malloc(INET_ADDRSTRLEN+1);
    if(!inet_ntop(addrin->sin_family, &(addrin->sin_addr), ip_addr , sizeof(struct sockaddr_in6))) {
      return NULL;
    }
  } else if (AF_INET6 == client_addr->sa_family) {
    ip_addr = malloc(INET6_ADDRSTRLEN+1);
    if(!inet_ntop(addrin6->sin6_family, &(addrin6->sin6_addr), ip_addr , sizeof(struct sockaddr_in6))){
      return NULL;
    }
  } else {
    return NULL;
  }


  LOCK_CLIENT_LIST();
  client = client_list_add_client(ip_addr);
  UNLOCK_CLIENT_LIST();
  return client;
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
