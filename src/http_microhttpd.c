/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free:Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
\********************************************************************/

/** @internal
 * @file http_microhttpd.c
 * @brief a httpd implementation using libmicrohttpd
 * @author Copyright (C) 2015 Alexander Couzens <lynxis@fe80.eu>
 */


#include <microhttpd.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <unistd.h>

#include "client_list.h"
#include "conf.h"
#include "debug.h"
#include "firewall.h"
#include "auth.h"
#include "http_microhttpd.h"
#include "http_microhttpd_utils.h"
#include "mimetypes.h"
#include "safe.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static t_client *add_client(const char *ip_addr);
static int preauthenticated(struct MHD_Connection *connection, const char *ip_addr, const char *mac, const char *url, t_client *client);
static int authenticated(struct MHD_Connection *connection, const char *ip_addr, const char *mac, const char *url, t_client *client);
static int get_host_value_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value);
static int serve_file(struct MHD_Connection *connection, t_client *client, const char *url);
static int show_splashpage(struct MHD_Connection *connection, t_client *client);
static int redirect_to_splashpage(struct MHD_Connection *connection, t_client *client, const char *host, const char *url);
static int send_error(struct MHD_Connection *connection, int error);
static int send_redirect_temp(struct MHD_Connection *connection, const char *url);
static int need_a_redirect(struct MHD_Connection *connection, const char *host);
static int is_splashpage(const char *host, const char *url);
static int get_query(struct MHD_Connection *connection, char **collect_query);


static int need_a_redirect(struct MHD_Connection *connection, const char *host) {
  char our_host[24];
  s_config *config = config_get_config();
  snprintf(our_host, 24, "%s:%u", config->gw_address, config->gw_port);

  /* we serve all request without a host entry as well we serve all request going to our gw_address */
  if (host == NULL || !strcmp(host, our_host))
    return 0;

  return 1;
}

static int is_splashpage(const char *host, const char *url) {
  char our_host[24];
  s_config *config = config_get_config();
  snprintf(our_host, 24, "%s:%u", config->gw_address, config->gw_port);

  if (host == NULL) {
    /* no hostname given
     * '/' -> splash
     * ''  -> splash [is this even possible with MHD?
     */
    if (strlen(url) == 0 ||
        !strcmp("/", url)) {
      return 1;
    }
  } else {
    /* hostname give - check if it's our hostname */

    if (strcmp(host, our_host)) {
      /* hostname isn't ours */
      return 0;
    }

    /* '/' -> splash
     * ''  -> splash
     */
    if (strlen(url) == 0 ||
        !strcmp("/", url)) {
      return 1;
    }
  }
  /* doesnt hit one of our rules - this isn't the splashpage */
  return 0;
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
  char *host = NULL;

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
  if(need_a_redirect(connection, host))
    return redirect_to_splashpage(connection, client, host, url);
  else if(is_splashpage(host, url)) {
    return show_splashpage(connection, client);
  } else {
    return serve_file(connection, client, url);
  }
}

/**
 * @brief redirect the client to the splash page
 * @param connection
 * @param client
 * @param host
 * @param url
 * @return
 */
static int redirect_to_splashpage(struct MHD_Connection *connection, t_client *client, const char *host, const char *url) {
  char *originurl = NULL;
  char *splashpageurl = NULL;
  char *query = NULL;
  char encoded[2048];
  int ret;
  s_config *config = config_get_config();

  get_query(connection, &query);

//  if (config_get_config()->redirectURL)
//    redirecturl = safe_strdup(config_get_config()->redirectURL);
//  else
  safe_asprintf(&originurl, "http://%s%s%s%s", host, url, strlen(query) ? "?" : "" , query);
  if (uh_urlencode(encoded, 2048, originurl, strlen(originurl)) == -1) {
    debug(LOG_WARNING, "could not encode url");
    // TODO: error handle urlencode
  }

  safe_asprintf(&splashpageurl, "http://%s:%u%s?q=%s", config->gw_address , config->gw_port, "/splash.html", encoded);
  debug(LOG_WARNING, "originurl: %s", originurl);
  debug(LOG_WARNING, "splashpageurl: %s", splashpageurl);

  ret = send_redirect_temp(connection, splashpageurl);
  free(splashpageurl);
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

struct collect_query {
  int i;
  char **elements;
};

static int collect_query_string(void *cls, enum MHD_ValueKind kind, const char *key, const char *value) {
  /* what happens when '?=foo' supplied? */
  struct collect_query *collect_query = cls;
  if (key && !value) {
    collect_query->elements[collect_query->i] = safe_strdup(key);
  } else if(key && value) {
    safe_asprintf(&(collect_query->elements[collect_query->i]), "%s=%s", key, value);
  }
  collect_query->i++;
  return MHD_YES;
}

/* a dump iterator required for counting all elements */
static int counter_iterator(void *cls, enum MHD_ValueKind kind, const char *key, const char *value) {
  return MHD_YES;
}

static int get_query(struct MHD_Connection *connection, char **query) {
  int element_counter;
  char **elements;
  struct collect_query collect_query;
  int i;
  int j;
  int length = 0;

  element_counter = MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, counter_iterator, NULL);
  if (element_counter == 0) {
    *query = safe_strdup("");
    return 0;
  }
  elements = calloc(element_counter, sizeof(char *));
  collect_query.i = 0;
  collect_query.elements = elements;

//  static int get_host_value_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value) {
  MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, collect_query_string, &collect_query);

  for(i=0; i<element_counter;i++) {
    if(!elements[i])
      continue;
    length += strlen(elements[i]);

    if(i >0) /* q=foo&o=bar the '&' need also some space */
      length++;
  }

  /* don't miss the zero terminator */
  *query = calloc(1, length+1);

  for(i=0, j=0; i<element_counter;i++) {
    if(!elements[i])
      continue;
    strncpy(*query + j, elements[i], length-j);
    free(elements[i]);
  }

  free(elements);
  return 0;
}

static int send_error(struct MHD_Connection *connection, int error)
{
  struct MHD_Response *response = NULL;
  // cannot automate since cannot translate automagically between error number and MHD's status codes -- and cannot rely on MHD_HTTP_ values to provide an upper bound for an array
  const char *page_400 = "<html><head><title>Error 400</title></head><body><h1>Error 400 - Bad Request</h1></body></html>";
  const char *page_403 = "<html><head><title>Error 403</title></head><body><h1>Error 403 - Forbidden</h1></body></html>";
  const char *page_404 = "<html><head><title>Error 404</title></head><body><h1>Error 404 - Not Found</h1></body></html>";
  const char *page_500 = "<html><head><title>Error 500</title></head><body><h1>Error 500 - Internal Server Error. Oh no!</body></html>";
  const char *page_501 = "<html><head><title>Error 501</title></head><body><h1>Error 501 - Not Implemented</h1></body></html>";
  const char *page_503 = "<html><head><title>Error 503</title></head><body><h1>Error 503 - Internal Server Error</h1></body></html>";


  int ret = MHD_NO;

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
  case 503:
    response = MHD_create_response_from_data(strlen(page_503), (char *)page_503, MHD_NO, MHD_NO);
    ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
    break;
  }

  if (response)
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

  if (!strcmp("Host", key)) {
    *host = safe_strdup(value);
    return MHD_NO;
  }

  return MHD_YES;
}
/**
 * @brief show_splashpage is called when the client clicked on Ok as well when the client doesn't know us yet.
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
 * @brief return an extension like `csv` if file = '/bar/foobar.csv'.
 * @param filename
 * @return a pointer within file is returned. NULL can be returned as well as
 */
const char *get_extension(const char *filename) {
  int pos = strlen(filename);
  while(pos > 0) {
    pos--;
    switch (filename[pos]) {
    case '/':
      return NULL;
    case '.':
      return (filename+pos+1);
    }
  }

  return NULL;
}

#define DEFAULT_MIME_TYPE "application/octet-stream"

const char *lookup_mimetype(const char *filename) {
  int i;
  const char *extension;

  if(!filename) {
    return NULL;
  }

  extension = get_extension(filename);
  if(!extension)
    return DEFAULT_MIME_TYPE;

  for(i=0; i< ARRAY_SIZE(uh_mime_types); i++) {
    if(strcmp(extension, uh_mime_types[i].extn) == 0) {
      return uh_mime_types[i].mime;
    }
  }

  return DEFAULT_MIME_TYPE;
}

/**
 * @brief serve_file try to serve a request via filesystem. Using webroot as root.
 * @param connection
 * @param client
 * @return
 */
static int serve_file(struct MHD_Connection *connection, t_client *client, const char *url) {
  s_config *config = config_get_config();
  struct MHD_Response *response;
  char filename[PATH_MAX];
  int ret = MHD_NO;
  const char *mimetype = NULL;
  size_t size;

  snprintf(filename, PATH_MAX, "%s/%s", config->webroot, url);

  int fd = open(filename, O_RDONLY);
  if (fd < 0)
    return send_error(connection, 404);

  mimetype = lookup_mimetype(filename);

  /* serving file and creating response */
  size = lseek(fd, 0, SEEK_END);
  response = MHD_create_response_from_fd(size, fd);
  MHD_add_response_header(response, "Content-Type", mimetype);
  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);

  return ret;
}
