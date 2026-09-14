/** @file state_file.c
    @brief State file import/exporter using jansson
    @author Copyright (C) 2025 Alexander Couzens <lynxis@fe80.eu>
*/

#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include <jansson.h>

#include "auth.h"
#include "client_list.h"
#include "debug.h"
#include "fw_common.h"
#include "safe.h"
#include "fw_common.h"

#define NDS_JSON_EXPORT_VERSION 1
#define GOTO_ERR(_err, x) if ((x)) { goto _err; }

static json_t *
state_file_export_client(t_client *client)
{
	json_t *cli = json_object();
	if (!cli)
		return NULL;

	GOTO_ERR(err, json_object_set_new(cli, "ip", json_string(client->ip)));
	GOTO_ERR(err, json_object_set_new(cli, "mac", json_string(client->mac)));
	GOTO_ERR(err, json_object_set_new(cli, "token", json_string(client->token)));
	GOTO_ERR(err, json_object_set_new(cli, "fw_connection_state", json_integer(client->fw_connection_state)));
	GOTO_ERR(err, json_object_set_new(cli, "session_start", json_integer(client->session_start)));
	GOTO_ERR(err, json_object_set_new(cli, "session_end", json_integer(client->session_end)));
	GOTO_ERR(err, json_object_set_new(cli, "download_limit", json_integer(client->download_limit)));
	GOTO_ERR(err, json_object_set_new(cli, "upload_limit", json_integer(client->upload_limit)));

	json_t *counters = json_object();
	if (!counters)
		goto err;

	GOTO_ERR(err_counter, json_object_set_new(counters, "incoming", json_integer(client->counters.incoming)));
	GOTO_ERR(err_counter, json_object_set_new(counters, "outgoing", json_integer(client->counters.outgoing)));
	GOTO_ERR(err_counter, json_object_set_new(counters, "last_updated", json_integer(client->counters.last_updated)));

	GOTO_ERR(err, json_object_set_new(cli, "counters", counters));

	return cli;

err_counter:
	json_decref(counters);
err:
	json_decref(cli);
	return NULL;
}

int
state_file_export(const char *path)
{
	int rc = 0;
	json_t *top = json_object();

	if (!top)
		return -ENOMEM;

	GOTO_ERR(err, json_object_set_new(top, "version", json_integer(NDS_JSON_EXPORT_VERSION)));
	GOTO_ERR(err, json_object_set_new(top, "name", json_string("nodogsplash")));

	json_t *clist = json_array();
	if (!clist)
		goto err;

	LOCK_CLIENT_LIST();
	t_client *ptr;
	for (ptr = client_get_first_client(); ptr; ptr = ptr->next) {
		json_t *client = state_file_export_client(ptr);
		if (!client) {
			UNLOCK_CLIENT_LIST();
			goto err_clist;
		}
		json_array_append_new(clist, client);
	}
	UNLOCK_CLIENT_LIST();
	GOTO_ERR(err_clist, json_object_set_new(top, "clients", clist));

	if ((rc = json_dump_file(top, path, JSON_INDENT(2)))) {
		debug(LOG_ERR, "Failed to write nodogsplash state to file %s", path);
		rc = -EINVAL;
	}

	json_decref(top);
	return rc;

err_clist:
	json_decref(clist);
err:
	json_decref(top);
	return -EINVAL;
}

#define JSON_GET_FIELD_OBJECT(_target, _err, _jsn_obj, _field, _check_func) do { \
		json_t *jsn_ptr = json_object_get(_jsn_obj, _field); \
		if (!jsn_ptr) { \
		    debug(LOG_ERR, "Failed to get field '%s'", _field); \
		    goto _err; \
		} \
		if (!_check_func(jsn_ptr)) { \
		    debug(LOG_ERR, "Wrong type for field '%s'", _field); \
		    goto _err; \
		} \
		_target = jsn_ptr; \
	} while (0)

#define JSON_GET_FIELD(_target, _err, _jsn_obj, _field, _check_func, _val_func) do { \
		json_t *jsn_ptr = json_object_get(_jsn_obj, _field); \
		if (!jsn_ptr) { \
			debug(LOG_ERR, "Failed to get field '%s'", _field); \
			goto _err; \
		} \
		if (!_check_func(jsn_ptr)) { \
			debug(LOG_ERR, "Wrong type for field '%s'", _field); \
			goto _err; \
		}	\
		_target = _val_func(jsn_ptr); \
	} while (0)


int
state_file_import_client(json_t *json_client)
{
	t_client *client = NULL;
	const char *mac = NULL;
	const char *ip = NULL;

	JSON_GET_FIELD(mac, err, json_client, "mac", json_is_string, json_string_value);
	JSON_GET_FIELD(ip, err, json_client, "ip", json_is_string, json_string_value);

	client = client_list_find(mac, ip);
	if (client) {
		debug(LOG_ERR, "Found a duplicate client containing same ip & mac (%s / %s) !", ip, mac);
		return -1;
	}

	client = client_list_add_client(mac, ip);
	if (!client) {
		debug(LOG_ERR, "Failed to add client with mac %s, ip %s. Maybe invalid mac or ip?", mac, ip);
		return -1;
	}

	const char *token = NULL;
	JSON_GET_FIELD(token, err, json_client, "token", json_is_string, json_string_value);
	if (client->token)
		free(client->token);

	client->token = safe_strdup(token);

	JSON_GET_FIELD(client->session_start, err, json_client, "session_start", json_is_integer, json_integer_value);
	JSON_GET_FIELD(client->session_end, err, json_client, "session_end", json_is_integer, json_integer_value);
	JSON_GET_FIELD(client->download_limit, err, json_client, "download_limit", json_is_integer, json_integer_value);
	JSON_GET_FIELD(client->upload_limit, err, json_client, "upload_limit", json_is_integer, json_integer_value);

	json_t *counters = NULL;
	JSON_GET_FIELD_OBJECT(counters, err, json_client, "counters", json_is_object);

	JSON_GET_FIELD(client->counters.incoming, err, counters, "incoming", json_is_integer, json_integer_value);
	JSON_GET_FIELD(client->counters.outgoing, err, counters, "outgoing", json_is_integer, json_integer_value);
	JSON_GET_FIELD(client->counters.incoming_offset, err, counters, "incoming", json_is_integer, json_integer_value);
	JSON_GET_FIELD(client->counters.outgoing_offset, err, counters, "outgoing", json_is_integer, json_integer_value);
	JSON_GET_FIELD(client->counters.last_updated, err, counters, "last_updated", json_is_integer, json_integer_value);

	unsigned int fw_connection_state = FW_MARK_PREAUTHENTICATED;
	JSON_GET_FIELD(fw_connection_state, err, json_client, "fw_connection_state", json_is_integer, json_integer_value);

	auth_change_state(client, fw_connection_state, "import_state_file");

	return 0;
err:
	if (client)
		client_list_delete(client);
	return -1;
}

/*! Import the client list from path. */
int
state_file_import(const char *path)
{
	int rc;
	struct stat statbuf = {};
	rc = stat(path, &statbuf);
	if (rc) {
		if (errno == ENOENT) {
			debug(LOG_DEBUG, "State file doesn't exist. Can't load old state.");
			return 1;
		} else {
			debug(LOG_DEBUG, "State file couldn't accessed. errno %d - %s.", errno, strerror(errno));
			return 2;
		}
	}

	rc = -EINVAL;
	json_error_t error;

	json_t *top = json_load_file(path, 0, &error);
	if (!top) {
		debug(LOG_ERR, "Failed to parse state file %s: line %d: %s", path, error.line, error.text);
		return -1;
	}

	int64_t version = -1;
	JSON_GET_FIELD(version, err, top, "version", json_is_integer, json_integer_value);
	if (version != NDS_JSON_EXPORT_VERSION) {
		debug(LOG_ERR, "Invalid version of state file");
		goto err;
	}

	const char *name = NULL;
	JSON_GET_FIELD(name, err, top, "name", json_is_string, json_string_value);
	if (strcmp(name, "nodogsplash")) {
		debug(LOG_ERR, "Invalid name in state file. Expected %s, but found %s",
		      "nodogsplash", name);
		goto err;
	}

	json_t *clients = NULL;
	JSON_GET_FIELD_OBJECT(clients, err, top, "clients", json_is_array);

	LOCK_CLIENT_LIST();
	int len = json_array_size(clients);
	for (int i = 0; i < len; i++) {
		json_t *client = json_array_get(clients, i);
		if (!json_is_object(client)) {
			debug(LOG_ERR, "clients: Invalid type of array entry %d in state file.", i);
			UNLOCK_CLIENT_LIST();
			goto err;
		}

		rc = state_file_import_client(client);
		if (rc) {
			debug(LOG_ERR, "clients: Ignoring invalid client entry at index %d", i);
		}
	}
	UNLOCK_CLIENT_LIST();

	json_decref(top);
	return 0;

err:
	json_decref(top);
	return rc;
}
