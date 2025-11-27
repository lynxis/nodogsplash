/** @file test_client_list_mode.c
    @brief Test cases for the client list modes
    @author Copyright (C) 2025 Alexander Couzens <lynxis@fe80.eu>
*/

#include <asm-generic/errno-base.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/client_list.h"
#include "../src/conf.h"
#include "../src/fw_abstract.h"
#include "../src/fw_common.h"

time_t started_time = 0;
unsigned int authenticated_since_start = 0;

unsigned long long int
dummy_fw_total_download()
{
	return 23;
}

unsigned long long int
dummy_fw_total_upload()
{
	return 42;
}

int
dummy_fw_counters_update(void)
{
	return 0;
}

int
dummy_fw_deauthenticate(t_client *client)
{
	fprintf(stderr, " fw deauth client %s / %s", client->mac, client->ip);
	return 0;
}

int
dummy_fw_authenticate(t_client *client)
{
	fprintf(stderr, " fw auth client %s / %s", client->mac, client->ip);
	return 0;
}

fw_ops fw_gops = {
    .total_download = dummy_fw_total_download,
    .total_upload = dummy_fw_total_upload,
    .authenticate = dummy_fw_authenticate,
    .deauthenticate = dummy_fw_deauthenticate,
    .counters_update = dummy_fw_counters_update,
};

const char *
fw_connection_state_as_string(int mark)
{
	if (mark == FW_MARK_PREAUTHENTICATED)
		return "Preauthenticated";
	if (mark == FW_MARK_AUTHENTICATED)
		return "Authenticated";
	if (mark == FW_MARK_TRUSTED)
		return "Trusted";
	if (mark == FW_MARK_BLOCKED)
		return "Blocked";
	return "ERROR: unrecognized mark";
}

int auth_change_state(t_client *client, const unsigned int new_state, const char *reason)
{
	return 0;
}


void print_client_list(void)
{
	t_client *client = client_get_first_client();
	while (client != NULL) {
		fprintf(stderr, "Client id %d\n", client->id);

		fprintf(stderr, "  IP: %s MAC: %s\n", client->ip, client->mac);
		fprintf(stderr, "  Token: %s\n", client->token ? client->token : "none");

		fprintf(stderr, "  session_start: %ld\n", client->session_start);
		fprintf(stderr, "  session_end: %ld\n", client->session_end);

		fprintf(stderr, "  counters.last_updated: %ld\n", client->counters.last_updated);
		fprintf(stderr, "  counters.incoming: %lld\n", client->counters.incoming);
		fprintf(stderr, "  counters.outgoing: %lld\n", client->counters.outgoing);
		fprintf(stderr, "  download_limit: %d\n", client->download_limit);
		fprintf(stderr, "  upload_limit: %d\n", client->upload_limit);

		client = client->next;
	}
}

struct testclient {
	char *mac;
	char *ip;
};

struct testclient clients[] = {
    {"00:16:3e:d8:29:6e", "192.168.23.6"},
    {"02:ca:ff:ee:ba:be", "192.168.23.7"},
    {"00:01:02:03:04:05", "192.168.23.8"},
    {"00:23:42:03:04:05", "192.168.23.9"},
};

t_client *add_client(int offset)
{
	return client_list_add_client(clients[offset].mac, clients[offset].ip);
}

void test_client_mac_ip(void)
{
	/* Test with client list mode MAC/IP */
	s_config *config = config_get_config();
	t_client *a = add_client(0);
	t_client *b = add_client(1);
	t_client *c = add_client(2);

	config->client_mode = MODE_MAC_IP;

	/* add the three little pigs */
	assert(client_list_find(clients[0].mac, clients[0].ip) == a);
	assert(client_list_find(clients[1].mac, clients[1].ip) == b);
	assert(client_list_find(clients[2].mac, clients[2].ip) == c);

	/* search for a non existant entry */
	assert(client_list_find(clients[3].mac, clients[3].ip) == NULL);

	assert(client_list_find_migrate(clients[2].mac, clients[2].ip) == c);

	/* switch ip/mac, should be NULL in all cases */
	assert(client_list_find_migrate(clients[2].mac, clients[3].ip) == NULL);
}


void test_client_mac(void)
{
	/* Test with client list mode MAC only */
	s_config *config = config_get_config();
	t_client *a = add_client(0);
	t_client *b = add_client(1);
	t_client *c = add_client(2);
	assert(a);
	assert(b);
	assert(c);

	config->client_mode = MODE_MAC;

	/* add the three little pigs */
	assert(client_list_find(clients[0].mac, clients[0].ip) == a);
	assert(client_list_find(clients[1].mac, clients[1].ip) == b);
	assert(client_list_find(clients[2].mac, clients[2].ip) == c);

	/* search for a non existant entry */
	assert(client_list_find(clients[3].mac, clients[3].ip) == NULL);

	/* Should find c, but not update c */
	assert(client_list_find(clients[2].mac, clients[3].ip) == c);

	/* only mac is the search criteria */
	assert(client_list_find(clients[3].mac, clients[2].ip) == NULL);

	assert(!strcmp(clients[2].mac, c->mac));
	assert(!strcmp(clients[2].ip, c->ip));

	/* lets migrate it */
	assert(client_list_find_migrate(clients[2].mac, clients[3].ip) == c);
	assert(!strcmp(clients[2].mac, c->mac));
	assert(!strcmp(clients[3].ip, c->ip));
}

struct a_test {
	const char *name;
	const char *description;
	void (*test_func)(void);
};

struct a_test tests[] = {
    {"client_list_mode_mac_ip", "Test the mode MAC/IP (default)", test_client_mac_ip},
    {"client_list_mode_mac", "Test the mode MAC", test_client_mac},
    {NULL, NULL, NULL},
};

int main(int argc, char **argv)
{
	s_config *config = config_get_config();
	config->maxclients = 256;

	client_list_init();
	struct a_test *current = &tests[0];
	for (; current->test_func != NULL; current++) {
		fprintf(stderr, "Starting test %s (%s)\n", current->name, current->description);
		current->test_func();
		client_list_flush();
	}
	fprintf(stderr, "\nFinished all tests.\n");
}
