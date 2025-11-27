/** @file test_conf.c
    @brief Test cases for config file parsing
    @author Copyright (C) 2025 Alexander Couzens <lynxis@fe80.eu>
*/

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../../src/conf.h"

/* stub for debug.c */
char *format_time(time_t t, char *buf)
{
	strftime(buf, 64, "%a %b %d %H:%M:%S %Y", localtime(&t));
	return buf;
}

static void reset_config(void)
{
	config_init();
}

void test_conf_minimal(void)
{
	s_config *config;

	reset_config();
	config_read("minimal.conf");
	config = config_get_config();

	assert(!strcmp(config->gw_interface, "virbr1"));
	assert(config->maxclients == 2);
	assert(config->gw_port == 8080);
	assert(!strcmp(config->webroot, "/tmp/splash/htdocs"));
	assert(config->session_timeout == 10080);
	assert(config->preauth_idle_timeout == 5);
	assert(config->auth_idle_timeout == 1440);
	assert(config->session_timeout_block == 0);
	assert(config->client_mode == MODE_MAC_IP);
}

void test_conf_clientlistmode(void)
{
	s_config *config;

	reset_config();
	config_read("clientlistmode.conf");
	config = config_get_config();

	assert(config->client_mode == MODE_MAC);
}

static int trusted_mac_list_length(void)
{
	s_config *config = config_get_config();
	t_MAC *p;
	int count = 0;

	for (p = config->trustedmaclist; p != NULL; p = p->next)
		count++;
	return count;
}

void test_conf_long_trustedlist(void)
{
	s_config *config;

	reset_config();
	config_read("long_trustedlist.conf");
	config = config_get_config();

	/* verify base settings are parsed correctly */
	assert(!strcmp(config->gw_interface, "virbr1"));
	assert(config->maxclients == 2);
	assert(config->gw_port == 8080);

	/* verify all 1000 MAC addresses were parsed from the long line */
	assert(trusted_mac_list_length() == 1000);

	/* MACs are prepended, so first in file is at the tail */
	t_MAC *head = config->trustedmaclist;
	assert(head != NULL);
	assert(!strcasecmp(head->mac, "ae:3E:F7:51:E4:a1"));

	t_MAC *p = head;
	while (p->next != NULL)
		p = p->next;
	assert(!strcasecmp(p->mac, "3E:f9:6C:90:d1:D1"));
}

struct a_test {
	const char *name;
	const char *description;
	void (*test_func)(void);
};

struct a_test tests[] = {
	{"minimal.conf", "Test with a minimal config file", test_conf_minimal},
	{"long_trustedlist.conf", "Test with a long TrustedMACList line (>4096 bytes)", test_conf_long_trustedlist},
	{"clientlistmode.conf", "Test clientlistmode 1 (MAC only)", test_conf_clientlistmode},
	{NULL, NULL, NULL},
};

int main(int argc, char **argv)
{
	struct a_test *current = &tests[0];

	for (; current->test_func != NULL; current++) {
		fprintf(stderr, "Starting test %s (%s)\n", current->name, current->description);
		current->test_func();
	}
	fprintf(stderr, "Finished all tests.\n");
	return 0;
}
