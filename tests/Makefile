

.PHONY: all tests
all: tests

tests: run_test_client_list_mode run_test_conf run_tests_state_file

# client list mode tests
run_test_client_list_mode: test_client_list_mode
	./test_client_list_mode

TEST_CLIENT_LIST_MODE_OBJECT := \
	test_client_list_mode.c \
	../src/client_list.c \
	../src/conf.c \
	../src/debug.c \
	../src/fw_common.c \
	../src/safe.c \
	../src/tc.c \
	../src/util.c

test_client_list_mode: $(TEST_CLIENT_LIST_MODE_OBJECT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o test_client_list_mode $+ $(LDLIBS)

# state_file tests
run_tests_state_file:
	$(MAKE) -C ./state_file/ tests

# conf tests
run_test_conf:
	$(MAKE) -C ./conf/ tests

clean:
	rm ./test_client_list_mode
	$(MAKE) -C ./conf/ clean
	$(MAKE) -C ./state_file/ clean
