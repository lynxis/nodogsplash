# testing nodogsplash

The automatic testing with nodogsplash uses lxc container and the python3 api of lxc.
These tests are based on the tunneldigger tests.

## Overview of the test system

These test will use lxc containers to setup multiple containers.

* httpd container runs a httpd.
* nds container runs nodogsplash.
* client containers runs test scripts.

The test based on python nose and are located in ./pynosetests/.
For every file in *pynosetests* nodogsplash will restarted and run independent from each other.

```
-------
|httpd|
-------
   |
-------
| nds |
-------
   |
--------
|client|
--------
```

## Setup the environment

`./test_td.py --setup`

will setup the lxc environment and create a template container which is used by all tests.
The resulting container is named nodogsplash-base.

## Do a test run

A test run requires you have setted up the environment.
`./test_td.py --test --server HEAD`

will do a test run using HEAD for the server.

## What does a test run?

* generate a build hash
* checkout the repository
* clone containers based on template container `nodogsplash-base`, naming them `hash-client`, `hash-client`, `hast-httpd`.
* start the scripts `prepare_client.sh`, `prepare_nds.sh`, `prepare_httpd.sh`.
* start the scripts `run_client.sh`, `run_nds.sh`, `run_httpd.sh`

## Files

* travis.sh - entrypoint for travis tests
* jenkins.sh - entrypoint for jenkins tests

* hook_client.sh - hook for the client to configure the interface ip
* hook_server - hooks for the server. add/remove the interface to the bridge

* prepare_client.sh - locally checkout the client and compiles it
* prepare_server.sh - do network configuration, install dependencies(pip) and builds the server

* run_client.sh - starts the client
* run_server.sh - starts the server

* test-data - empty dir used by tests to put test-data like big files for download-testing into it
* test_nose.py - nose test cases
* nodogsplash.py - LXC logic and basic test logic (no tests)

## Future

* move ip setup from prepare into run script
* stop/start client, server, httpd container between each file in the client directory

## travis integration

To run these scripts on travis, it's required to run them as root.

```
sudo: required
script:
  - sudo -E sh ./tests/ci.sh
```
