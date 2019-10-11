#!/usr/bin/env python3

from trepan.api import debug
import lxc
import re
from random import randint
from subprocess import check_call, check_output
from time import sleep
import argparse
import logging
import os
import shlex
import signal
import sys
from threading import Timer

GIT_URL = "https://github.com/nodogsplash/nodogsplash"

LOG = logging.getLogger("test.nodogsplash")

def setup_template():
    """ all test container are cloned from this one
    it's important that this container is *NOT* running!
    """
    container = lxc.Container("nodogsplash-base")

    if not container.defined:
        if not container.create("download", lxc.LXC_CREATE_QUIET, {"dist": "debian",
                                                                   "release": "buster",
                                                                   "arch": "amd64"}):
            raise RuntimeError("failed to create container")

    if not container.running:
        if not container.start():
            raise RuntimeError("failed to start container")

    container.attach_wait(lxc.attach_run_command, ["dhclient", "eth0"])
    check_ping(container, 'google-public-dns-a.google.com', 10)
    container.attach_wait(lxc.attach_run_command, ["apt-get", "update"])
    container.attach_wait(lxc.attach_run_command, ["apt-get", "dist-upgrade", "-y"])

    # nodogsplash requirements
    pkg_to_install = [
        "bridge-utils",
        "libnetfilter-conntrack3",
        "python-dev",
        "libevent-dev",
        "ebtables",
        "python-virtualenv",
        "build-essential",
        "cmake",
        "libnl-3-dev",
        "libnl-genl-3-dev",
        "libasyncns-dev",
        "linux-libc-dev",
        "libffi-dev",
        "python-cffi",
        "libnfnetlink-dev",
        "libnetfilter-conntrack-dev",
        ]
    pkg_to_install += [
        "wget",
        "curl",
        "git",
        "iputils-ping"
        ]
    # for testing the connection
    pkg_to_install += [
        "lighttpd"
        ]

    container.attach_wait(lxc.attach_run_command, ["apt-get", "update"])
    container.attach_wait(lxc.attach_run_command, ["apt-get", "install", "-y"] + pkg_to_install)
    container.shutdown(30)

def get_random_context():
    """ return a random hex similiar to mktemp, but do not check is already used """
    context = randint(0, 2**32)
    context = hex(context)[2:]
    return context

def configure_network(container, bridge, ip_netmask, gateway=None):
    """ configure the container and connect them to the bridge
    container is a lxc container
    bridge the name of your bridge to attach the container
    ip_netmask is the give address in cidr. e.g. 192.168.1.2/24"""
    config = [
        ('lxc.network.type', 'veth'),
        ('lxc.network.link', bridge),
        ('lxc.network.flags', 'up'),
        ('lxc.network.ipv4', ip_netmask),
    ]

    if gateway:
        config += [('lxc.network.gateway', gateway)]

    for item in config:
        container.append_config_item(item[0], item[1])

def configure_mounts(container):
    # mount testing dir
    local_path = os.path.dirname(os.path.realpath(__file__))
    git_repo = local_path + '/../.git'

    # TODO: this mount is very dirty and may be DANGEROUS!!! Unescaped.
    # mount this directory to /testing
    container.append_config_item('lxc.mount.entry', '%s testing none bind,ro,create=dir 0 0' % local_path)
    container.append_config_item('lxc.mount.entry', '%s git_repo none bind,ro,create=dir 0 0' % git_repo)

    # TODO: check if this is required because of libc-dev package
    container.append_config_item('lxc.mount.entry', '/usr/src usr/src none bind,ro 0 0')

def create_bridge(name):
    """ setup a linux bridge device """
    try:
        os.stat('/sys/class/net/%s' % name)
    except FileNotFoundError:
        LOG.info("Creating bridge %s", name)
        check_call(["brctl", "addbr", name], timeout=10)

    check_call(["ip", "link", "set", name, "up"], timeout=10)

    # FIXME: lxc_container: confile.c: network_netdev: 474 no network device defined for 'lxc.network.1.link' = 'br-46723922' option
    sleep(3)

def remove_bridge(name):
    LOG.info("Destroy bridge %s", name)
    check_call(["ip", "link", "set", name, "down"], timeout=10)
    check_call(["brctl", "delbr", name], timeout=10)

def check_ping(container, server, tries):
    """ check the internet connectivity inside the container """
    ping = 'ping -c 1 -W 1 %s' % server
    for i in range(0, tries):
        ret = container.attach_wait(lxc.attach_run_command, shlex.split(ping))
        if ret == 0:
            return True
        sleep(1)
    return False

def generate_test_file():
    """ generate a test file with sha256sum"""
    local_path = os.path.dirname(os.path.realpath(__file__))
    test_data = local_path + '/test-data'
    test_8m = test_data + '/test_8m'
    sum_file = test_data + '/sha256sum'
    if not os.path.exists(test_data):
        os.mkdir(test_data)
    if not os.path.exists(test_8m):
        check_call(['dd', 'if=/dev/urandom', 'of=%s' % test_8m, 'bs=1M', 'count=8'])
        output = check_output(['sha256sum', test_8m], cwd=test_data)
        f = open(sum_file, 'wb')
        f.write(output)
        f.close()

def testing(server_rev, mhd_version=None):
    context = get_random_context()
    print("generate a run for %s" % context)
    httpd, nds, client = prepare_containers(context, server_rev, mhd_version)

    # wait until client is connected to server
    if not check_ping(client, '192.168.250.1', 20):
        raise RuntimeError('Client can not ping 192.168.250.1. Check the container network')

    npid = run_script(nds, 'nds')
    hpid = run_script(httpd, 'httpd')
    cpid = run_script(client, 'client')
    run_tests(nds, client)

def prepare(cont_type, context, prepare_args=[]):
    # create new containers and prepare them to be used in the test case
    # 
    # cont_type: one of httpd, nds, client
    # context: a random generated context to ensure bridges/container names etc. are unique
    # prepare_args: command line argument given to the prepare script. e.g. `prepare_nds.sh $args`

    # e.g. httpd-baf14114
    name = "%s-%s" % (context, cont_type)

    if cont_type not in ['httpd', 'nds', 'client']:
        raise RuntimeError('Unknown container type given')
    if lxc.Container(name).defined:
        raise RuntimeError('Container "%s" already exist!' % name)

    base = lxc.Container("nodogsplash-base")
    if not base.defined:
        raise RuntimeError("Setup first the base container")

    base = lxc.Container("nodogsplash-base")
    if base.running:
        raise RuntimeError(
            "base container %s is still running."
            "Please run lxc-stop --name %s -t 5" %
            (base.name, base.name))

    LOG.info("Cloning base (%s) to %s (%s)", base.name, cont_type, name)
    cont = base.clone(name, None, lxc.LXC_CLONE_SNAPSHOT, bdevtype='aufs')
    if not cont:
        raise RuntimeError('could not create container "%s"' % name)

    cont.append_config_item('lxc.logfile', '/tmp/output.log')

    # network configuration
    # - all container also have another interface to the internet
    #
    #   -------
    #   |httpd|
    #   -------
    #      | --- 192.168.250.0/24
    #   -------
    #   | nds |
    #   -------
    #      | --- 192.168.55.0/24
    #   --------
    #   |client|
    #   --------

    httpd = '%s-http' % context
    client = '%s-cli' % context

    create_bridge(httpd)
    create_bridge(client)

    if cont_type == 'httpd':
        configure_network(cont, httpd, '192.168.250.1/24')
    elif cont_type == 'nds':
        configure_network(cont, httpd, '192.168.250.2/24')
        configure_network(cont, client, '192.168.55.1/24')
    elif cont_type == 'client':
        configure_network(cont, client, '192.168.55.2/24')

    configure_mounts(cont)
    sleep(10)
    if not cont.start():
        print("Container is defined? %s" % cont.defined)
        raise RuntimeError("Can not start container %s" % cont.name)
    sleep(3)
    if not check_ping(cont, 'google-public-dns-a.google.com', 20):
        debug()
        raise RuntimeError("Container doesn't have an internet connection %s"
                % cont.name)

    script = '/testing/prepare_%s.sh' % cont_type
    arguments = [script]
    arguments += prepare_args

    LOG.info("Server %s run %s", name, script)
    ret = cont.attach_wait(lxc.attach_run_command, arguments)
    if ret != 0:
        raise RuntimeError('Failed to prepare the container "%s" type %s' % (name, cont_type))
    LOG.info("Finished prepare_server %s", name)
    return cont

def prepare_containers(context, nds_rev, mhd_version=None):
    """ this does the real test.
    - cloning containers from nodogsplash-base
    - setup network
    - checkout git repos
    - execute "compiler" steps
    - return clientcontainer, servercontainer
    """

    generate_test_file()
    nds_args = [nds_rev]
    if mhd_version:
        nds_args += [mhd_version]

    nds = prepare('nds', context, nds_args)
    httpd = prepare('httpd', context)
    client = prepare('client', context)

    return httpd, nds, client

def run_script(container, cont_type, arguments=[]):
    _arguments = ['/testing/run_%s.sh' % cont_type]
    _arguments += arguments
    pid = container.attach(lxc.attach_run_command, _arguments)
    return pid

def run_tests(server, client):
    """ the client should be already connect to the server """
    ret = client.attach_wait(lxc.attach_run_command, [
        "wget", "-t", "2", "-T", "4", "http://192.168.254.1:8080/testing/test-data/test_8m", '-O', '/dev/null'])
    if ret != 0:
        raise RuntimeError("failed to run the tests")

def clean_up():
    """ clean the up all bridge and containers created by this scripts. It will also abort all running tests."""
    rex = re.compile(r'([a-f0-9]{8})-(httpd|nds|client)')
    for container in lxc.list_containers():
        if not rex.match(container):
            continue

        cont = lxc.Container(container)
        if cont.running:
            LOG.debug("hardstop container %s",cont.name)
            cont.shutdown(0)
        LOG.debug("destroy container %s", cont.name)
        cont.destroy()

    rex = re.compile(r'([a-f0-9]{8})-(http|cli)')
    for device in os.listdir('/sys/devices/virtual/net/'):
        if not rex.match(device):
            continue
        remove_bridge(device)

def check_host():
    """ check if the host has all known requirements to run this script """
    have_brctl = False

    try:
        check_call(["brctl", "--version"], timeout=3)
        have_brctl = True
    except Exception:
        pass

    if not have_brctl:
        sys.stderr.write("No brctl installed\n")

    if have_brctl:
        print("Everything is installed")
        return True
    raise RuntimeError("Missing dependencies. See stderr for more info")

def run_as_lxc(container, command, timeout=10):
    """
    run command within container and returns output

    command is a list of command and arguments,
    The output is limited to the buffersize of pipe (64k on linux)
    """
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    pid = container.attach(lxc.attach_run_command, command, stdout=write_fd, stderr=write_fd)
    timer = Timer(timeout, os.kill, args=(pid, signal.SIGKILL), kwargs=None)
    if timeout:
        timer.start()
    output_list = []
    os.waitpid(pid, 0)
    timer.cancel()
    try:
        while True:
            output_list.append(os.read(read_fd, 1024))
    except BlockingIOError:
        pass
    return bytes().join(output_list)

def check_if_git_contains(container, repo_path, top_commit, search_for_commit):
    """ checks if a git commit is included within a certain tree
    look into repo under *repo_path*, check if search_for_commit is included in the top_commit
    """
    cmd = ['sh', '-c', 'cd %s ; git merge-base "%s" "%s"' % (repo_path, top_commit, search_for_commit)]
    base = run_as_lxc(container, cmd)
    sys.stderr.write("\nGIT call is %s\n" % cmd)
    sys.stderr.write("\nGIT returns is %s\n" % base)
    if base.startswith(bytes(search_for_commit, 'utf-8')):
        # the base must be the search_for_commit when search_for_commit should included into top_commit
        # TODO: replace with git merge-base --is-ancestor
        return True
    return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Test nodogsplash version against each other")
    # operation on the hosts
    parser.add_argument('--check-host', dest='check_host', action='store_true', default=False,
            help="Check if the host has all requirements installed")
    parser.add_argument('--setup', dest='setup', action='store_true', default=False,
            help="Setup the basic template. Must run once before doing the tests.")
    # testing arguments
    parser.add_argument('-t', '--test', dest='test', action='store_true', default=False,
            help="Do a test run. Server rev and Client rev required. See -s and -c.")
    parser.add_argument('-s', '--server', dest='server', type=str,
            help="The revision used by the server")
    # clean up
    parser.add_argument('--clean', action='store_true', default=False,
            help="Clean up (old) containers and bridges. This will kill all running tests!")
    parser.add_argument('--mhd', dest='mhd_version', default=None,
            help="Set the version of the libmicrohttpd.")

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    if not args.check_host and not args.setup and not args.test and not args.clean:
      parser.print_help()

    if args.check_host:
        check_host()

    if args.setup:
        setup_template()

    if args.test:
        if not args.server:
            raise RuntimeError("No server revision given. E.g. --test --server aba123.")
        testing(args.server, args.mhd_version)

    if args.clean:
        clean_up()
