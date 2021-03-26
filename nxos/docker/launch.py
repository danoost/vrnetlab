#!/usr/bin/env python3

import datetime
import logging
import os
import random
import re
import signal
import sys
import telnetlib
import time

import vrnetlab

def handle_SIGCHLD(signal, frame):
    os.waitpid(-1, os.WNOHANG)

def handle_SIGTERM(signal, frame):
    sys.exit(0)

signal.signal(signal.SIGINT, handle_SIGTERM)
signal.signal(signal.SIGTERM, handle_SIGTERM)
signal.signal(signal.SIGCHLD, handle_SIGCHLD)

TRACE_LEVEL_NUM = 9
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")
def trace(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kws)
logging.Logger.trace = trace



class NXOS_vm(vrnetlab.VM):
    def __init__(self, username, password):
        for e in os.listdir("/"):
            if re.search(".qcow2$", e):
                disk_image = "/" + e
                filename, ext = os.path.splitext(disk_image)
                overlay_disk_image = f"{filename}-overlay{ext}"
        ram = 8192
        super(NXOS_vm, self).__init__(username, password, disk_image=disk_image, ram=ram)
        self.num_nics = 64 # N9k available images are from 9364 & 9500 (chassis) so 64 should be the least common denominator.
        self.credentials = [["admin", "admin"]]
        self.qemu_args.extend(["-pflash", "/usr/share/edk2.git/ovmf-x64/OVMF-pure-efi.fd"])
        # We swap out -display none for -nographic, because we still want the serial console
        self.qemu_args.remove("-display")
        self.qemu_args.remove("none")
        # We remove the -drive declaration, because we manually specify its format later on
        self.qemu_args.remove("-drive")
        self.qemu_args = [x for x in self.qemu_args if "if=ide,file=" not in x]

        self.qemu_args.extend([
            "-nographic",
            # Host CPU mode and providing 2 cores makes for considerably better performance
            "-cpu",
            "host",
            "-smp",
            "cpus=2",
            # Manually declare all the drives and such that we need.
            "-device",
            "ahci,id=ahci0,bus=pci.0",
            "-device",
            "ide-drive,drive=drive-sata-disk0,bus=ahci0.0,id=drive-sata-disk0,bootindex=1",
            "-drive",
            "file=%s,if=none,id=drive-sata-disk0,index=0,media=disk,format=qcow2" % overlay_disk_image,
        ])


    def bootstrap_spin(self):
        """ This function should be called periodically to do work.
        """

        if self.spins > 300:
            # too many spins with no result ->  give up
            self.stop()
            self.start()
            return

        (ridx, match, res) = self.tn.expect(
            [b"Abort Power On Auto Provisioning [yes - continue with normal setup, skip - bypass password and basic configuration, no - continue with Power On Auto Provisioning] (yes/skip/no)[no]:", b"login:"], 1
        )
        if match:  # got a match!
            if ridx == 0:
                self.wait_write("skip", wait=None)
            elif ridx == 1:
                self.logger.debug("matched login prompt")
                try:
                    username, password = self.credentials.pop(0)
                except IndexError as exc:
                    self.logger.error("no more credentials to try")
                    return
                self.logger.debug("trying to log in with %s / %s" % (username, password))
                self.wait_write(username, wait=None)
                self.wait_write(password, wait="Password:")

                # run main config!
                self.bootstrap_config()
                # close telnet connection
                self.tn.close()
                # startup time?
                startup_time = datetime.datetime.now() - self.start_time
                self.logger.info("Startup complete in: %s" % startup_time)
                # mark as running
                self.running = True
                return

        # no match, if we saw some output from the router it's probably
        # booting, so let's give it some more time
        if res != b'':
            self.logger.trace("OUTPUT: %s" % res.decode())
            # reset spins if we saw some output
            self.spins = 0

        self.spins += 1

        return


    def bootstrap_config(self):
        """ Do the actual bootstrap config
        """
        self.logger.info("applying bootstrap configuration")
        self.wait_write("", None)
        self.wait_write("configure")
        self.wait_write("username %s password 0 %s role network-admin" % (self.username, self.password))

        # configure mgmt interface
        self.wait_write("interface mgmt0")
        self.wait_write("ip address 10.0.0.15/24")
        self.wait_write("exit")
        self.wait_write("exit")
        self.wait_write("copy running-config startup-config")


class NXOS(vrnetlab.VR):
    def __init__(self, username, password):
        super(NXOS, self).__init__(username, password)
        self.vms = [ NXOS_vm(username, password) ]

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--trace', action='store_true', help='enable trace level logging')
    parser.add_argument('--username', default='admin', help='Username')
    parser.add_argument('--password', default='admin', help='Password')
    args = parser.parse_args()

    LOG_FORMAT = "%(asctime)s: %(module)-10s %(levelname)-8s %(message)s"
    logging.basicConfig(format=LOG_FORMAT)
    logger = logging.getLogger()

    logger.setLevel(logging.DEBUG)
    if args.trace:
        logger.setLevel(1)

    vr = NXOS(args.username, args.password)
    vr.start()
