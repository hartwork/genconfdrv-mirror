#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import print_function

import argparse
import fs.tempfs
import fs.path
import ipaddress
import json
import os
import subprocess
import sys
import uuid

__VERSION__ = '0.1'


class ConfigDrive:
    def __init__(self, genisoimage='/usr/bin/genisoimage', verbose=False):
        self._tmpfs = None
        self._genisoimage = genisoimage
        self._user_data = {}  # {"system_info": {"default_user": None}}
        self._interfaces = []
        self._pubkeys = []
        self._verbose = verbose
        self._clean_metadata = False

        self._added_resolv_module_call = False

        if not os.path.exists(genisoimage):
            print("Error: %s does not exist, no genisoimage found!" % genisoimage, file=sys.stderr)
            sys.exit(1)

        self.open()

    def set_hostname(self, hostname):
        self._hostname = hostname

    def conf_network(self, interface, address=None, gateway=None, *extra_routes):
        if not address and gateway:
            raise ValueError("You cannot define a gateway, but supply no address")

        if not self._interfaces:
            self._interfaces.extend([
                "auto lo",
                "iface lo inet loopback",
            ])

        if address:
            if address == "dhcp":
                address = None
                method = "dhcp"
            elif "/" in address:
                address = ipaddress.ip_interface(address)
                method = "static"
            else:
                raise ValueError("IP Interface is not a subnet")
        else:
            method = "manual"

        self._interfaces.extend([
            "",
            "auto %s" % interface,
            "iface %s inet%s %s" % (interface, "" if not address or address.version == 4 else "6", method),
        ])

        if address:
            self._interfaces.append("    address %s" % address)

        if gateway:
            self._interfaces.append("    gateway %s" % str(ipaddress.ip_address(gateway)))

        for routedef in extra_routes:
            if "-" not in routedef:
                raise ValueError("Route {} is missing a gateway separated by a -".format(routedef))
            route, gw = routedef.split('-')
            if "/" not in route:
                raise ValueError("Route {} is not a subnet".format(route))
            route = ipaddress.ip_interface(route)
            gw = ipaddress.ip_address(gw)
            self._interfaces.append("    up ip route add {} via {}".format(route, gw))

    def conf_resolve(self, resolvers):
        if not self._hostname:
            raise ValueError("Please set a hostname before calling this function")

        for n, resolver in enumerate(resolvers, 1):
            try:
                ipaddress.ip_address(resolver)
            except ValueError as e:
                print("Nameserver argument %s: %s" % (n, e), file=sys.stderr)
                sys.exit(1)

        self._user_data["manage_resolv_conf"] = True
        self._user_data["resolv_conf"] = {
            "nameservers": resolvers,
        }

        if "." in self._hostname:
            self._user_data["domain"] = ".".join(self._hostname.split(".")[1:])

        # debian, by default, does not call the cc_resolv_conf module

        if not self._added_resolv_module_call:
            self.add_command("cloud-init single --name cc_resolv_conf", True)
            self._added_resolv_module_call = True

    def set_clean_metadata(self, do_clean_metadata):
        self._clean_metadata = do_clean_metadata

    def add_user(self, name, keys=None, gecos=None, sudo=False, password=None):
        if "users" not in self._user_data:
            self._user_data["users"] = []

        user = {
            "name": name,
            "shell": "/bin/bash",
            "home": "/home/%s" % name
        }

        if keys:
            if type(keys) == str:
                keys = [keys]

            user["ssh_authorized_keys"] = keys

        if gecos:
            user["gecos"] = gecos

        if sudo:
            user["sudo"] = "ALL=(ALL) NOPASSWD:ALL"

        if password:
            raise NotImplementedError("crypt, salt, $6$ something")

        self._user_data["users"].append(user)

    def add_fp(self, path, fp):
        self.add_text(path, fp.read())

    def add_text(self, path, content):
        dir_path = fs.path.dirname(path)
        if dir_path and not self._tmpfs.exists(dir_path):
            self._tmpfs.makedirs(dir_path)

        self._tmpfs.settext(path, content)
        if self._verbose:
            print(" >>", path)
            print(content)
            print()

    def open(self):
        if not self._tmpfs:
            self._tmpfs = fs.tempfs.TempFS("genconfdrv", auto_clean=True)

    def _write_metadata(self):
        if not self._hostname:
            raise ValueError("No hostname set")

        meta_data = {
            # "availability_zone": "cat",
            "files": [],
            "hostname": self._hostname,
            "name": self._hostname.split(".")[0],
            # "meta": {
            #     "role": "webservers",
            #     "essential": False,
            # }
            "uuid": str(uuid.uuid4()),
        }

        if self._interfaces:
            # add the source-directory to interfaces
            self._interfaces.extend([
                "",
                "source-directory /etc/network/interfaces.d/",
                "",
            ])

            meta_data["files"].append({"content_path": "/content/0000", "path": "/etc/network/interfaces"})
            self.add_text("/openstack/content/0000", "\n".join(self._interfaces))

            meta_data["files"].append({"content_path": "/content/0001",
                                       "path": "/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"})
            self.add_text("/openstack/content/0001", "network: {config: disabled}")

        # do not look for datasource on every boot
        if self._clean_metadata:
            meta_data["files"].append({"content_path": "/content/0002",
                                       "path": "/etc/cloud/cloud.cfg.d/99-manual-cache-clean.cfg"})
            self.add_text("/openstack/content/0002", "manual_cache_clean: True")

        if self._pubkeys:
            meta_data["public_keys"] = {}
            for n, key in enumerate(self._pubkeys):
                meta_data["public_keys"]["key-%02d" % n] = key

        self.add_text("/openstack/latest/meta_data.json", json.dumps(meta_data, indent=4))

    def enable_upgrades(self):
        self._user_data["package_update"] = True
        self._user_data["package_upgrade"] = True

    def add_command(self, command, boot=True):
        key = "bootcmd" if boot else "runcmd"
        if key not in self._user_data:
            self._user_data[key] = []

        self._user_data[key].append(command)

    def add_pubkey(self, pubkey):
        self._pubkeys.append(pubkey)

    def set_password(self, user, password):
        if "chpasswd" not in self._user_data:
            self._user_data["chpasswd"] = {}
            self._user_data["chpasswd"]["list"] = ""
            # self._user_data["chpasswd"]["list"] = []

        # self._user_data["chpasswd"]["list"].append("%s:%s" % (user, password))
        self._user_data["chpasswd"]["list"] += "%s:%s\n" % (user, password)

    def _write_userdata(self):
        self.add_text("/openstack/latest/user_data", "#cloud-config\n" + json.dumps(self._user_data, indent=4))

    def write_drive(self, path, fmt):
        self._write_metadata()
        self._write_userdata()

        if fmt == "iso":
            self._write_iso(path)
        elif fmt == "tgz":
            self._write_tgz(path)
        else:
            raise ValueError("Unknown format")

    def _write_iso(self, path):
        p = subprocess.Popen([self._genisoimage,
                              "-J", "-r", "-q",
                              "-V", "config-2",
                              "-publisher", "seba-genconfdrv"
                              "-l", "-ldots", "-allow-lowercase", "-allow-multidot",
                              "-input-charset", "utf-8",
                              "-o", path,
                              self._tmpfs.getsyspath(""),
                              ])

        return p.wait()

    def _write_tgz(self, path):
        p = subprocess.Popen(["tar", "cfz", path, "-C", self._tmpfs.getsyspath(""), "."])
        return p.wait()

    def close(self):
        if self._tmpfs:
            self._tmpfs.close()

# defaults for testing
#        cfgdrv.set_hostname("foo.someserver.de")
#        cfgdrv.conf_network("ens3", "172.23.0.4/24", "172.23.0.1")
#        cfgdrv.conf_resolve(["1.1.1.1", "8.8.8.8"])
#        cfgdrv.enable_upgrades()
#        cfgdrv.add_command("rm -rf /home/debian/; userdel debian; groupdel debian", True)
#        cfgdrv.add_command("cloud-init single --name cc_resolv_conf", True)
#        cfgdrv.add_command("rm -f /etc/network/interfaces.d/eth*.cfg", True)
#        cfgdrv.add_command("sed -rni '/^([^#]|## template)/p' /etc/cloud/templates/sources.list.*.tmpl; "
#                           "rm /etc/apt/sources.list.d/*", True)
#        #cfgdrv.add_command("(whoami; date) > /root/bleep", False)
#        cfgdrv.add_pubkey("ssh-rsa bleep foo")
#        cfgdrv.set_password("root", "kitteh")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-H", "--hostname", required=True, help="Hostname")
    parser.add_argument("-o", "--output", required=True, help="Path to write iso to")
    parser.add_argument("-n", "--nameservers", "--ns", default=["1.1.1.1", "8.8.8.8"], nargs="+", help="Nameservers")
    parser.add_argument("-i", "--networks", "--net", default=[], nargs="+",
                        help="Specify all networks, in format of interface[:address[:gateway[:route-gateway[:...]]]]. "
                             "Both : and ; can be used as delimiter (but only one per net config). "
                             "Address MUST be a network in CIDR notation or dhcp for DHCP mode. "
                             "Additional routes can be added in the form of cidr-gateway, e.g. "
                             "10.0.0.0/8-10.0.0.1")
    parser.add_argument("-u", "--disable-upgrades", action="store_true", default=False)
    parser.add_argument("-v", "--verbose", action="store_true", default=False)
    parser.add_argument("--no-debian-cleanup", "--ndc", action="store_true", default=False)
    parser.add_argument("--no-debian-sources-cleanup", "--ndsc", action="store_true", default=False)
    parser.add_argument("--no-remove-cloud-init", action="store_true", default=False,
                        help="Do not purge cloud-init from system after execution")
    parser.add_argument("--set-root-password", "--srp", default=None)
    parser.add_argument("-a", "--add-user", default=[], nargs="+",
                        help="Add users, format is username:key?:sudo?:gecos?:password?, "
                             "sudo is a bool, key is either an ssh key or a path to an ssh key")
    parser.add_argument("-f", "--format", default=None, choices=('tgz', 'iso'),
                        help="Specify output format, default is to infer from output file extension")

    args = parser.parse_args()

    if not args.format:
        if args.output.endswith(".tar.gz") or args.output.endswith(".tgz"):
            args.format = "tgz"
        elif args.output.endswith(".iso"):
            args.format = "iso"
        else:
            parser.error("Could not infer output format from output file extension")

    cfgdrv = None
    try:
        cfgdrv = ConfigDrive(verbose=args.verbose)

        cfgdrv.set_hostname(args.hostname)

        for net in args.networks:
            if ";" in net:
                net = net.split(";")
            else:
                net = net.split(":")
            cfgdrv.conf_network(*net)

        if args.nameservers:
            cfgdrv.conf_resolve(args.nameservers)

        if not args.disable_upgrades:
            cfgdrv.enable_upgrades()

        if not args.no_debian_cleanup:
            cfgdrv.add_command("rm -f /etc/network/interfaces.d/eth*", True)
            cfgdrv.add_command("sed -rni '/^([^#]|## template)/p' /etc/cloud/templates/sources.list.*.tmpl", True)
            cfgdrv.add_command("sed -rni '/^([^#]|## template)/p' "
                               "/etc/resolv.conf /etc/cloud/templates/resolv.conf.tmpl", True)

        if not args.no_debian_sources_cleanup:
            cfgdrv.add_command("rm /etc/apt/sources.list.d/*", True)

        if args.set_root_password:
            cfgdrv.set_password("root", args.set_root_password)

        if args.add_user:
            for user in args.add_user:
                user = user.split(":")
                # user key sudo gecos password
                if len(user) < 2:
                    parser.error("Missing key parameter for user")

                keys = ""
                if len(user) >= 2:
                    if user[1].startswith("ssh-"):
                        keys = [user[1]]
                    else:
                        with open(os.path.expanduser(user[1])) as keyfile:
                            keys = keyfile.read().split("\n")

                sudo = True
                if len(user) >= 3:
                    sudo = user[2] not in (False, 0, "0", "no", "false", "False")

                gecos = None
                if len(user) >= 4:
                    gecos = user[3]

                password = None
                if len(user) >= 5:
                    password = user[4]
                cfgdrv.add_user(user[0], keys, sudo=sudo, gecos=gecos, password=password)

        if not args.no_remove_cloud_init:
            cfgdrv.add_command("apt remove -y cloud-init")

        if args.output:
            cfgdrv.write_drive(args.output, args.format)
    finally:
        if cfgdrv:
            cfgdrv.close()


if __name__ == '__main__':
    main()
