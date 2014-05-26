#!/usr/bin/env python
#
import os
import sys
import time
import struct
import socket

from netaddr import IPNetwork
from daemon import daemon
from threading import Thread, RLock
import Queue

import radix
import adns
import sqlite3
import json

#
# Configuration section.
#
config = {}

# PID file location.
config["pid_file"] = "/opt/gixflow/gixflow.pid"

# Logging and debugging.
config["log_file"] = "/opt/gixflow/log_gixflow"
config["debug"] = True

# DB file location.
config["db_file"] = "/opt/gixflow/gixflow.db"

# Listen on the given IP address and port.
# Set to blank to bind to all IP addresses.
config["listen_port"] = 9000

config["listen_ipv4"] = "178.32.56.59"
config["listen_ipv4_enable"] = True

config["listen_ipv6"] = "2001:41d0:2:541b::2"
config["listen_ipv6_enable"] = True

# Size of the NetFlow queue.
config["netflow_queue"] = 50000

# Number of NetFlow workers.
config["netflow_workers"] = 50

# Enable/Disable: Forwarding NetFlow data to another collector.
config["forwardto_enable"] = False
config["forwardto_ip"] = "127.0.0.1"
config["forwardto_port"] = 2100

# Enable/Disable: IP2ASN lookup using Cymru DNS service.
# Keep in mind that the process can generate thousands of DNS queries
# to your local DNS resolver which will forward them to Cymru DNS servers.
config["ip2asn"] = False

#
# Main code - do not modify the code below the line
#
Running = False

# NetFlow sources
netflow_sources = {}


class NetflowMessageID:
    TemplateV9 = 0
    Template = 2
    Template_Optional = 3
    FlowRecord = 256
    FlowRecord_Optional1 = 257
    FlowRecord_Optional2 = 512


class ASNtype:
    Internal = 0
    Unknown = 4294967295


class PrefixExpire:
    # never - for RFC special IP networks and known prefixes
    Never = 0
    # 4 weeks - for prefixes where DNS lookup returned data
    Default = 2419200
    # 2 hours - for prefixes where DNS lookup returned no data or failed
    Short = 7200


def RFCPrefixTable():
    prefix_cache = radix.Radix()

    # Current network (only valid as source address)
    prefix = prefix_cache.add("0.0.0.0/8")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # Private network
    prefix = prefix_cache.add("10.0.0.0/8")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # Loopback
    prefix = prefix_cache.add("127.0.0.0/8")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # Link-local
    prefix = prefix_cache.add("169.254.0.0/16")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # Private network
    prefix = prefix_cache.add("172.16.0.0/12")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # IETF Protocol Assignments
    prefix = prefix_cache.add("192.0.0.0/24")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # TEST-NET-1, documentation and examples
    prefix = prefix_cache.add("192.0.2.0/24")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # Private network
    prefix = prefix_cache.add("192.168.0.0/16")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # Network benchmark tests
    prefix = prefix_cache.add("198.18.0.0/15")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # TEST-NET-2, documentation and examples
    prefix = prefix_cache.add("198.51.100.0/24")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # TEST-NET-3, documentation and examples
    prefix = prefix_cache.add("203.0.113.0/24")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # IP multicast (former Class D network)
    prefix = prefix_cache.add("224.0.0.0/4")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # Reserved (former Class E network)
    prefix = prefix_cache.add("240.0.0.0/4")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never

    # Overlay Routable Cryptographic Hash IDentifiers (ORCHID) addresses
    prefix = prefix_cache.add("2001:10::/28")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # Documentation and examples
    prefix = prefix_cache.add("2001:db8::/32")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # The second instance of the 6bone experimental network
    prefix = prefix_cache.add("3ffe::/16")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # The first instance of the 6bone experimental network
    prefix = prefix_cache.add("5f00::/8")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # Unique-local
    prefix = prefix_cache.add("fc00::/7")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never
    # Link-local
    prefix = prefix_cache.add("fe80::/10")
    prefix.data["asn"] = ASNtype.Unknown
    prefix.data["exp"] = PrefixExpire.Never

    # AS112 DNS
    prefix = prefix_cache.add("192.175.48.0/24")
    prefix.data["asn"] = 112
    prefix.data["exp"] = PrefixExpire.Never
    # AS112 DNS
    prefix = prefix_cache.add("2620:4f:8000::/48")
    prefix.data["asn"] = 112
    prefix.data["exp"] = PrefixExpire.Never

    # definition of IP networks which should be considered by AS-Stats as local
    # prefix = prefix_cache.add("x.x.x.x/yy")
    # prefix.data["asn"] = ASNtype.Internal
    # prefix.data["exp"] = PrefixExpire.Never
    # prefix = prefix_cache.add("x:x:x::/yy")
    # prefix.data["asn"] = ASNtype.Internal
    # prefix.data["exp"] = PrefixExpire.Never

    return prefix_cache


def IP2ASNresolver(adns_resolver, ip_addr):
    global prefix_cache

    try:
        ip_addr_ar = ip_addr.split(".")
        ip_net = ip_addr_ar[0] + "." + ip_addr_ar[1] + "." + ip_addr_ar[2] + ".0"
        ip_rev = "0." + ip_addr_ar[2] + "." + ip_addr_ar[1] + "." + ip_addr_ar[0]

        ts = int(time.time())
        rnode = prefix_cache.search_best(ip_addr)
        if rnode is None:
            qa = None
            qac = 0

            while ((qa is None or qa[3] == ()) and qac <= 1):
                qa = adns_resolver.synchronous(ip_rev + ".origin.asn.cymru.com", adns.rr.TXT)
                qac += 1

            if qa is not None and qa[3] != ():
                for i in range(0, len(qa[3])):
                    asn = int(qa[3][i][0].split("|")[0].split(" ")[0])
                    ip_prefix = qa[3][i][0].split("|")[1].split(" ")[1]

                    with lock:
                        prefix = prefix_cache.add(ip_prefix)
                        prefix.data["asn"] = asn
                        prefix.data["exp"] = ts + PrefixExpire.Default

                asn = prefix_cache.search_best(ip_addr).data["asn"]

            else:
                asn = ASNtype.Unknown

                with lock:
                    prefix = prefix_cache.add(ip_net + "/24")
                    prefix.data["asn"] = asn
                    prefix.data["exp"] = ts + PrefixExpire.Short

        else:
            if rnode.data["exp"] == 0 or rnode.data["exp"] >= ts:
                asn = rnode.data["asn"]
            else:
                prefix_cache.delete(rnode.prefix)
                asn = IP2ASNresolver(adns_resolver, ip_addr)

    except:
        asn = ASNtype.Unknown

        with lock:
            prefix = prefix_cache.add(ip_net + "/24")
            prefix.data["asn"] = asn
            prefix.data["exp"] = ts + PrefixExpire.Short

        if config["debug"]:
            e = str(sys.exc_info())
            sys.stdout.write("I2A - exception: " + e + ", ip: " + ip_addr + ".\n")
            sys.stdout.flush()

        pass

    return int(asn)


def Stats_Worker():
    global Running, prefix_cache

    swi = 1

    while Running:
        time.sleep(10)

        if swi == 12:
            swi = 1
            if config["debug"]:
                sys.stdout.write("SW - Dumping prefix table to SQLite database.\n")
                sys.stdout.flush()
            sqlite_con = sqlite3.connect(config["db_file"])
            sqlite_cur = sqlite_con.cursor()
            sqlite_cur.execute("DELETE FROM prefixes")

            nodes = prefix_cache.nodes()
            for rnode in nodes:
                sqlite_cur.execute("INSERT INTO prefixes VALUES ('" + rnode.prefix + "', " + str(rnode.data["asn"]) + ", " + str(rnode.data["exp"]) + ")")

            sqlite_con.commit()
            sqlite_con.close()

        else:
            swi += 1
            if config["debug"]:
                prefixes = prefix_cache.prefixes()
                sys.stdout.write("SW - Nb of prefixes: " + str(len(prefixes)) + ", swi: " + str(swi) + ".\n")
                sys.stdout.flush()

                for ipaddr in netflow_sources.keys():
                    sys.stdout.write("SW - " + ipaddr + ", packets: " + str(netflow_sources[ipaddr]["packets"]) + ".\n")
                    sys.stdout.flush()


def NetFlow_Worker():
    if config["ip2asn"]:
        adns_resolver = adns.init()

    while Running:
        try:
            while Running:
                nf_src_ip, data = netflow_queue.get(block=True, timeout=10)
                if config["ip2asn"]:
                    NetFlow_Processor(adns_resolver, nf_src_ip, data)
                else:
                    NetFlow_Processor(0, nf_src_ip, data)
                netflow_queue.task_done()

        except Queue.Empty:
            if config["debug"]:
                sys.stdout.write("NFW - Flow queue is empty.\n")
                sys.stdout.flush()
            pass

        except:
            if config["debug"]:
                e = str(sys.exc_info())
                sys.stdout.write("NFW - exception: " + e + "\n")
                sys.stdout.flush()
            pass


def NetFlow_Receiver(netrecvd):
    global Running, netflow_sources

    if netrecvd == "ipv4":
        listen_ipv4 = (config["listen_ipv4"], config["listen_port"])
        UDPSockv4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        UDPSockv4.bind(listen_ipv4)
    elif netrecvd == "ipv6":
        listen_ipv6 = (config["listen_ipv6"], config["listen_port"])
        UDPSockv6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        UDPSockv6.bind(listen_ipv6)
    else:
        if config["debug"]:
            sys.stdout.write("NR - NetFlow receiver must be started with a valid argument.\n")
            sys.stdout.flush()
        Running = False

    while Running:
        try:
            if netrecvd == "ipv4":
                while Running:
                    data, ipaddr = UDPSockv4.recvfrom(8192)
                    netflow_queue.put([ipaddr[0], data], block=False)

                    with lock:
                        if ipaddr[0] in netflow_sources.keys():
                            netflow_sources[ipaddr[0]]["packets"] = netflow_sources[ipaddr[0]]["packets"] + 1
                        else:
                            netflow_sources[ipaddr[0]] = {}
                            netflow_sources[ipaddr[0]]["packets"] = 1

            else:
                while Running:
                    data, ipaddr = UDPSockv6.recvfrom(8192)
                    netflow_queue.put([ipaddr[0], data], block=False)

                    with lock:
                        if ipaddr[0] in netflow_sources.keys():
                            netflow_sources[ipaddr[0]]["packets"] = netflow_sources[ipaddr[0]]["packets"] + 1
                        else:
                            netflow_sources[ipaddr[0]] = {}
                            netflow_sources[ipaddr[0]]["packets"] = 1

        except Queue.Full:
            if config["debug"]:
                sys.stdout.write("NR - Flow queue is full.\n")
                sys.stdout.flush()
            pass

        except:
            if config["debug"]:
                e = str(sys.exc_info())
                sys.stdout.write("GF - exception: " + e + "\n")
                sys.stdout.flush()
            pass


def NetFlow_Processor(adns_resolver, nf_src_ip, data):
    try:
        nfdec_pos = 0

        nfdec_pos_size = 2
        nf_hdr_version, = struct.unpack(">H", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
        if config["forwardto_enable"]:
            data_tx = data[nfdec_pos:nfdec_pos + nfdec_pos_size]
        nfdec_pos += nfdec_pos_size

        if nf_hdr_version == 10:
            nfdec_pos_size = 18
            nf_hdr_length, nf_hdr_export_time, nf_hdr_sequence_number, nf_hdr_domain_id, nf_hdr_info_element_id, nf_hdr_field_length = struct.unpack(">HIIIHH", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
            nfdec_pos += nfdec_pos_size

            if nf_hdr_info_element_id == NetflowMessageID.Template:
                nfdec_pos_size = 4
                nf_tmpl_id, nf_tmpl_field_count = struct.unpack(">HH", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
                nfdec_pos += nfdec_pos_size

                nfdec_pos_size = nf_tmpl_field_count * 4
                nfd_template_v10 = struct.unpack(">" + "H" * (nfdec_pos_size / 2), data[nfdec_pos:nfdec_pos + nfdec_pos_size])
                nfdec_pos += nfdec_pos_size

            elif nf_hdr_info_element_id == NetflowMessageID.Template_Optional:
                nfdec_pos_size = 6
                nf_tmpl_id, nf_tmpl_field_count, nf_tmpl_scope_field_count = struct.unpack(">HHH", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
                nfdec_pos += nfdec_pos_size

                nfdec_pos_size = nf_tmpl_field_count * 4
                nfd_template_v10_optional = struct.unpack(">" + "H" * (nfdec_pos_size / 2), data[nfdec_pos:nfdec_pos + nfdec_pos_size])
                nfdec_pos += nfdec_pos_size

                nfdec_pos_size = nf_tmpl_scope_field_count * 2
                nfd_template_v10_scope = struct.unpack(">" + "H" * (nf_tmpl_scope_field_count), data[nfdec_pos:nfdec_pos + nfdec_pos_size])
                nfdec_pos += nfdec_pos_size

            elif nf_hdr_info_element_id == NetflowMessageID.FlowRecord_Optional1:
                nfdec_pos_size = 18
                nf_x1, nf_x2, nf_x3, nf_x4, nf_x5 = struct.unpack(">IQIBB", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
                nfdec_pos += nfdec_pos_size

            elif nf_hdr_info_element_id == NetflowMessageID.FlowRecord_Optional2:
                nfdec_pos_size = 18
                nf_x1, nf_x2, nf_x3, nf_x4, nf_x5 = struct.unpack(">IQIBB", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
                nfdec_pos += nfdec_pos_size

            elif nf_hdr_info_element_id == NetflowMessageID.FlowRecord:
                i = 0
                while nfdec_pos != nf_hdr_length:
                    i += 1

                    # v10 template JUNOS 11.4R7.5
                    nfdec_pos_size = 72
                    nf_data = struct.unpack(">IIBBHHHIBBIIIBIQQQQB", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
                    nfdec_pos += nfdec_pos_size

                    nfi_src_ip = socket.inet_ntoa(struct.pack("!L", nf_data[0]))
                    nfi_dst_ip = socket.inet_ntoa(struct.pack("!L", nf_data[1]))
                    # nfi_in_int = nf_data[7]
                    # nfi_src_mask = nf_data[8]
                    # nfi_dst_mask = nf_data[9]
                    # nfi_src_as = nf_data[10]
                    # nfi_dst_as = nf_data[11]
                    # nfi_out_int = nf_data[14]
                    # nfi_bytes = nf_data[15]
                    # nfi_packets = nf_data[16]
                    # ip = IPNetwork(nfi_src_ip + "/" + str(nfi_src_mask))
                    # nfi_src_net = str(ip.network) + "/" + str(nfi_src_mask)
                    # ip = IPNetwork(nfi_dst_ip + "/" + str(nfi_dst_mask))
                    # nfi_dst_net = str(ip.network) + "/" + str(nfi_dst_mask)

                    if config["ip2asn"]:
                        src_as = IP2ASNresolver(adns_resolver, nfi_src_ip)
                        dst_as = IP2ASNresolver(adns_resolver, nfi_dst_ip)

            else:
                if config["debug"]:
                    sys.stdout.write("NFP - Unknown NetFlow message type: " + str(nf_hdr_info_element_id) + ", src ip: " + nf_src_ip + ".\n")
                    sys.stdout.flush()

        elif nf_hdr_version == 9:
            nfdec_pos_size = 20
            nf_hdr_count, nf_hdr_sys_uptime, nf_hdr_unix_sec, nf_hdr_pack_seq, nf_hdr_source_id, nf_hdr_info_element_id = struct.unpack(">HIIIIH", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
            if config["forwardto_enable"]:
                data_tx = data_tx + struct.pack(">HIIIIH", nf_hdr_count, nf_hdr_sys_uptime, nf_hdr_unix_sec, nf_hdr_pack_seq, nf_hdr_source_id, nf_hdr_info_element_id)
            nfdec_pos += nfdec_pos_size

            if nf_hdr_info_element_id == NetflowMessageID.TemplateV9:
                nfdec_pos_size = 6
                nf_tmpl_length, nf_tmpl_id, nf_tmpl_field_count = struct.unpack(">HHH", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
                if config["forwardto_enable"]:
                    data_tx = data_tx + struct.pack(">HHH", nf_tmpl_length + 8, nf_tmpl_id, nf_tmpl_field_count + 2)
                nfdec_pos += nfdec_pos_size

                nfdec_pos_size = nf_tmpl_field_count * 4
                nfd_template_v9 = struct.unpack(">" + "H" * (nfdec_pos_size / 2), data[nfdec_pos:nfdec_pos + nfdec_pos_size])
                if config["forwardto_enable"]:
                    data_tx = data_tx + data[nfdec_pos:nfdec_pos + nfdec_pos_size]
                nfdec_pos += nfdec_pos_size

                if config["forwardto_enable"]:
                    data_tx = data_tx + struct.pack(">HHHH", 16, 4, 17, 4)
                    udpsock_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udpsock_tx.sendto(data_tx, (config["forwardto_ip"], config["forwardto_port"]))

            elif nf_hdr_info_element_id == NetflowMessageID.FlowRecord:
                nfdec_pos_size = 2
                nf_hdr_length, = struct.unpack(">H", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
                if config["forwardto_enable"]:
                    data_tx = data_tx + struct.pack(">H", nf_hdr_length + nf_hdr_count * 8)
                nfdec_pos += nfdec_pos_size

                i = 0
                while nfdec_pos != nf_hdr_length + 20:
                    i += 1

                    if config["forwardto_enable"]:
                        data_tx = data[0:nfdec_pos]

                    # Mikrotik v6.x
                    nfdec_pos_size = 45
                    nf_data = struct.unpack(">IIIIIIIIBBHHIBBB", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
                    nfdec_pos += nfdec_pos_size

                    # nfi_switch_first = nf_data[0]
                    # nfi_switch_last = nf_data[1]
                    # nfi_packets = nf_data[2]
                    # nfi_bytes = nf_data[3]
                    # nfi_in_int = nf_data[4]
                    # nfi_out_int = nf_data[5]
                    nfi_src_ip = socket.inet_ntoa(struct.pack("!L", nf_data[6]))
                    nfi_dst_ip = socket.inet_ntoa(struct.pack("!L", nf_data[7]))
                    # nfi_proto = nf_data[8]
                    # nfi_src_tos = nf_data[9]
                    # nfi_src_port = nf_data[10]
                    # nfi_dst_port = nf_data[11]
                    # nfi_next_hop = socket.inet_ntoa(struct.pack("!L", nf_data[12]))
                    # nfi_dst_mask = nf_data[13]
                    # nfi_src_mask = nf_data[14]
                    # nfi_tcp_flags = nf_data[15]

                    if config["ip2asn"]:
                        src_as = IP2ASNresolver(adns_resolver, nfi_src_ip)
                        dst_as = IP2ASNresolver(adns_resolver, nfi_dst_ip)

                    if config["forwardto_enable"]:
                        data_tx = data_tx + data[nfdec_pos - nfdec_pos_size:nfdec_pos] + struct.pack(">II", int(src_as), int(dst_as))

                if config["forwardto_enable"]:
                    udpsock_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udpsock_tx.sendto(data_tx, (config["forwardto_ip"], config["forwardto_port"]))

        else:
            if config["debug"]:
                sys.stdout.write("NFP - Unknown NetFlow packet version: " + str(nf_hdr_version) + ", src ip: " + nf_src_ip + ".\n")
                sys.stdout.flush()
            return
    except:
        pass


def GIXFlow():
    global prefix_cache

    try:
        if config["debug"]:
            sys.stdout.write("GF - Importing SQLite database to prefix cache.\n")
            sys.stdout.flush()

        sqlite_con = sqlite3.connect(config["db_file"])
        sqlite_cur = sqlite_con.cursor()
        sqlite_cur.execute("SELECT * FROM prefixes")
        for ip_prefix in sqlite_cur:
            prefix = prefix_cache.add(ip_prefix[0])
            prefix.data["asn"] = ip_prefix[1]
            prefix.data["exp"] = ip_prefix[2]
        sqlite_con.close()

    except sqlite3.Error:
        if config["debug"]:
            sys.stdout.write("GF - SQLite database does not exist. Creating a new file.\n")
            sys.stdout.flush()

        sqlite_cur.execute("CREATE TABLE prefixes (prefix text, asn integer, timestamp integer)")
        sqlite_con.close()
        pass

    statsd = Thread(target=Stats_Worker)
    statsd.daemon = True
    statsd.start()

    for i in range(config["netflow_workers"]):
        netflowd = Thread(target=NetFlow_Worker)
        netflowd.daemon = True
        netflowd.start()
        if config["debug"]:
            sys.stdout.write("GF - NetFlow worker " + str(i) + " started.\n")
            sys.stdout.flush()

    if config["listen_ipv4_enable"]:
        netrecvd = "ipv4"
        netrecvd4 = Thread(target=NetFlow_Receiver, args=(netrecvd,))
        netrecvd4.daemon = True
        netrecvd4.start()
        if config["debug"]:
            sys.stdout.write("GF - NetFlow receiver v4 started.\n")
            sys.stdout.flush()

    if config["listen_ipv6_enable"]:
        netrecvd = "ipv6"
        netrecvd6 = Thread(target=NetFlow_Receiver, args=(netrecvd,))
        netrecvd6.daemon = True
        netrecvd6.start()
        if config["debug"]:
            sys.stdout.write("GF - NetFlow receiver v6 started.\n")
            sys.stdout.flush()

    while Running:
        time.sleep(10)
        if config["debug"]:
            sys.stdout.write("GF - alive.\n")
            sys.stdout.flush()


class GIXFlowDaemon(daemon):
    def run(self):
        GIXFlow()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        if sys.argv[1] == "start":

            if not config["listen_ipv4_enable"] and not config["listen_ipv6_enable"]:
                print("You must enable the process to listen at least on one address, IPv4 or IPv6.")
                sys.exit(2)

            Running = True

            # Initialize a prefix cache.
            prefix_cache = RFCPrefixTable()

            # Initialize a queue for NetFlow workers.
            netflow_queue = Queue.Queue(maxsize=config["netflow_queue"])

            # Initialize a lock.
            lock = RLock()

            if config["debug"]:
                daemon = GIXFlowDaemon(config["pid_file"], stdout=config["log_file"], stderr=config["log_file"])
            else:
                daemon = GIXFlowDaemon(config["pid_file"])
            daemon.start()

        elif sys.argv[1] == "stop":
            Running = False

            if config["debug"]:
                daemon = GIXFlowDaemon(config["pid_file"], stdout=config["log_file"], stderr=config["log_file"])
            else:
                daemon = GIXFlowDaemon(config["pid_file"])
            daemon.stop()

        # Not yet implemented. GIXflow does not process updates received from ExaBGP process.
        elif sys.argv[1] == "exabgp":
            Running = True

            # Initialize a prefix cache.
            prefix_cache = RFCPrefixTable()

            # Initialize a queue for NetFlow workers.
            netflow_queue = Queue.Queue(maxsize=config["netflow_queue"])

            # Initialize a lock.
            lock = RLock()

            # Starting GIXflow as a foreground process.
            GIXFlow()

        else:
            print("Unknown argument")
            sys.exit(2)

        sys.exit(0)

    else:
        print("Usage: %s start|stop|exabgp" % sys.argv[0])
        sys.exit(2)
