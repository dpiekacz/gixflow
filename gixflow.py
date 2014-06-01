#!/usr/bin/env python
#
"""
gixglow.py
Created by Daniel Piekacz on 2014-01-28.
Updated on 2014-06-01.
http://gix.net.pl
"""
import os
import sys
import time
import struct
import socket

# from netaddr import IPNetwork
from daemon import daemon
from threading import Thread, RLock
import Queue

import radix
import adns
import sqlite3
import json

from gixflow_config import config
from gixflow_classes import *

#
# Main code - Do not modify the code below the line.
#
Running = False

# NetFlow sources.
netflow_sources = {}


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
    global Running, prefix_cache

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

    except KeyboardInterrupt:
        Running = False
        os._exit(1)

    except:
        asn = ASNtype.Unknown

        with lock:
            prefix = prefix_cache.add(ip_net + "/24")
            prefix.data["asn"] = asn
            prefix.data["exp"] = ts + PrefixExpire.Short

        if config["debug"]:
            e = str(sys.exc_info())
            sys.stdout.write("I2A/%s/Exception: %s.\n" % (ip_addr, e))
            sys.stdout.flush()

        pass

    return int(asn)


def Stats_Worker():
    global Running, prefix_cache

    swi = 1
    while Running:
        try:
            while Running:
                time.sleep(10)

                if swi == 12:
                    swi = 1
                    if config["debug"]:
                        sys.stdout.write("SW/Dumping prefix table to SQLite database.\n")
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
                        sys.stdout.write("SW/Nb of prefixes: %s, swi: %s.\n" % (len(prefixes), swi))
                        sys.stdout.flush()

        except KeyboardInterrupt:
            Running = False
            os._exit(1)

        except:
            if config["debug"]:
                e = str(sys.exc_info())
                sys.stdout.write("SW/Exception: %s.\n" % (e))
                sys.stdout.flush()
            pass


def NetFlow_Worker():
    global Running

    if config["ip2asn"]:
        adns_resolver = adns.init()

    while Running:
        try:
            while Running:
                nf_src_ip, data = netflow_queue.get(block=True, timeout=10)
                if config["ip2asn"]:
                    NetFlow_PacketProcessor(adns_resolver, nf_src_ip, data)

                else:
                    NetFlow_PacketProcessor(0, nf_src_ip, data)
                netflow_queue.task_done()

        except Queue.Empty:
            if config["debug"]:
                sys.stdout.write("NFW/Flow queue is empty.\n")
                sys.stdout.flush()
            pass

        except KeyboardInterrupt:
            Running = False
            os._exit(1)

        except:
            if config["debug"]:
                e = str(sys.exc_info())
                sys.stdout.write("NFW/Exception: %s.\n" % (e))
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
            sys.stdout.write("NFR/NetFlow receiver must be started with a valid argument.\n")
            sys.stdout.flush()
        Running = False
        return

    while Running:
        try:
            if netrecvd == "ipv4":
                while Running:
                    data, ipaddr = UDPSockv4.recvfrom(8192)
                    netflow_queue.put([ipaddr[0], data], block=False)

                    with lock:
                        if ipaddr[0] in netflow_sources.keys():
                            netflow_sources[ipaddr[0]]["v4_packets_received"] += 1

                        else:
                            netflow_sources[ipaddr[0]] = {}
                            netflow_sources[ipaddr[0]]["v4_packets_received"] = 1
                            netflow_sources[ipaddr[0]]["v4_packets_processed"] = 0

            else:
                while Running:
                    data, ipaddr = UDPSockv6.recvfrom(8192)
                    netflow_queue.put([ipaddr[0], data], block=False)

                    with lock:
                        if ipaddr[0] in netflow_sources.keys():
                            netflow_sources[ipaddr[0]]["v6_packets_received"] += 1

                        else:
                            netflow_sources[ipaddr[0]] = {}
                            netflow_sources[ipaddr[0]]["v6_packets_received"] = 1
                            netflow_sources[ipaddr[0]]["v6_packets_processed"] = 0

        except Queue.Full:
            if config["debug"]:
                sys.stdout.write("NFR/Flow queue is full.\n")
                sys.stdout.flush()
            pass

        except socket.error:
            Running = False
            os._exit(1)

        except KeyboardInterrupt:
            Running = False
            os._exit(1)

        except:
            if config["debug"]:
                e = str(sys.exc_info())
                sys.stdout.write("NFR/Exception: %s.\n" % (e))
                sys.stdout.flush()
            pass


def NetFlow_FlowProcessor(adns_resolver, nfd):
    global Running

    if config["ip2asn"]:
        if nfd["src_ip4"] is not None and nfd["dst_ip4"] is not None:
            if nfd["src_as"] is None or nfd["src_as"] == ASNtype.Unknown or (nfd["src_as"] >= 64512 and nfd["src_as"] <= 65534) or (nfd["src_as"] >= 4200000000 and nfd["src_as"] <= 4294967294):
                nfd["src_as"] = IP2ASNresolver(adns_resolver, nfd["src_ip4"])

            if nfd["dst_as"] is None or nfd["dst_as"] == ASNtype.Unknown or (nfd["dst_as"] >= 64512 and nfd["dst_as"] <= 65534) or (nfd["dst_as"] >= 4200000000 and nfd["dst_as"] <= 4294967294):
                nfd["dst_as"] = IP2ASNresolver(adns_resolver, nfd["dst_ip4"])

        elif nfd["src_ip6"] is not None and nfd["dst_ip6"] is not None:
            # IP2ASN DNS lookup not supported for IPv6
            if config["debug"]:
                sys.stdout.write("NFP/%s/v%s/%s/IP2ASN DNS lookup not supported for IPv6 addresses.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                sys.stdout.flush()


def NetFlow_PacketProcessor(adns_resolver, nf_src_ip, data):
    global Running

    try:
        nfd = {}
        nfd["msg_type"] = "packet"
        nfd["msg_size"] = len(data)
        nfd["msg_src_ip"] = nf_src_ip

        nfdec_pos = 0
        nfdec_size = 2
        # Bits 0..15 - Version
        nfd["version"], = struct.unpack(">H", data[nfdec_pos:nfdec_pos + nfdec_size])
        nfdec_pos += nfdec_size

        if nfd["version"] == 1:
            # Header
            # H/Bits  16...31 - Count
            # I/Bits  32...63 - System Uptime
            # I/Bits  64...95 - UNIX seconds
            # I/Bits  96..127 - UNIX nano seconds
            nfdec_size = 14
            if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                nfd["count"], nfd["sys_uptime"], nfd["unix_sec"], nfd["unix_nsec"] = struct.unpack(">HIII", data[nfdec_pos:nfdec_pos + nfdec_size])
                nfdec_pos += nfdec_size

            else:
                if config["debug"]:
                    sys.stdout.write("NFP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                    sys.stdout.flush()
                return

            # Data
            i = 0
            while i != nfd["count"]:
                nfdec_size = 48
                if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                    nfd_src_ip4, nfd_dst_ip4, nfd_nexthop_ip4, nfd["in_interface"], nfd["out_interface"], nfd["in_packets"], nfd["in_bytes"], nfd["flow_first"], nfd["flow_last"], nfd["src_port"], nfd["dst_port"], nf_pad1, nfd["proto"], nfd["src_tos"], nfd["tcp_flags"], nf_pad2, nf_pad3, nf_pad4, nf_reserved = struct.unpack(">IIIHHIIIIHHHBBBBBBI", data[nfdec_pos:nfdec_pos + nfdec_size])
                    nfdec_pos += nfdec_size
                    i += 1

                    nfd["src_ip4"] = socket.inet_ntop(socket.AF_INET, struct.pack("!L", nfd_src_ip4))
                    nfd["dst_ip4"] = socket.inet_ntop(socket.AF_INET, struct.pack("!L", nfd_dst_ip4))
                    nfd["nexthop_ip4"] = socket.inet_ntop(socket.AF_INET, struct.pack("!L", nfd_nexthop_ip4))

                else:
                    if config["debug"]:
                        sys.stdout.write("NFP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                        sys.stdout.flush()
                    return

                NetFlow_FlowProcessor(adns_resolver, nfd)

            with lock:
                if "." in nfd["msg_src_ip"]:
                    netflow_sources[nfd["msg_src_ip"]]["v4_packets_processed"] += 1
                else:
                    netflow_sources[nfd["msg_src_ip"]]["v6_packets_processed"] += 1

        elif nfd["version"] == 5:
            # Header
            # H/Bits  16...31 - Count
            # I/Bits  32...63 - System Uptime
            # I/Bits  64...95 - UNIX seconds
            # I/Bits  96..127 - UNIX nano seconds
            # I/Bits 128..159 - Sequence Number
            # B/Bits 160..167 - Engine Type
            # B/Bits 168..175 - Engine ID
            # H/Bits 176..191 - Sampling Interval
            nfdec_size = 22
            if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                nfd["count"], nfd["sys_uptime"], nfd["unix_sec"], nfd["unix_nsec"], nfd["sequence_number"], nfd["engine_type"], nfd["engine_id"], nfd["sampling_interval"] = struct.unpack(">HIIIIBBH", data[nfdec_pos:nfdec_pos + nfdec_size])
                nfdec_pos += nfdec_size

            else:
                if config["debug"]:
                    sys.stdout.write("NFP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                    sys.stdout.flush()
                return

            # Data
            i = 0
            while i != nfd["count"]:
                nfdec_size = 48
                if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                    nfd_src_ip4, nfd_dst_ip4, nfd_nexthop_ip4, nfd["in_interface"], nfd["out_interface"], nfd["in_packets"], nfd["in_bytes"], nfd["flow_first"], nfd["flow_last"], nfd["src_port"], nfd["dst_port"], nf_pad1, nfd["tcp_flags"], nfd["proto"], nfd["src_tos"], nfd["src_as"], nfd["dst_as"], nfd["src_mask4"], nfd["dst_mask4"], nf_pad2 = struct.unpack(">IIIHHIIIIHHBBBBHHBBH", data[nfdec_pos:nfdec_pos + nfdec_size])
                    nfdec_pos += nfdec_size
                    i += 1

                    nfd["src_ip4"] = socket.inet_ntop(socket.AF_INET, struct.pack("!L", nfd_src_ip4))
                    nfd["dst_ip4"] = socket.inet_ntop(socket.AF_INET, struct.pack("!L", nfd_dst_ip4))
                    nfd["nexthop_ip4"] = socket.inet_ntop(socket.AF_INET, struct.pack("!L", nfd_nexthop_ip4))

                else:
                    if config["debug"]:
                        sys.stdout.write("NFP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                        sys.stdout.flush()
                    return

                NetFlow_FlowProcessor(adns_resolver, nfd)

            with lock:
                if "." in nfd["msg_src_ip"]:
                    netflow_sources[nfd["msg_src_ip"]]["v4_packets_processed"] += 1
                else:
                    netflow_sources[nfd["msg_src_ip"]]["v6_packets_processed"] += 1

        if (nfd["version"] == 9 or nfd["version"] == 10):
            # NetFlow v9 - Header
            if nfd["version"] == 9:
                # H/Bits  16...31 - Count
                # I/Bits  32...63 - System Uptime
                # I/Bits  64...95 - UNIX seconds
                # I/Bits  96..127 - Sequence Number
                # I/Bits 128..159 - Source ID
                # H/Bits 160..175 - Element ID
                # H/Bits 176..191 - Field Length
                nfdec_size = 22
                if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                    nfd["count"], nfd["sys_uptime"], nfd["unix_sec"], nfd["sequence_number"], nfd["source_id"], nfd["field_info_element_id"], nfd["field_length"] = struct.unpack(">HIIIIHH", data[nfdec_pos:nfdec_pos + nfdec_size])
                    nfdec_pos += nfdec_size

                else:
                    if config["debug"]:
                        sys.stdout.write("NFP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                        sys.stdout.flush()
                    return

            # NetFlow v10 - Header
            elif nfd["version"] == 10:
                # H/Bits  16...31 - Message Length
                # I/Bits  32...63 - Export Timestamp
                # I/Bits  64...95 - Sequence Number
                # I/Bits  96..127 - Observation Domain ID
                # H/Bits 128..143 - Element ID
                # H/Bits 144..159 - Field Length
                nfdec_size = 18
                if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                    nfd["length"], nfd["export_time"], nfd["sequence_number"], nfd["domain_id"], nfd["field_info_element_id"], nfd["field_length"] = struct.unpack(">HIIIHH", data[nfdec_pos:nfdec_pos + nfdec_size])
                    nfdec_pos += nfdec_size

                else:
                    if config["debug"]:
                        sys.stdout.write("NFP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                        sys.stdout.flush()
                    return

                # Bits 160..191 - Enterprise Number (when 1st bit in Element ID is set)
                if nfd["field_info_element_id"] & NetflowMessageID.Enterprise == NetflowMessageID.Enterprise:
                    nfdec_size = 4
                    if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                        nfd["enterprise_number"], = struct.unpack(">I", data[nfdec_pos:nfdec_pos + nfdec_size])
                        nfdec_pos += nfdec_size

                    else:
                        if config["debug"]:
                            sys.stdout.write("NFP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                            sys.stdout.flush()
                        return

            # NetFlow v10 (IPFIX) & v9 - Templates
            if (nfd["field_info_element_id"] == NetflowMessageID.Template or nfd["field_info_element_id"] == NetflowMessageID.TemplateV9):

                nfd["msg_type"] = "template"
                if nfd["version"] == 9:
                    nf_template_size = 20 + nfd["field_length"]
                elif nfd["version"] == 10:
                    nf_template_size = 16 + nfd["field_length"]

                # while nfdec_pos != nfd["msg_size"]:
                while nfdec_pos != nf_template_size:
                    nfdec_size = 4
                    if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                        nfd["template_id"], nfd["template_field_count"] = struct.unpack(">HH", data[nfdec_pos:nfdec_pos + nfdec_size])
                        nfdec_pos += nfdec_size

                    else:
                        if config["debug"]:
                            sys.stdout.write("NFP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                            sys.stdout.flush()
                        return

                    nfdec_size = nfd["template_field_count"] * 4
                    if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                        nfd_template = struct.unpack(">" + "H" * (nfdec_size / 2), data[nfdec_pos:nfdec_pos + nfdec_size])
                        nfdec_pos += nfdec_size

                    else:
                        if config["debug"]:
                            sys.stdout.write("NFP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                            sys.stdout.flush()
                        return

                    if (nfd["version"] == 10) and (nfd["field_info_element_id"] & NetflowMessageID.Enterprise == NetflowMessageID.Enterprise):
                        nfdec_size = 4
                        if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                            nfd["field_enterprise_number"], = struct.unpack(">I", data[nfdec_pos:nfdec_pos + nfdec_size])
                            nfdec_pos += nfdec_size

                        else:
                            if config["debug"]:
                                sys.stdout.write("NFP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                                sys.stdout.flush()
                            return

                    i = 0
                    j = 0
                    nfd_template_unpack = ">"
                    nfd_template_struct = {}
                    nfd_template_size = 0
                    while i != nfd["template_field_count"]:
                        if nfd_template[(2*i)+1] == 1:
                            nfd_template_struct[nfd_template[(2*i)]] = (j, 1, 1)
                            j += 1
                            nfd_template_unpack = nfd_template_unpack + "B"
                            nfd_template_size += 1

                        elif nfd_template[(2*i)+1] == 2:
                            nfd_template_struct[nfd_template[(2*i)]] = (j, 1, 2)
                            j += 1
                            nfd_template_unpack = nfd_template_unpack + "H"
                            nfd_template_size += 2

                        elif nfd_template[(2*i)+1] == 3:
                            nfd_template_struct[nfd_template[(2*i)]] = (j, 3, 3)
                            j += 3
                            nfd_template_unpack = nfd_template_unpack + "BBB"
                            nfd_template_size += 3

                        elif nfd_template[(2*i)+1] == 4:
                            nfd_template_struct[nfd_template[(2*i)]] = (j, 1, 4)
                            j += 1
                            nfd_template_unpack = nfd_template_unpack + "I"
                            nfd_template_size += 4

                        elif nfd_template[(2*i)+1] == 6:
                            nfd_template_struct[nfd_template[(2*i)]] = (j, 3, 6)
                            j += 3
                            nfd_template_unpack = nfd_template_unpack + "HHH"
                            nfd_template_size += 6

                        elif nfd_template[(2*i)+1] == 8:
                            nfd_template_struct[nfd_template[(2*i)]] = (j, 1, 8)
                            j += 1
                            nfd_template_unpack = nfd_template_unpack + "Q"
                            nfd_template_size += 8

                        elif nfd_template[(2*i)+1] == 16:
                            nfd_template_struct[nfd_template[(2*i)]] = (j, 2, 16)
                            j += 2
                            nfd_template_unpack = nfd_template_unpack + "QQ"
                            nfd_template_size += 16

                        else:
                            if config["debug"]:
                                sys.stdout.write("NFP/%s/v%s/%s/%s/Not valid field size: %s,%s,%s.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["template_id"], nfd["msg_type"], i, nfd_template[(2*i)], nfd_template[(2*i)+1]))
                                sys.stdout.flush()
                            return
                        i += 1

                    with lock:
                        if "template" in netflow_sources[nfd["msg_src_ip"]].keys():
                            netflow_sources[nfd["msg_src_ip"]]["template"][nfd["template_id"]] = (nfd["version"], nfd_template_size, nfd_template, nfd_template_unpack, nfd_template_struct)

                        else:
                            netflow_sources[nfd["msg_src_ip"]]["template"] = {}
                            netflow_sources[nfd["msg_src_ip"]]["template"][nfd["template_id"]] = (nfd["version"], nfd_template_size, nfd_template, nfd_template_unpack, nfd_template_struct)

                    if config["debug"]:
                        sys.stdout.write("NFP/%s/v%s/%s/%s/Processed.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["template_id"], nfd["msg_type"]))

            elif nfd["field_info_element_id"] == NetflowMessageID.Template_Optional:
                nfd["msg_type"] = "optional"
                # Not yet implemented.
                if config["debug"]:
                    sys.stdout.write("NFP/%s/v%s/%s/%s/Not yet supported.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["field_info_element_id"], nfd["msg_type"]))
                    sys.stdout.flush()
                return

            elif nfd["field_info_element_id"] == NetflowMessageID.TemplateV9_Optional:
                nfd["msg_type"] = "optional"
                # Not yet implemented.
                if config["debug"]:
                    sys.stdout.write("NFP/%s/v%s/%s/%s/Not yet supported.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["field_info_element_id"], nfd["msg_type"]))
                    sys.stdout.flush()
                return

            elif nfd["field_info_element_id"] >= NetflowMessageID.FlowRecord:
                nfd["msg_type"] = "data"
                if "template" in netflow_sources[nfd["msg_src_ip"]].keys():
                    if nfd["field_info_element_id"] in netflow_sources[nfd["msg_src_ip"]]["template"].keys():
                        if nfd["version"] == netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Version]:

                            # Calculate padding.
                            nf_data_padding = ((nfd["msg_size"] - nfdec_pos) % (netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Size])) % 4

                            while nfdec_pos != nfd["msg_size"] - nf_data_padding:
                                nfdec_size = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Size]
                                if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                                    nf_data = struct.unpack(netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Unpack], data[nfdec_pos:nfdec_pos + nfdec_size])
                                    nfdec_pos += nfdec_size
                                else:
                                    if config["debug"]:
                                        sys.stdout.write("NFP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                                        sys.stdout.flush()
                                    return

                                if NetFlowDataTypes.IPv4_Src_Addr in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.IPv4_Src_Addr][0]
                                    nfd["src_ip4"] = socket.inet_ntop(socket.AF_INET, struct.pack("!L", nf_data[nf_data_loc]))
                                else:
                                    nfd["src_ip4"] = None

                                if NetFlowDataTypes.IPv4_Dst_Addr in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.IPv4_Dst_Addr][0]
                                    nfd["dst_ip4"] = socket.inet_ntop(socket.AF_INET, struct.pack("!L", nf_data[nf_data_loc]))
                                else:
                                    nfd["dst_ip4"] = None

                                if NetFlowDataTypes.IPv4_Next_Hop in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.IPv4_Next_Hop][0]
                                    nfd["nexthop_ip4"] = socket.inet_ntop(socket.AF_INET, struct.pack("!L", nf_data[nf_data_loc]))
                                else:
                                    nfd["nexthop_ip4"] = None

                                if NetFlowDataTypes.IPv6_Src_Addr in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.IPv6_Src_Addr][0]
                                    nfd["src_ip6"] = socket.inet_ntop(socket.AF_INET6, struct.pack("!2Q", nf_data[nf_data_loc], nf_data[nf_data_loc + 1]))
                                else:
                                    nfd["src_ip6"] = None

                                if NetFlowDataTypes.IPv6_Dst_Addr in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.IPv6_Dst_Addr][0]
                                    nfd["dst_ip6"] = socket.inet_ntop(socket.AF_INET6, struct.pack("!2Q", nf_data[nf_data_loc], nf_data[nf_data_loc + 1]))
                                else:
                                    nfd["dst_ip6"] = None

                                if NetFlowDataTypes.IPv6_Next_Hop in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.IPv6_Next_Hop][0]
                                    nfd["nexthop_ip6"] = socket.inet_ntop(socket.AF_INET6, struct.pack("!2Q", nf_data[nf_data_loc], nf_data[nf_data_loc + 1]))
                                else:
                                    nfd["nexthop_ip6"] = None

                                if NetFlowDataTypes.Src_AS in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.Src_AS][0]
                                    nfd["src_as"] = nf_data[nf_data_loc]
                                else:
                                    nfd["src_as"] = None

                                if NetFlowDataTypes.Dst_AS in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.Dst_AS][0]
                                    nfd["dst_as"] = nf_data[nf_data_loc]
                                else:
                                    nfd["dst_as"] = None

                                if NetFlowDataTypes.Input_SNMP in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.Input_SNMP][0]
                                    nfd["in_interface"] = nf_data[nf_data_loc]
                                else:
                                    nfd["in_interface"] = 0

                                if NetFlowDataTypes.Output_SNMP in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.Output_SNMP][0]
                                    nfd["out_interface"] = nf_data[nf_data_loc]
                                else:
                                    nfd["out_interface"] = 0

                                if NetFlowDataTypes.In_Bytes in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.In_Bytes][0]
                                    nfd["in_bytes"] = nf_data[nf_data_loc]
                                else:
                                    nfd["in_bytes"] = 0

                                if NetFlowDataTypes.Out_Bytes in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.Out_Bytes][0]
                                    nfd["out_bytes"] = nf_data[nf_data_loc]
                                else:
                                    nfd["out_bytes"] = 0

                                if NetFlowDataTypes.In_Packets in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.In_Packets][0]
                                    nfd["in_packets"] = nf_data[nf_data_loc]
                                else:
                                    nfd["in_packets"] = 0

                                if NetFlowDataTypes.Out_Packets in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.Out_Packets][0]
                                    nfd["out_packets"] = nf_data[nf_data_loc]
                                else:
                                    nfd["out_packets"] = 0

                                if NetFlowDataTypes.First_Switched in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.First_Switched][0]
                                    nfd["flow_first"] = nf_data[nf_data_loc]
                                else:
                                    nfd["flow_first"] = 0

                                if NetFlowDataTypes.Last_Switched in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.Last_Switched][0]
                                    nfd["flow_last"] = nf_data[nf_data_loc]
                                else:
                                    nfd["flow_last"] = 0

                                if NetFlowDataTypes.L4_Src_Port in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.L4_Src_Port][0]
                                    nfd["src_port"] = nf_data[nf_data_loc]
                                else:
                                    nfd["src_port"] = None

                                if NetFlowDataTypes.L4_Dst_Port in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.L4_Dst_Port][0]
                                    nfd["dst_port"] = nf_data[nf_data_loc]
                                else:
                                    nfd["dst_port"] = None

                                if NetFlowDataTypes.TCP_Flags in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.TCP_Flags][0]
                                    nfd["tcp_flags"] = nf_data[nf_data_loc]
                                else:
                                    nfd["tcp_flags"] = None

                                if NetFlowDataTypes.Protocol in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.Protocol][0]
                                    nfd["proto"] = nf_data[nf_data_loc]
                                else:
                                    nfd["proto"] = None

                                if NetFlowDataTypes.Src_TOS in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.Src_TOS][0]
                                    nfd["src_tos"] = nf_data[nf_data_loc]
                                else:
                                    nfd["src_tos"] = None

                                if NetFlowDataTypes.Dst_TOS in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.Dst_TOS][0]
                                    nfd["dst_tos"] = nf_data[nf_data_loc]
                                else:
                                    nfd["dst_tos"] = None

                                if NetFlowDataTypes.Src_Mask in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.Src_Mask][0]
                                    nfd["src_mask4"] = nf_data[nf_data_loc]
                                else:
                                    nfd["src_mask4"] = None

                                if NetFlowDataTypes.Dst_Mask in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.Dst_Mask][0]
                                    nfd["dst_mask4"] = nf_data[nf_data_loc]
                                else:
                                    nfd["dst_mask4"] = None

                                if NetFlowDataTypes.IPv6_Src_Mask in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.IPv6_Src_Mask][0]
                                    nfd["src_mask6"] = nf_data[nf_data_loc]
                                else:
                                    nfd["src_mask6"] = None

                                if NetFlowDataTypes.IPv6_Dst_Mask in netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct]:
                                    nf_data_loc = netflow_sources[nfd["msg_src_ip"]]["template"][nfd["field_info_element_id"]][NetFlowTemplates.Struct][NetFlowDataTypes.IPv6_Dst_Mask][0]
                                    nfd["dst_mask6"] = nf_data[nf_data_loc]
                                else:
                                    nfd["dst_mask6"] = None

                                NetFlow_FlowProcessor(adns_resolver, nfd)

                        else:
                            if config["debug"]:
                                sys.stdout.write("NFP/%s/v%s/%s/%s/Version does not match with the known template.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["field_info_element_id"], nfd["msg_type"]))
                                sys.stdout.flush()
                            return

                    else:
                        if config["debug"]:
                            sys.stdout.write("NFP/%s/v%s/%s/%s/Unknown template ID.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["field_info_element_id"], nfd["msg_type"]))
                            sys.stdout.flush()
                        return

                else:
                    # if config["debug"]:
                    #    sys.stdout.write("NFP/%s/v%s/%s/%s/No templates received from the source.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["field_info_element_id"], nfd["msg_type"]))
                    #    sys.stdout.flush()
                    return

            else:
                if config["debug"]:
                    sys.stdout.write("NFP/%s/v%s/%s/%s/Unknown message type.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["field_info_element_id"], nfd["msg_type"]))
                    sys.stdout.flush()
                return

            with lock:
                if "." in nfd["msg_src_ip"]:
                    netflow_sources[nfd["msg_src_ip"]]["v4_packets_processed"] += 1
                else:
                    netflow_sources[nfd["msg_src_ip"]]["v6_packets_processed"] += 1

        else:
            if config["debug"]:
                sys.stdout.write("NFP/%s/v%s/%s/Unsupported version.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                sys.stdout.flush()
            return

    except KeyboardInterrupt:
        Running = False
        os._exit(1)

    except:
        if config["debug"]:
            e = str(sys.exc_info())
            if (nfd["version"] == 9 or nfd["version"] == 10):
                sys.stdout.write("NFP/%s/v%s/%s/%s/Exception: %s.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["field_info_element_id"], nfd["msg_type"], e))
            else:
                sys.stdout.write("NFP/%s/v%s/%s/Exception: %s.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"], e))
            sys.stdout.flush()
        Running = False
        os._exit(1)


def GIXFlow():
    global Running, prefix_cache

    try:
        if config["debug"]:
            sys.stdout.write("GF/Importing SQLite database to prefix cache.\n")
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
            sys.stdout.write("GF/SQLite database does not exist. Creating a new file.\n")
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
            sys.stdout.write("GF/NetFlow worker %s started.\n" % (i))
            sys.stdout.flush()

    if config["listen_ipv4_enable"]:
        netrecvd = "ipv4"
        netrecvd4 = Thread(target=NetFlow_Receiver, args=(netrecvd,))
        netrecvd4.daemon = True
        netrecvd4.start()
        if config["debug"]:
            sys.stdout.write("GF/NetFlow receiver v4 started.\n")
            sys.stdout.flush()

    if config["listen_ipv6_enable"]:
        netrecvd = "ipv6"
        netrecvd6 = Thread(target=NetFlow_Receiver, args=(netrecvd,))
        netrecvd6.daemon = True
        netrecvd6.start()
        if config["debug"]:
            sys.stdout.write("GF/NetFlow receiver v6 started.\n")
            sys.stdout.flush()

    while Running:
        try:
            while Running:
                time.sleep(10)
                if config["debug"]:
                    sys.stdout.write("GF/alive.\n")
                    sys.stdout.flush()

        except KeyboardInterrupt:
            Running = False
            os._exit(1)

        except socket.error:
            Running = False
            os._exit(1)

        except:
            if config["debug"]:
                e = str(sys.exc_info())
                sys.stdout.write("GF/Exception: %s.\n" % (e))
                sys.stdout.flush()
            pass


class GIXFlowDaemon(daemon):
    def run(self):
        GIXFlow()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        if sys.argv[1] == "start":

            if not config["listen_ipv4_enable"] and not config["listen_ipv6_enable"]:
                print("You must enable the process to listen on at least one IP address, IPv4 or IPv6.")
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
            print("Unknown argument. Usage: %s start|stop|exabgp" % sys.argv[0])
            sys.exit(2)

        sys.exit(0)

    else:
        print("Usage: %s start|stop|exabgp" % sys.argv[0])
        sys.exit(2)
