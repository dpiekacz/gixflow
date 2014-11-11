#!/usr/bin/env python
#
"""
gixglow.py
Created by Daniel Piekacz on 2014-01-28.
Updated on 2014-11-11.
https://gixtools.net
"""
import os
import sys
import time
import struct
import socket

from netaddr import IPNetwork
from daemon import daemon
import threading
import Queue

import radix
import adns
import sqlite3
import json

import tornado.httpserver
import tornado.ioloop
import tornado.web
from tornado.log import enable_pretty_logging

from gixflow_config import config
from gixflow_stats import netflow_sources
from gixflow_classes import *

#
# Main code - Do not modify the code below the line.
#
Running = False


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

    return prefix_cache


def IP2ASN_dns(adns_resolver, ip_ver, ip_addr, ip2asn_mode):
    global Running, prefix_cache, netflow_sources

    try:
        if ip2asn_mode == "cymru":
            if ip_ver == 4:
                ip2asn_domain = ".origin.asn.cymru.com"

            else:
                ip2asn_domain = ".origin6.asn.cymru.com"

        elif ip2asn_mode == "routeviews":
            if ip_ver == 4:
                ip2asn_domain = ".asn.routeviews.org"

            else:
                # IPv6 addresses mapping is not supported by Route Views
                # ip2asn_domain = ""
                asn = ASNtype.Unknown
                return asn

        else:
            asn = ASNtype.Unknown
            return asn

        if ip_ver == 4:
            ip_tmp = IPNetwork(ip_addr + "/" + IP2ASN_def_mask.IPv4).network
            ip_net = str(ip_tmp)
            ip_rev = ip_tmp.reverse_dns[0:-14]

        else:
            ip_tmp = IPNetwork(ip_addr + "/" + IP2ASN_def_mask.IPv6).network
            ip_net = str(ip_tmp)
            ip_rev = ip_tmp.reverse_dns[0:-10]

        ts = int(time.time())
        rnode = prefix_cache.search_best(ip_addr)
        if rnode is None:
            qa = None
            qac = 0

            if ip2asn_mode == "cymru":
                while ((qa is None or qa[3] == ()) and qac <= 1):
                    with lock:
                        netflow_sources["dns_queries"] += 1
                    qa = adns_resolver.synchronous(ip_rev + ip2asn_domain, adns.rr.TXT)
                    qac += 1

            elif ip2asn_mode == "routeviews":
                while ((qa is None or qa[3] == ()) and qac <= 1):
                    with lock:
                        netflow_sources["dns_queries"] += 1
                    qa = adns_resolver.synchronous(ip_rev + ip2asn_domain, adns.rr.TXT)
                    qac += 1

            if ip2asn_mode == "cymru" and qa is not None and qa[3] != ():
                for i in range(0, len(qa[3])):
                    asn = int(qa[3][i][0].split("|")[0].split(" ")[0])
                    ip_prefix = qa[3][i][0].split("|")[1].split(" ")[1]

                    with lock:
                        prefix = prefix_cache.add(ip_prefix)
                        prefix.data["asn"] = asn
                        prefix.data["exp"] = ts + PrefixExpire.Default
                        netflow_sources["stats_prefix_cache"] += 1

                asn = int(prefix_cache.search_best(ip_addr).data["asn"])

            elif ip2asn_mode == "routeviews" and qa is not None and qa[3] != ():
                asn = int(qa[3][0][0])
                ip_prefix = qa[3][0][1] + "/" + qa[3][0][2]

                if ip_prefix != "0.0.0.0/0" and ip_prefix != "0/0":
                    with lock:
                        prefix = prefix_cache.add(ip_prefix)
                        prefix.data["asn"] = asn
                        prefix.data["exp"] = ts + PrefixExpire.Default
                        netflow_sources["stats_prefix_cache"] += 1

                else:
                    asn = ASNtype.Unknown
                    with lock:
                        prefix = prefix_cache.add(ip_net + "/" + IP2ASN_def_mask.IPv4)
                        prefix.data["asn"] = asn
                        prefix.data["exp"] = ts + PrefixExpire.Short
                        netflow_sources["stats_prefix_cache"] += 1

            else:
                asn = ASNtype.Unknown

                with lock:
                    if ip_ver == 4:
                        prefix = prefix_cache.add(ip_net + "/" + IP2ASN_def_mask.IPv4)

                    else:
                        prefix = prefix_cache.add(ip_net + "/" + IP2ASN_def_mask.IPv6)
                    prefix.data["asn"] = asn
                    prefix.data["exp"] = ts + PrefixExpire.Short
                    netflow_sources["stats_prefix_cache"] += 1

        else:
            if rnode.data["exp"] == 0 or rnode.data["exp"] >= ts:
                asn = int(rnode.data["asn"])

            else:
                with lock:
                    prefix_cache.delete(rnode.prefix)
                    netflow_sources["stats_prefix_cache"] -= 1
                asn = IP2ASN_dns(adns_resolver, ip_ver, ip_addr, ip2asn_mode)

    except KeyboardInterrupt:
        Running = False
        os._exit(1)

    except AttributeError:
        if config["debug"]:
            sys.stdout.write("I2A/%s/Exception: %s.\n" % (ip_addr, qa))
            sys.stdout.flush()

        asn = ASNtype.Unknown
        return asn

    except:
        if config["debug"]:
            e = str(sys.exc_info())
            sys.stdout.write("I2A/%s/Exception: %s, %s.\n" % (ip_addr, e, qa))
            sys.stdout.flush()

        asn = ASNtype.Unknown
        return asn

    return asn


def IP2ASN_geodb(ip_ver, ip_addr):
    global Running, prefix_cache

    rnode = prefix_cache.search_best(ip_addr)
    if rnode is None:
        asn = ASNtype.Unknown
    else:
        asn = int(rnode.data["asn"])

    return asn


class HTTP_Stats_Main(tornado.web.RequestHandler):
    def get(self):
        f_handler = open(config["http_file_stats"], "r")
        f_content = f_handler.read()
        f_handler.close()
        self.write(f_content)


class HTTP_Stats_Packets(tornado.web.RequestHandler):
    def get(self):
        timestamp = int(time.time()) * 1000
        value1 = netflow_sources["stats_packets_received"]
        value2 = netflow_sources["stats_packets_processed"]
        self.write("[%s,%s,%s]" % (timestamp, value1, value2))


class HTTP_Stats_Flows(tornado.web.RequestHandler):
    def get(self):
        timestamp = int(time.time()) * 1000
        value1 = netflow_sources["stats_flows_received"]
        value2 = netflow_sources["stats_flows_processed"]
        self.write("[%s,%s,%s]" % (timestamp, value1, value2))


class HTTP_Stats_Prefixes(tornado.web.RequestHandler):
    def get(self):
        timestamp = int(time.time()) * 1000
        value = netflow_sources["stats_prefix_cache"]
        self.write("[%s,%s]" % (timestamp, value))


class HTTP_Stats_Queue(tornado.web.RequestHandler):
    def get(self):
        timestamp = int(time.time()) * 1000
        value = netflow_sources["stats_queue"]
        self.write("[%s,%s]" % (timestamp, value))


class HTTP_Stats_DNSq(tornado.web.RequestHandler):
    def get(self):
        timestamp = int(time.time()) * 1000
        value = netflow_sources["stats_dns_queries"]
        self.write("[%s,%s]" % (timestamp, value))


class HTTP_Stats_Proto_Bytes(tornado.web.RequestHandler):
    def get(self):
        timestamp = int(time.time()) * 1000
        value1 = netflow_sources["stats_proto_tcp_bytes"]
        value2 = netflow_sources["stats_proto_udp_bytes"]
        value3 = netflow_sources["stats_proto_icmp_bytes"]
        value4 = netflow_sources["stats_proto_ipv6_bytes"]
        value5 = netflow_sources["stats_proto_other_bytes"]
        self.write("[%s,%s,%s,%s,%s,%s]" % (timestamp, value1, value2, value3, value4, value5))


class HTTP_Stats_Proto_Packets(tornado.web.RequestHandler):
    def get(self):
        timestamp = int(time.time()) * 1000
        value1 = netflow_sources["stats_proto_tcp_packets"]
        value2 = netflow_sources["stats_proto_udp_packets"]
        value3 = netflow_sources["stats_proto_icmp_packets"]
        value4 = netflow_sources["stats_proto_ipv6_packets"]
        value5 = netflow_sources["stats_proto_other_packets"]
        self.write("[%s,%s,%s,%s,%s,%s]" % (timestamp, value1, value2, value3, value4, value5))


def HTTP_Worker():
    global Running, prefix_cache

    enable_pretty_logging()

    httpd_app = tornado.web.Application([
        (r"/", HTTP_Stats_Main),
        (r"/stats-packets/", HTTP_Stats_Packets),
        (r"/stats-flows/", HTTP_Stats_Flows),
        (r"/stats-prefixes/", HTTP_Stats_Prefixes),
        (r"/stats-queue/", HTTP_Stats_Queue),
        (r"/stats-dnsq/", HTTP_Stats_DNSq),
        (r"/stats-proto-bytes/", HTTP_Stats_Proto_Bytes),
        (r"/stats-proto-packets/", HTTP_Stats_Proto_Packets),
    ])

    if config["http_ssl_enable"]:
        httpd_srv = tornado.httpserver.HTTPServer(httpd_app, ssl_options={
            "certfile": config["http_ssl_cert"],
            "keyfile": config["http_ssl_key"],
        })
    else:
        httpd_srv = tornado.httpserver.HTTPServer(httpd_app)

    if config["http_ipv4_enable"]:
        httpd_srv.listen(config["http_port"], address=config["http_ipv4"])
    if config["http_ipv6_enable"]:
        httpd_srv.listen(config["http_port"], address=config["http_ipv6"])
    tornado.ioloop.IOLoop.instance().start()


def Stats_Worker():
    global Running, prefix_cache, netflow_sources

    swi = 1
    while Running:
        try:
            while Running:
                time.sleep(1)

                if swi == 1200:
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

                    with lock:
                        netflow_sources["stats_packets_received"] = netflow_sources["v4_packets_received"] + netflow_sources["v6_packets_received"]
                        netflow_sources["stats_packets_processed"] = netflow_sources["v4_packets_processed"] + netflow_sources["v6_packets_processed"]
                        netflow_sources["stats_flows_received"] = netflow_sources["flows_received"]
                        netflow_sources["stats_flows_processed"] = netflow_sources["flows_processed"]
                        netflow_sources["stats_queue"] = netflow_queue.qsize()
                        netflow_sources["stats_dns_queries"] = netflow_sources["dns_queries"]
                        netflow_sources["v4_packets_received"] = 0
                        netflow_sources["v6_packets_received"] = 0
                        netflow_sources["v4_packets_processed"] = 0
                        netflow_sources["v6_packets_processed"] = 0
                        netflow_sources["flows_received"] = 0
                        netflow_sources["flows_processed"] = 0
                        netflow_sources["dns_queries"] = 0

                        if swi % 5 == 0:
                            netflow_sources["stats_proto_tcp_bytes"] = netflow_sources["proto_tcp_bytes"]
                            netflow_sources["stats_proto_tcp_packets"] = netflow_sources["proto_tcp_packets"]
                            netflow_sources["stats_proto_udp_bytes"] = netflow_sources["proto_udp_bytes"]
                            netflow_sources["stats_proto_udp_packets"] = netflow_sources["proto_udp_packets"]
                            netflow_sources["stats_proto_icmp_bytes"] = netflow_sources["proto_icmp_bytes"]
                            netflow_sources["stats_proto_icmp_packets"] = netflow_sources["proto_icmp_packets"]
                            netflow_sources["stats_proto_ipv6_bytes"] = netflow_sources["proto_ipv6_bytes"]
                            netflow_sources["stats_proto_ipv6_packets"] = netflow_sources["proto_ipv6_packets"]
                            netflow_sources["stats_proto_other_bytes"] = netflow_sources["proto_other_bytes"]
                            netflow_sources["stats_proto_other_packets"] = netflow_sources["proto_other_packets"]
                            netflow_sources["proto_tcp_bytes"] = 0
                            netflow_sources["proto_tcp_packets"] = 0
                            netflow_sources["proto_udp_bytes"] = 0
                            netflow_sources["proto_udp_packets"] = 0
                            netflow_sources["proto_icmp_bytes"] = 0
                            netflow_sources["proto_icmp_packets"] = 0
                            netflow_sources["proto_ipv6_bytes"] = 0
                            netflow_sources["proto_ipv6_packets"] = 0
                            netflow_sources["proto_other_bytes"] = 0
                            netflow_sources["proto_other_packets"] = 0

                    if config["debug"]:
                        prefixes = netflow_sources["stats_prefix_cache"]
                        sys.stdout.write("SW/Nb of prefixes: %s, swi: %s.\n" % (prefixes, swi))
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

    if config["ip2asn_enable"] and (config["ip2asn_mode"] == "cymru" or config["ip2asn_mode"] == "routeviews"):
        adns_resolver = adns.init()

    while Running:
        try:
            while Running:
                nf_src_ip, data = netflow_queue.get(block=True, timeout=10)
                if config["ip2asn_enable"] and (config["ip2asn_mode"] == "cymru" or config["ip2asn_mode"] == "routeviews"):
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
        flow_ipv4 = (config["flow_ipv4"], config["flow_port"])
        UDPSockv4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        UDPSockv4.bind(flow_ipv4)

    elif netrecvd == "ipv6":
        flow_ipv6 = (config["flow_ipv6"], config["flow_port"])
        UDPSockv6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        UDPSockv6.bind(flow_ipv6)

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
                        netflow_sources["v4_packets_received"] += 1
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
                        netflow_sources["v6_packets_received"] += 1
                        if ipaddr[0] in netflow_sources.keys():
                            netflow_sources[ipaddr[0]]["v6_packets_received"] += 1

                        else:
                            netflow_sources[ipaddr[0]] = {}
                            netflow_sources[ipaddr[0]]["v6_packets_received"] = 1
                            netflow_sources[ipaddr[0]]["v6_packets_processed"] = 0

        except Queue.Full:
            if netrecvd == "ipv4":
                with lock:
                    netflow_sources["v4_packets_received"] += 1
                    if ipaddr[0] in netflow_sources.keys():
                        netflow_sources[ipaddr[0]]["v4_packets_received"] += 1

                    else:
                        netflow_sources[ipaddr[0]] = {}
                        netflow_sources[ipaddr[0]]["v4_packets_received"] = 1
                        netflow_sources[ipaddr[0]]["v4_packets_processed"] = 0

            else:
                with lock:
                    netflow_sources["v6_packets_received"] += 1
                    if ipaddr[0] in netflow_sources.keys():
                        netflow_sources[ipaddr[0]]["v6_packets_received"] += 1

                    else:
                        netflow_sources[ipaddr[0]] = {}
                        netflow_sources[ipaddr[0]]["v6_packets_received"] = 1
                        netflow_sources[ipaddr[0]]["v6_packets_processed"] = 0

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
    global Running, netflow_sources

    if config["ip2asn_enable"]:
        if nfd["src_ip4"] is not None and nfd["dst_ip4"] is not None:
            if nfd["src_as"] is None or nfd["src_as"] == ASNtype.Unknown or (nfd["src_as"] >= 64512 and nfd["src_as"] <= 65534) or (nfd["src_as"] >= 4200000000 and nfd["src_as"] <= 4294967294):
                if config["ip2asn_mode"] == "cymru" or config["ip2asn_mode"] == "routeviews":
                    nfd["src_as"] = IP2ASN_dns(adns_resolver, 4, nfd["src_ip4"], config["ip2asn_mode"])
                elif config["ip2asn_mode"] == "maxmind":
                    nfd["src_as"] = IP2ASN_geodb(4, nfd["src_ip4"])

            if nfd["dst_as"] is None or nfd["dst_as"] == ASNtype.Unknown or (nfd["dst_as"] >= 64512 and nfd["dst_as"] <= 65534) or (nfd["dst_as"] >= 4200000000 and nfd["dst_as"] <= 4294967294):
                if config["ip2asn_mode"] == "cymru" or config["ip2asn_mode"] == "routeviews":
                    nfd["dst_as"] = IP2ASN_dns(adns_resolver, 4, nfd["dst_ip4"], config["ip2asn_mode"])
                elif config["ip2asn_mode"] == "maxmind":
                    nfd["dst_as"] = IP2ASN_geodb(4, nfd["dst_ip4"])

        elif nfd["src_ip6"] is not None and nfd["dst_ip6"] is not None:
            if nfd["src_as"] is None or nfd["src_as"] == ASNtype.Unknown or (nfd["src_as"] >= 64512 and nfd["src_as"] <= 65534) or (nfd["src_as"] >= 4200000000 and nfd["src_as"] <= 4294967294):
                if config["ip2asn_mode"] == "cymru" or config["ip2asn_mode"] == "routeviews":
                    nfd["src_as"] = IP2ASN_dns(adns_resolver, 6, nfd["src_ip6"], config["ip2asn_mode"])
                elif config["ip2asn_mode"] == "maxmind":
                    nfd["src_as"] = IP2ASN_geodb(6, nfd["src_ip6"])

            if nfd["dst_as"] is None or nfd["dst_as"] == ASNtype.Unknown or (nfd["dst_as"] >= 64512 and nfd["dst_as"] <= 65534) or (nfd["dst_as"] >= 4200000000 and nfd["dst_as"] <= 4294967294):
                if config["ip2asn_mode"] == "cymru" or config["ip2asn_mode"] == "routeviews":
                    nfd["dst_as"] = IP2ASN_dns(adns_resolver, 6, nfd["dst_ip6"], config["ip2asn_mode"])
                elif config["ip2asn_mode"] == "maxmind":
                    nfd["dst_as"] = IP2ASN_geodb(6, nfd["dst_ip6"])

    # if config["debug"]:
    #    if nfd["in_packets"] > 10000 or nfd["out_packets"] > 10000:
    #        if nfd["src_ip4"] is not None and nfd["dst_ip4"] is not None:
    #            sys.stdout.write("NFP/%s/%s/%s/%s/%s/%s/%s/%s.\n" % (nfd["msg_src_ip"], nfd["src_ip4"], nfd["dst_ip4"], nfd["proto"], nfd["in_bytes"], nfd["in_packets"], nfd["out_bytes"], nfd["out_packets"]))
    #        else:
    #            sys.stdout.write("NFP/%s/%s/%s/%s/%s/%s/%s/%s.\n" % (nfd["msg_src_ip"], nfd["src_ip6"], nfd["dst_ip6"], nfd["proto"], nfd["in_bytes"], nfd["in_packets"], nfd["out_bytes"], nfd["out_packets"]))
    #        sys.stdout.flush()

    with lock:
        if nfd["proto"] == Protocols.TCP:
            netflow_sources["proto_tcp_bytes"] += nfd["in_bytes"]
            netflow_sources["proto_tcp_packets"] += nfd["in_packets"]
        elif nfd["proto"] == Protocols.UDP:
            netflow_sources["proto_udp_bytes"] += nfd["in_bytes"]
            netflow_sources["proto_udp_packets"] += nfd["in_packets"]
        elif nfd["proto"] == Protocols.ICMP:
            netflow_sources["proto_icmp_bytes"] += nfd["in_bytes"]
            netflow_sources["proto_icmp_packets"] += nfd["in_packets"]
        elif nfd["proto"] == Protocols.IPV6 or nfd["proto"] == Protocols.ICMP6:
            netflow_sources["proto_ipv6_bytes"] += nfd["in_bytes"]
            netflow_sources["proto_ipv6_packets"] += nfd["in_packets"]
        else:
            netflow_sources["proto_other_bytes"] += nfd["in_bytes"]
            netflow_sources["proto_other_packets"] += nfd["in_packets"]


def NetFlow_PacketProcessor(adns_resolver, nf_src_ip, data):
    global Running, netflow_sources

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
                    sys.stdout.write("NPP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                    sys.stdout.flush()
                return

            # Data
            i = 0
            while i != nfd["count"]:
                with lock:
                    netflow_sources["flows_received"] += 1

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
                        sys.stdout.write("NPP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                        sys.stdout.flush()
                    return

                NetFlow_FlowProcessor(adns_resolver, nfd)

                with lock:
                    netflow_sources["flows_processed"] += 1

            with lock:
                if "." in nfd["msg_src_ip"]:
                    netflow_sources["v4_packets_processed"] += 1
                    netflow_sources[nfd["msg_src_ip"]]["v4_packets_processed"] += 1
                else:
                    netflow_sources["v6_packets_processed"] += 1
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
                    sys.stdout.write("NPP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                    sys.stdout.flush()
                return

            # Data
            i = 0
            while i != nfd["count"]:
                with lock:
                    netflow_sources["flows_received"] += 1

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
                        sys.stdout.write("NPP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                        sys.stdout.flush()
                    return

                NetFlow_FlowProcessor(adns_resolver, nfd)

                with lock:
                    netflow_sources["flows_processed"] += 1

            with lock:
                if "." in nfd["msg_src_ip"]:
                    netflow_sources["v4_packets_processed"] += 1
                    netflow_sources[nfd["msg_src_ip"]]["v4_packets_processed"] += 1
                else:
                    netflow_sources["v6_packets_processed"] += 1
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
                    nfd["domain_id"] = 0

                else:
                    if config["debug"]:
                        sys.stdout.write("NPP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
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
                        sys.stdout.write("NPP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
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
                            sys.stdout.write("NPP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
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
                            sys.stdout.write("NPP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                            sys.stdout.flush()
                        return

                    nfdec_size = nfd["template_field_count"] * 4
                    if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                        nfd_template = struct.unpack(">" + "H" * (nfdec_size / 2), data[nfdec_pos:nfdec_pos + nfdec_size])
                        nfdec_pos += nfdec_size

                    else:
                        if config["debug"]:
                            sys.stdout.write("NPP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                            sys.stdout.flush()
                        return

                    if (nfd["version"] == 10) and (nfd["field_info_element_id"] & NetflowMessageID.Enterprise == NetflowMessageID.Enterprise):
                        nfdec_size = 4
                        if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                            nfd["field_enterprise_number"], = struct.unpack(">I", data[nfdec_pos:nfdec_pos + nfdec_size])
                            nfdec_pos += nfdec_size

                        else:
                            if config["debug"]:
                                sys.stdout.write("NPP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                                sys.stdout.flush()
                            return

                    i = 0
                    j = 0
                    nfd_template_unpack = ">"
                    nfd_template_struct = {}
                    nfd_template_size = 0
                    while i != nfd["template_field_count"]:
                        if nfd_template[(2 * i) + 1] == 1:
                            nfd_template_struct[nfd_template[(2 * i)]] = (j, 1, 1)
                            j += 1
                            nfd_template_unpack = nfd_template_unpack + "B"
                            nfd_template_size += 1

                        elif nfd_template[(2 * i) + 1] == 2:
                            nfd_template_struct[nfd_template[(2 * i)]] = (j, 1, 2)
                            j += 1
                            nfd_template_unpack = nfd_template_unpack + "H"
                            nfd_template_size += 2

                        elif nfd_template[(2 * i) + 1] == 3:
                            nfd_template_struct[nfd_template[(2 * i)]] = (j, 3, 3)
                            j += 3
                            nfd_template_unpack = nfd_template_unpack + "BBB"
                            nfd_template_size += 3

                        elif nfd_template[(2 * i) + 1] == 4:
                            nfd_template_struct[nfd_template[(2 * i)]] = (j, 1, 4)
                            j += 1
                            nfd_template_unpack = nfd_template_unpack + "I"
                            nfd_template_size += 4

                        elif nfd_template[(2 * i) + 1] == 6:
                            nfd_template_struct[nfd_template[(2 * i)]] = (j, 3, 6)
                            j += 3
                            nfd_template_unpack = nfd_template_unpack + "HHH"
                            nfd_template_size += 6

                        elif nfd_template[(2 * i) + 1] == 8:
                            nfd_template_struct[nfd_template[(2 * i)]] = (j, 1, 8)
                            j += 1
                            nfd_template_unpack = nfd_template_unpack + "Q"
                            nfd_template_size += 8

                        elif nfd_template[(2 * i) + 1] == 16:
                            nfd_template_struct[nfd_template[(2 * i)]] = (j, 2, 16)
                            j += 2
                            nfd_template_unpack = nfd_template_unpack + "QQ"
                            nfd_template_size += 16

                        else:
                            if config["debug"]:
                                sys.stdout.write("NPP/%s/v%s/%s/%s/Not valid field size: %s,%s,%s.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["template_id"], nfd["msg_type"], i, nfd_template[(2 * i)], nfd_template[(2 * i) + 1]))
                                sys.stdout.flush()
                            return
                        i += 1

                    with lock:
                        template_id = "template-v" + str(nfd["version"]) + "-t" + str(nfd["template_id"]) + "-d" + str(nfd["domain_id"])

                        if template_id in netflow_sources[nfd["msg_src_ip"]].keys():
                            netflow_sources[nfd["msg_src_ip"]][template_id] = (nfd_template_size, nfd_template, nfd_template_unpack, nfd_template_struct)

                        else:
                            netflow_sources[nfd["msg_src_ip"]][template_id] = {}
                            netflow_sources[nfd["msg_src_ip"]][template_id] = (nfd_template_size, nfd_template, nfd_template_unpack, nfd_template_struct)

                    if config["debug"]:
                        sys.stdout.write("NPP/%s/v%s/%s/%s/Processed.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["template_id"], nfd["msg_type"]))

            elif nfd["field_info_element_id"] == NetflowMessageID.Template_Optional:
                nfd["msg_type"] = "optional"
                # Not yet implemented.
                if config["debug"]:
                    sys.stdout.write("NPP/%s/v%s/%s/%s/Not yet supported.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["field_info_element_id"], nfd["msg_type"]))
                    sys.stdout.flush()
                return

            elif nfd["field_info_element_id"] == NetflowMessageID.TemplateV9_Optional:
                nfd["msg_type"] = "optional"
                # Not yet implemented.
                if config["debug"]:
                    sys.stdout.write("NPP/%s/v%s/%s/%s/Not yet supported.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["field_info_element_id"], nfd["msg_type"]))
                    sys.stdout.flush()
                return

            elif nfd["field_info_element_id"] >= NetflowMessageID.FlowRecord:
                nfd["msg_type"] = "data"

                template_id = "template-v" + str(nfd["version"]) + "-t" + str(nfd["field_info_element_id"]) + "-d" + str(nfd["domain_id"])
                if template_id in netflow_sources[nfd["msg_src_ip"]].keys():
                    # Calculate padding.
                    nf_data_padding = ((nfd["msg_size"] - nfdec_pos) % (netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Size])) % 4

                    while nfdec_pos != nfd["msg_size"] - nf_data_padding:
                        with lock:
                            netflow_sources["flows_received"] += 1

                        nfdec_size = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Size]
                        if (nfd["msg_size"] - nfdec_pos) >= nfdec_size:
                            nf_data = struct.unpack(netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Unpack], data[nfdec_pos:nfdec_pos + nfdec_size])
                            nfdec_pos += nfdec_size
                        else:
                            if config["debug"]:
                                sys.stdout.write("NPP/%s/v%s/%s/Not enough data left.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                                sys.stdout.flush()
                            return

                        if NetFlowDataTypes.IPv4_Src_Addr in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.IPv4_Src_Addr][0]
                            nfd["src_ip4"] = socket.inet_ntop(socket.AF_INET, struct.pack("!L", nf_data[nf_data_loc]))
                        else:
                            nfd["src_ip4"] = None

                        if NetFlowDataTypes.IPv4_Dst_Addr in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.IPv4_Dst_Addr][0]
                            nfd["dst_ip4"] = socket.inet_ntop(socket.AF_INET, struct.pack("!L", nf_data[nf_data_loc]))
                        else:
                            nfd["dst_ip4"] = None

                        if NetFlowDataTypes.IPv4_Next_Hop in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.IPv4_Next_Hop][0]
                            nfd["nexthop_ip4"] = socket.inet_ntop(socket.AF_INET, struct.pack("!L", nf_data[nf_data_loc]))
                        else:
                            nfd["nexthop_ip4"] = None

                        if NetFlowDataTypes.IPv6_Src_Addr in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.IPv6_Src_Addr][0]
                            nfd["src_ip6"] = socket.inet_ntop(socket.AF_INET6, struct.pack("!2Q", nf_data[nf_data_loc], nf_data[nf_data_loc + 1]))
                        else:
                            nfd["src_ip6"] = None

                        if NetFlowDataTypes.IPv6_Dst_Addr in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.IPv6_Dst_Addr][0]
                            nfd["dst_ip6"] = socket.inet_ntop(socket.AF_INET6, struct.pack("!2Q", nf_data[nf_data_loc], nf_data[nf_data_loc + 1]))
                        else:
                            nfd["dst_ip6"] = None

                        if NetFlowDataTypes.IPv6_Next_Hop in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.IPv6_Next_Hop][0]
                            nfd["nexthop_ip6"] = socket.inet_ntop(socket.AF_INET6, struct.pack("!2Q", nf_data[nf_data_loc], nf_data[nf_data_loc + 1]))
                        else:
                            nfd["nexthop_ip6"] = None

                        if NetFlowDataTypes.Src_AS in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.Src_AS][0]
                            nfd["src_as"] = nf_data[nf_data_loc]
                        else:
                            nfd["src_as"] = None

                        if NetFlowDataTypes.Dst_AS in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.Dst_AS][0]
                            nfd["dst_as"] = nf_data[nf_data_loc]
                        else:
                            nfd["dst_as"] = None

                        if NetFlowDataTypes.Input_SNMP in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.Input_SNMP][0]
                            nfd["in_interface"] = nf_data[nf_data_loc]
                        else:
                            nfd["in_interface"] = 0

                        if NetFlowDataTypes.Output_SNMP in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.Output_SNMP][0]
                            nfd["out_interface"] = nf_data[nf_data_loc]
                        else:
                            nfd["out_interface"] = 0

                        if NetFlowDataTypes.In_Bytes in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.In_Bytes][0]
                            nfd["in_bytes"] = nf_data[nf_data_loc]
                        else:
                            nfd["in_bytes"] = 0

                        if NetFlowDataTypes.Out_Bytes in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.Out_Bytes][0]
                            nfd["out_bytes"] = nf_data[nf_data_loc]
                        else:
                            nfd["out_bytes"] = 0

                        if NetFlowDataTypes.In_Packets in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.In_Packets][0]
                            nfd["in_packets"] = nf_data[nf_data_loc]
                        else:
                            nfd["in_packets"] = 0

                        if NetFlowDataTypes.Out_Packets in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.Out_Packets][0]
                            nfd["out_packets"] = nf_data[nf_data_loc]
                        else:
                            nfd["out_packets"] = 0

                        if NetFlowDataTypes.First_Switched in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.First_Switched][0]
                            nfd["flow_first"] = nf_data[nf_data_loc]
                        else:
                            nfd["flow_first"] = 0

                        if NetFlowDataTypes.Last_Switched in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.Last_Switched][0]
                            nfd["flow_last"] = nf_data[nf_data_loc]
                        else:
                            nfd["flow_last"] = 0

                        if NetFlowDataTypes.L4_Src_Port in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.L4_Src_Port][0]
                            nfd["src_port"] = nf_data[nf_data_loc]
                        else:
                            nfd["src_port"] = None

                        if NetFlowDataTypes.L4_Dst_Port in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.L4_Dst_Port][0]
                            nfd["dst_port"] = nf_data[nf_data_loc]
                        else:
                            nfd["dst_port"] = None

                        if NetFlowDataTypes.TCP_Flags in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.TCP_Flags][0]
                            nfd["tcp_flags"] = nf_data[nf_data_loc]
                        else:
                            nfd["tcp_flags"] = None

                        if NetFlowDataTypes.Protocol in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.Protocol][0]
                            nfd["proto"] = nf_data[nf_data_loc]
                        else:
                            nfd["proto"] = None

                        if NetFlowDataTypes.Src_TOS in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.Src_TOS][0]
                            nfd["src_tos"] = nf_data[nf_data_loc]
                        else:
                            nfd["src_tos"] = None

                        if NetFlowDataTypes.Dst_TOS in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.Dst_TOS][0]
                            nfd["dst_tos"] = nf_data[nf_data_loc]
                        else:
                            nfd["dst_tos"] = None

                        if NetFlowDataTypes.Src_Mask in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.Src_Mask][0]
                            nfd["src_mask4"] = nf_data[nf_data_loc]
                        else:
                            nfd["src_mask4"] = None

                        if NetFlowDataTypes.Dst_Mask in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.Dst_Mask][0]
                            nfd["dst_mask4"] = nf_data[nf_data_loc]
                        else:
                            nfd["dst_mask4"] = None

                        if NetFlowDataTypes.IPv6_Src_Mask in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.IPv6_Src_Mask][0]
                            nfd["src_mask6"] = nf_data[nf_data_loc]
                        else:
                            nfd["src_mask6"] = None

                        if NetFlowDataTypes.IPv6_Dst_Mask in netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct]:
                            nf_data_loc = netflow_sources[nfd["msg_src_ip"]][template_id][NetFlowTemplates.Struct][NetFlowDataTypes.IPv6_Dst_Mask][0]
                            nfd["dst_mask6"] = nf_data[nf_data_loc]
                        else:
                            nfd["dst_mask6"] = None

                        NetFlow_FlowProcessor(adns_resolver, nfd)

                        with lock:
                            netflow_sources["flows_processed"] += 1

                else:
                    if config["debug"]:
                        sys.stdout.write("NPP/%s/v%s/%s/%s/Unknown template ID.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["field_info_element_id"], nfd["msg_type"]))
                        sys.stdout.flush()
                    return

            else:
                if config["debug"]:
                    sys.stdout.write("NPP/%s/v%s/%s/%s/Unknown message type.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["field_info_element_id"], nfd["msg_type"]))
                    sys.stdout.flush()
                return

            with lock:
                if "." in nfd["msg_src_ip"]:
                    netflow_sources["v4_packets_processed"] += 1
                    netflow_sources[nfd["msg_src_ip"]]["v4_packets_processed"] += 1
                else:
                    netflow_sources["v6_packets_processed"] += 1
                    netflow_sources[nfd["msg_src_ip"]]["v6_packets_processed"] += 1

        else:
            if config["debug"]:
                sys.stdout.write("NPP/%s/v%s/%s/Unsupported version.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"]))
                sys.stdout.flush()
            return

    except KeyboardInterrupt:
        Running = False
        os._exit(1)

    except:
        if config["debug"]:
            e = str(sys.exc_info())
            if (nfd["version"] == 9 or nfd["version"] == 10):
                sys.stdout.write("NPP/%s/v%s/%s/%s/Exception: %s.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["field_info_element_id"], nfd["msg_type"], e))
            else:
                sys.stdout.write("NPP/%s/v%s/%s/Exception: %s.\n" % (nfd["msg_src_ip"], nfd["version"], nfd["msg_type"], e))
            sys.stdout.flush()
        pass
        # Running = False
        # os._exit(1)


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
        netflow_sources["stats_prefix_cache"] = len(prefix_cache.prefixes())

    except sqlite3.Error:
        if config["debug"]:
            sys.stdout.write("GF/SQLite database does not exist. Creating a new file.\n")
            sys.stdout.flush()

        sqlite_cur.execute("CREATE TABLE prefixes (prefix text, asn integer, timestamp integer)")
        sqlite_con.close()
        pass

    statsd = threading.Thread(target=Stats_Worker)
    statsd.daemon = True
    statsd.start()

    netflowd = {}
    netflowd_nb = 0
    for i in range(config["netflow_workers"]):
        netflowd[netflowd_nb] = threading.Thread(target=NetFlow_Worker)
        netflowd[netflowd_nb].daemon = True
        netflowd[netflowd_nb].start()
        netflowd_nb += 1
        if config["debug"]:
            sys.stdout.write("GF/NetFlow worker %s started.\n" % (i))
            sys.stdout.flush()

    if config["flow_ipv4_enable"]:
        netrecvd = "ipv4"
        netrecvd4 = threading.Thread(target=NetFlow_Receiver, args=(netrecvd,))
        netrecvd4.daemon = True
        netrecvd4.start()
        if config["debug"]:
            sys.stdout.write("GF/NetFlow receiver v4 started.\n")
            sys.stdout.flush()

    if config["flow_ipv6_enable"]:
        netrecvd = "ipv6"
        netrecvd6 = threading.Thread(target=NetFlow_Receiver, args=(netrecvd,))
        netrecvd6.daemon = True
        netrecvd6.start()
        if config["debug"]:
            sys.stdout.write("GF/NetFlow receiver v6 started.\n")
            sys.stdout.flush()

    if config["http_enable"] and (config["http_ipv4_enable"] or config["http_ipv6_enable"]):
        httpd = threading.Thread(target=HTTP_Worker)
        httpd.daemon = True
        httpd.start()
        if config["debug"]:
            sys.stdout.write("GF/HTTP daemon started.\n")
            sys.stdout.flush()

    while Running:
        try:
            while Running:
                time.sleep(2)
                # if netflow_sources["stats_queue"] >= 0.85 * config["netflow_queue"]:
                #    netflowd_nb += 1
                #    netflowd[netflowd_nb] = threading.Thread(target=NetFlow_Worker)
                #    netflowd[netflowd_nb].daemon = True
                #    netflowd[netflowd_nb].start()
                #    if config["debug"]:
                #        sys.stdout.write("GF/NetFlow worker started.\n")
                #        sys.stdout.flush()

                # if netflow_sources["stats_queue"] <= 0.25 * config["netflow_queue"]:
                #    netflowd[netflowd_nb].append()
                #    netflowd_nb -= 1
                #    if config["debug"]:
                #        sys.stdout.write("GF/NetFlow worker stopped.\n")
                #        sys.stdout.flush()

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

            if not config["flow_ipv4_enable"] and not config["flow_ipv6_enable"]:
                print("You must enable the process to listen on at least one IP address, IPv4 or IPv6.")
                sys.exit(2)

            Running = True

            # Initialize a prefix cache.
            prefix_cache = RFCPrefixTable()

            # Initialize a queue for NetFlow workers.
            netflow_queue = Queue.Queue(maxsize=config["netflow_queue"])

            # Initialize a lock.
            lock = threading.RLock()

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
            lock = threading.RLock()

            # Starting GIXflow as a foreground process.
            GIXFlow()

        else:
            print("Unknown argument. Usage: %s start|stop|exabgp" % sys.argv[0])
            sys.exit(2)

        sys.exit(0)

    else:
        print("Usage: %s start|stop|exabgp" % sys.argv[0])
        sys.exit(2)
