#!/usr/bin/env python
#
import os, sys, time, struct, socket
import Queue
from daemon import daemon
from threading import Thread
from netaddr import IPNetwork
import radix
import adns
import sqlite3
import json

config = {}
config['listen_port'] = 9000
config['netflow_queue'] = 20000
config['netflow_workers'] = 10
config['forwardto_ip'] = '127.0.0.1'
config['forwardto_port'] = 2100

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
	Never = 0		# never - for RFC special IP networks and known prefixes
	Default = 2419200	# 4 weeks - for prefixes where DNS lookup returned data
	Short = 172800		# 2 days - for prefixes where DNS lookup returned no data or failed

def localIPtable():
	rtree = radix.Radix()

	prefix = rtree.add('0.0.0.0/8')			# Current network (only valid as source address)
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('10.0.0.0/8')		# Private network
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('127.0.0.0/8')		# Loopback
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('169.254.0.0/16')		# Link-local
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('172.16.0.0/12')		# Private network
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('192.0.0.0/24')		# IETF Protocol Assignments
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('192.0.2.0/24')		# TEST-NET-1, documentation and examples
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('192.168.0.0/16')		# Private network
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('198.18.0.0/15')		# Network benchmark tests
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('198.51.100.0/24')		# TEST-NET-2, documentation and examples
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('203.0.113.0/24')		# TEST-NET-3, documentation and examples
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('224.0.0.0/4')		# IP multicast (former Class D network)
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('240.0.0.0/4')		# Reserved (former Class E network)
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never

	prefix = rtree.add('2001:10::/28')		# Overlay Routable Cryptographic Hash IDentifiers (ORCHID) addresses
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('2001:db8::/32')		# Documentation and examples
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('3ffe::/16')			# The second instance of the 6bone experimental network
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('5f00::/8')			# The first instance of the 6bone experimental network
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('fc00::/7')			# Unique-local
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('fe80::/10')			# Link-local
	prefix.data["asn"] = ASNtype.Unknown
	prefix.data["exp"] = PrefixExpire.Never

	prefix = rtree.add('192.175.48.0/24')		# AS112 DNS
	prefix.data["asn"] = 112
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('2620:4f:8000::/48')		# AS112 DNS
	prefix.data["asn"] = 112
	prefix.data["exp"] = PrefixExpire.Never

## definition of IP networks which should be considered by AS-Stats as local
	prefix = rtree.add('x.x.x.x/yy')
	prefix.data["asn"] = ASNtype.Internal
	prefix.data["exp"] = PrefixExpire.Never
	prefix = rtree.add('x:x:x::/yy')
	prefix.data["asn"] = ASNtype.Internal
	prefix.data["exp"] = PrefixExpire.Never

	return rtree

def IP2ASNresolver(h_adns, ip_rev, ip_net):
	rnode = rtree.search_best(ip_net)
	ts = int(time.time())
	if rnode == None:
		qa = h_adns.synchronous(ip_rev + ".origin.asn.cymru.com", adns.rr.TXT)
		if qa != None and qa[3] != ():
			for i in range(0, len(qa[3])):
				asn = int(qa[3][i][0].split('|')[0].split(' ')[0])
				ip_prefix = qa[3][i][0].split('|')[1].split(' ')[1]
				prefix = rtree.add(ip_prefix)
				prefix.data["asn"] = asn
				prefix.data["exp"] = ts + PrefixExpire.Default
			asn = rtree.search_best(ip_net).data["asn"]
		else:
			qac = 0
			while ((qa == None or qa[3] == ()) and qac <= 2):
				qa = h_adns.synchronous(ip_rev + ".origin.asn.cymru.com", adns.rr.TXT)
				qac += 1

			if qa != None and qa[3] != ():
				for i in range(0, len(qa[3])):
					asn = int(qa[3][i][0].split('|')[0].split(' ')[0])
					ip_prefix = qa[3][i][0].split('|')[1].split(' ')[1]
					prefix = rtree.add(ip_prefix)
					prefix.data["asn"] = asn
					prefix.data["exp"] = ts + PrefixExpire.Default
				asn = rtree.search_best(ip_net).data["asn"]
			else:
				asn = ASNtype.Unknown
				prefix = rtree.add(ip_net + "/24")
				prefix.data["asn"] = ASNtype.Unknown
				prefix.data["exp"] = ts + PrefixExpire.Short
	else:
		if rnode.data["exp"] != 0 and rnode.data["exp"] < ts:
			rtree.delete(rnode.prefix)
			asn = IP2ASNresolver(h_adns, ip_rev, ip_net)
		else:
			asn = rnode.data["asn"]
	return int(asn)

def StatsWorker():
	swi = 0
	while True:
		time.sleep(10)

		if swi == 60:
			swi = 0
			sys.stdout.write("dumping prefix table to sqlite db\n")
			sys.stdout.flush()
			sqlite_con = sqlite3.connect('/opt/gixflow/gixflow.db')
			sqlite_cur = sqlite_con.cursor()
			sqlite_cur.execute('''DELETE FROM prefixes''')

			nodes = rtree.nodes()
			for rnode in nodes:
				sqlite_cur.execute("INSERT INTO prefixes VALUES ('" + rnode.prefix + "', " + str(rnode.data["asn"]) + ", " + str(rnode.data["exp"]) + ")")

			sqlite_con.commit()
			sqlite_con.close()
		else:
			swi += 1
			prefixes = rtree.prefixes()
			sys.stdout.write("nb of prefixes: " + str(len(prefixes)) + ", swi: " + str(swi) + "\n")
			sys.stdout.flush()

def NetFlowRecvWorker():
	h_adns = adns.init()

	while True:
		try:
			nf_src_ip, data = recvqueue.get(block=True,timeout=10)
			NetflowReceive(h_adns, nf_src_ip, data)
			recvqueue.task_done()
		except Queue.Empty:
			sys.stdout.write("Flow queue is empty\n")
			sys.stdout.flush()
			pass
		except:
			pass

def NetflowReceive(h_adns, nf_src_ip, data):
	try:
		nfdec_pos = 0

		nfdec_pos_size = 2
		nf_hdr_version, = struct.unpack(">H", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
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

## v10 template JUNOS 11.4R7.5
					nfdec_pos_size = 72
					nf_data = struct.unpack(">IIBBHHHIBBIIIBIQQQQB", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
					nfdec_pos += nfdec_pos_size

					nfi_src_ip = socket.inet_ntoa(struct.pack("!L", nf_data[0]))
					nfi_dst_ip = socket.inet_ntoa(struct.pack("!L", nf_data[1]))
					nfi_in_int = nf_data[7]
					nfi_src_mask = nf_data[8]
					nfi_dst_mask = nf_data[9]
					nfi_src_as = nf_data[10]
					nfi_dst_as = nf_data[11]
					nfi_out_int = nf_data[14]
					nfi_bytes = nf_data[15]
					nfi_packets = nf_data[16]

#					ip = IPNetwork(nfi_src_ip + "/" + str(nfi_src_mask))
#					nfi_src_net = str(ip.network) + "/" + str(nfi_src_mask)
#					ip = IPNetwork(nfi_dst_ip + "/" + str(nfi_dst_mask))
#					nfi_dst_net = str(ip.network) + "/" + str(nfi_dst_mask)

					src_ip = nfi_src_ip.split('.')
					src_ip_net = src_ip[0] + "." + src_ip[1] + "." + src_ip[2] + ".0"
					src_ip_rev = "0." + src_ip[2] + "." + src_ip[1] + "." + src_ip[0]

					dst_ip = nfi_dst_ip.split('.')
					dst_ip_net = dst_ip[0] + "." + dst_ip[1] + "." + dst_ip[2] + ".0"
					dst_ip_rev = "0." + dst_ip[2] + "." + dst_ip[1] + "." + dst_ip[0]

					src_as = IP2ASNresolver(h_adns, src_ip_rev, src_ip_net)
					dst_as = IP2ASNresolver(h_adns, dst_ip_rev, dst_ip_net)

			else:
				sys.stdout.write("Unknown Netflow message type: " + str(nf_hdr_info_element_id) + "\n")
				sys.stdout.flush()

		elif nf_hdr_version == 9:
			nfdec_pos_size = 20
			nf_hdr_count, nf_hdr_sys_uptime, nf_hdr_unix_sec, nf_hdr_pack_seq, nf_hdr_source_id, nf_hdr_info_element_id = struct.unpack(">HIIIIH", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
			data_tx = data_tx + struct.pack(">HIIIIH", nf_hdr_count, nf_hdr_sys_uptime, nf_hdr_unix_sec, nf_hdr_pack_seq, nf_hdr_source_id, nf_hdr_info_element_id)
			nfdec_pos += nfdec_pos_size

			if nf_hdr_info_element_id == NetflowMessageID.TemplateV9:
				nfdec_pos_size = 6
				nf_tmpl_length, nf_tmpl_id, nf_tmpl_field_count = struct.unpack(">HHH", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
				data_tx = data_tx + struct.pack(">HHH", nf_tmpl_length + 8, nf_tmpl_id, nf_tmpl_field_count + 2)
				nfdec_pos += nfdec_pos_size

				nfdec_pos_size = nf_tmpl_field_count * 4
				nfd_template_v9 = struct.unpack(">" + "H" * (nfdec_pos_size / 2), data[nfdec_pos:nfdec_pos + nfdec_pos_size])
				data_tx = data_tx + data[nfdec_pos:nfdec_pos + nfdec_pos_size]
				nfdec_pos += nfdec_pos_size

				data_tx = data_tx + struct.pack(">HHHH", 16, 4, 17, 4)

				udpsock_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				udpsock_tx.sendto(data_tx, (config['forwardto_ip'], config['forwardto_port']))

			elif nf_hdr_info_element_id == NetflowMessageID.FlowRecord:
				nfdec_pos_size = 2
				nf_hdr_length, = struct.unpack(">H", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
				data_tx = data_tx + struct.pack(">H", nf_hdr_length + nf_hdr_count * 8)
				nfdec_pos += nfdec_pos_size

				i = 0
				while nfdec_pos != nf_hdr_length + 20:
					i += 1

#					data_tx = data[0:nfdec_pos]

# Mikrotik v6.x
					nfdec_pos_size = 45
					nf_data = struct.unpack(">IIIIIIIIBBHHIBBB", data[nfdec_pos:nfdec_pos + nfdec_pos_size])
					nfdec_pos += nfdec_pos_size

#					nfi_switch_first = nf_data[0]
#					nfi_switch_last = nf_data[1]
#					nfi_packets = nf_data[2]
#					nfi_bytes = nf_data[3]
#					nfi_in_int = nf_data[4]
#					nfi_out_int = nf_data[5]
					nfi_src_ip = socket.inet_ntoa(struct.pack("!L", nf_data[6]))
					nfi_dst_ip = socket.inet_ntoa(struct.pack("!L", nf_data[7]))
#					nfi_proto = nf_data[8]
#					nfi_src_tos = nf_data[9]
#					nfi_src_port = nf_data[10]
#					nfi_dst_port = nf_data[11]
#					nfi_next_hop = socket.inet_ntoa(struct.pack("!L", nf_data[12]))
#					nfi_dst_mask = nf_data[13]
#					nfi_src_mask = nf_data[14]
#					nfi_tcp_flags = nf_data[15]

					src_ip = nfi_src_ip.split('.')
					src_ip_net = src_ip[0] + "." + src_ip[1] + "." + src_ip[2] + ".0"
					src_ip_rev = "0." + src_ip[2] + "." + src_ip[1] + "." + src_ip[0]

					dst_ip = nfi_dst_ip.split('.')
					dst_ip_net = dst_ip[0] + "." + dst_ip[1] + "." + dst_ip[2] + ".0"
					dst_ip_rev = "0." + dst_ip[2] + "." + dst_ip[1] + "." + dst_ip[0]

					src_as = IP2ASNresolver(h_adns, src_ip_rev, src_ip_net)
					dst_as = IP2ASNresolver(h_adns, dst_ip_rev, dst_ip_net)

					data_tx = data_tx + data[nfdec_pos - nfdec_pos_size:nfdec_pos] + struct.pack(">II", int(src_as), int(dst_as))

				udpsock_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				udpsock_tx.sendto(data_tx, (config['forwardto_ip'], config['forwardto_port']))

		else:
			sys.stdout.write("Unknown Netflow packet version: " + str(nf_hdr_version) + ", src ip: " + nf_src_ip + "\n")
			sys.stdout.flush()
			return
	except:
		pass

def GIXFlow():
	try:
		sys.stdout.write("importing sqlite db into prefix table\n")
		sys.stdout.flush()
		sqlite_con = sqlite3.connect('/opt/gixflow/gixflow.db')
		sqlite_cur = sqlite_con.cursor()
		sqlite_cur.execute('''SELECT * FROM prefixes''')
		for ip_prefix in sqlite_cur:
			prefix = rtree.add(ip_prefix[0])
			prefix.data["asn"] = ip_prefix[1]
			prefix.data["exp"] = ip_prefix[2]
	except sqlite3.Error:
		sqlite_cur.execute('''CREATE TABLE prefixes (prefix text, asn integer, timestamp integer)''')
	sqlite_con.close()

	listen_addr = ("", config['listen_port'])
	UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	UDPSock.bind(listen_addr)

	stats = Thread(target = StatsWorker)
	stats.daemon = True
	stats.start()

	for i in range(config['netflow_workers']):
		rt = Thread(target = NetFlowRecvWorker)
		rt.daemon = True
		rt.start()

	while True:
		try:
			data, addr = UDPSock.recvfrom(8192)
			recvqueue.put([addr[0], data], block=False)
		except Queue.Full:
			sys.stdout.write("Flow queue is full\n")
			sys.stdout.flush()
			pass
		except KeyboardInterrupt:
			exit()

class GIXFlowDaemon(daemon):
	def run(self):
		GIXFlow()

if __name__ == '__main__':
	if len(sys.argv) == 2:
		if sys.argv[1] == 'start':
			rtree = localIPtable()
			recvqueue = Queue.Queue(maxsize = config['netflow_queue'])
			daemon = GIXFlowDaemon('/opt/gixflow/gixflow.pid', stdout='/opt/gixflow/gixflow.log', stderr='/opt/gixflow/gixflow.log')
			daemon.start()
		elif  sys.argv[1] == 'stop':
			daemon = GIXFlowDaemon('/opt/gixflow/gixflow.pid', stdout='/opt/gixflow/gixflow.log', stderr='/opt/gixflow/gixflow.log')
			daemon.stop()
		elif  sys.argv[1] == 'restart':
			daemon = GIXFlowDaemon('/opt/gixflow/gixflow.pid', stdout='/opt/gixflow/gixflow.log', stderr='/opt/gixflow/gixflow.log')
			daemon.restart()
		elif  sys.argv[1] == 'exabgp':
			rtree = localIPtable()
			recvqueue = Queue.Queue(maxsize = config['netflow_queue'])
			GIXFlow()
		else:
			print "Unknown command"
			sys.exit(2)
		sys.exit(0)
	else:
		print "usage: %s start|stop|restart|exabgp" % sys.argv[0]
		sys.exit(2)
