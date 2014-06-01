"""
gixglow_config.py
Created by Daniel Piekacz on 2014-06-01.
Updated on 2014-06-01.
http://gix.net.pl
"""
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
config["netflow_workers"] = 1

# Enable/Disable: Forwarding NetFlow data to another collector.
config["forwardto_enable"] = False
config["forwardto_ip"] = "127.0.0.1"
config["forwardto_port"] = 2100

# Enable/Disable: IP2ASN lookup using Cymru DNS service.
# Keep in mind that the process can generate thousands of DNS queries
# to your local DNS resolver which will forward them to Cymru DNS servers.
config["ip2asn"] = False
