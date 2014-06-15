"""
gixglow_config.py
Created by Daniel Piekacz on 2014-06-01.
Updated on 2014-06-15.
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
config["db_file"] = "/opt/gixflow/db/gixflow.db"

# Listen on the given IP address and port.
# Set to blank to bind to all IP addresses.
config["flow_port"] = 9000

config["flow_ipv4_enable"] = True
config["flow_ipv4"] = "198.51.100.255"

config["flow_ipv6_enable"] = True
config["flow_ipv6"] = "2001:db8::ffff"

# Size of the NetFlow queue.
config["netflow_queue"] = 50000

# Number of NetFlow workers.
config["netflow_workers"] = 10

# Enable/Disable: Forwarding NetFlow data to another collector.
config["forwardto_enable"] = False
config["forwardto_ip"] = "127.0.0.1"
config["forwardto_port"] = 2100

# Enable IP2ASN lookup using Cymru DNS service.
# Keep in mind that the process may generate thousands of DNS queries
# to your local DNS resolver which will forward them to Cymru DNS servers.
config["ip2asn_enable"] = True

# IP2ASN lookup mode: maxmind/cymru/routeviews.
# maxmind - uses GeoLite data converted to SQLite3 database.
# cymru - uses DNS based IP2ASN mapping from Cymru (IPv4 & IPv6).
# routeviews - uses DNS based IP2ASN mapping from Route Views (IPv4 only).
config["ip2asn_mode"] = "maxmind"

# Enable HTTP server.
config["http_enable"] = True
config["http_port"] = 9001

config["http_ipv4_enable"] = True
config["http_ipv4"] = "198.51.100.255"
config["http_ipv6_enable"] = True
config["http_ipv6"] = "2001:db8::ffff"

# Enable SSL support.
config["http_ssl_enable"] = False
config["http_ssl_cert"] = "web/gixflow.crt"
config["http_ssl_key"] = "web/gixflow.pem"

# Paths to web files.
config["http_file_stats"] = 'web/stats.html'
config["http_file_jquery"] = 'web/jquery-1.11.1.min.js'
config["http_file_highcharts"] = 'web/highcharts.js'
