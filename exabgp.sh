#!/bin/sh
#
cd /opt/exabgp/sbin

env exabgp.daemon.daemonize=false \
 exabgp.daemon.pid=/var/run/exabgp.pid \
 exabgp.daemon.user=root \
 exabgp.tcp.bind="" \
 exabgp.tcp.port="179" \
 exabgp.log.enable=true \
 exabgp.log.all=false \
 exabgp.log.destination=/opt/gixflow/log_exabgp \
 exabgp.cache.attributes=false \
 exabgp.cache.nexthops=false \
 ./exabgp /opt/gixflow/exabgp.conf
