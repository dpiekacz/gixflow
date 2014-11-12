#!/bin/sh
#
# geodata_download.sh
# Created by Daniel Piekacz on 2014-11-10.
# Updated on 2014-11-11.
# https://gixtools.net
#
cd geodata
wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum2.zip
wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum2v6.zip
wget http://geolite.maxmind.com/download/geoip/database/GeoIPCountryCSV.zip
wget http://geolite.maxmind.com/download/geoip/database/GeoIPv6.csv.gz

unzip GeoIPASNum2.zip
unzip GeoIPASNum2v6.zip
unzip GeoIPCountryCSV.zip
gunzip -d GeoIPv6.csv.gz
