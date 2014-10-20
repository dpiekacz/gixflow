#!/usr/local/bin/python
#
"""
geodata_import.py
Created by Daniel Piekacz on 2014-06-07.
Updated on 2014-06-15.
https://gixtools.net
"""
import string
import netaddr
import sqlite3

sqlite_con = sqlite3.connect("db/geodata.db")
sqlite_cur = sqlite_con.cursor()
sqlite_cur.execute("CREATE TABLE prefixes (prefix text, asn integer, timestamp integer)")
sqlite_cur.execute("CREATE TABLE countries (prefix text, country text, timestamp integer)")

print ("IP2ASN v4")
f = open('geodata/GeoIPASNum2.csv', 'r')
i = 0
j = 0
for line in f:
    x1 = string.split(line, ",")
    iprange = netaddr.IPRange(x1[0].strip('"'), x1[1].strip('"'))
    x2 = x1[2].strip("\n").strip('"')
    x3 = string.find(x2, " ")
    asn = int(x2[2:x3])
    name = x2[x3 + 1:]

    for net in iprange.cidrs():
        ipnet = str(net)
        sqlite_cur.execute("INSERT INTO prefixes VALUES ('%s', %s, %s)" % (ipnet, asn, 0))

    i += 1
    if i == 1000:
        i = 0
        j += 1
        print (j * 1000)

sqlite_con.commit()
f.close()

print ("IP2ASN v6")
f = open('geodata/GeoIPASNumv6-2.csv', 'r')
i = 0
j = 0
for line in f:
    x1 = string.split(line, ",")
    iprange = netaddr.IPRange(x1[0].strip('"'), x1[1].strip('"'))
    x2 = x1[4].strip("\n").strip('"')
    x3 = string.find(x2, " ")
    asn = int(x2[2:x3])
    name = x2[x3 + 1:]

    for net in iprange.cidrs():
        ipnet = str(net)
        sqlite_cur.execute("INSERT INTO prefixes VALUES ('%s', %s, %s)" % (ipnet, asn, 0))

    i += 1
    if i == 1000:
        i = 0
        j += 1
        print (j * 1000)

sqlite_con.commit()
f.close()

print ("IP2COUNTRY v4")
f = open('geodata/GeoIPCountryWhois.csv', 'r')
i = 0
j = 0
for line in f:
    x1 = string.split(line, ",")
    iprange = netaddr.IPRange(x1[2].strip('"'), x1[3].strip('"'))
    country = x1[4].strip('"')

    for net in iprange.cidrs():
        ipnet = str(net)
        sqlite_cur.execute("INSERT INTO countries VALUES ('%s', '%s', %s)" % (ipnet, country, 0))

    i += 1
    if i == 1000:
        i = 0
        j += 1
        print (j * 1000)

sqlite_con.commit()
f.close()

print ("IP2COUNTRY v6")
f = open('geodata/GeoIPv6CountryCSV.cvs', 'r')
i = 0
j = 0
for line in f:
    x1 = string.split(line, ",")
    iprange = netaddr.IPRange(x1[0].strip(' ').strip('"'), x1[1].strip(' ').strip('"'))
    country = x1[4].strip('"').strip(' ')

    for net in iprange.cidrs():
        ipnet = str(net)
        sqlite_cur.execute("INSERT INTO countries VALUES ('%s', '%s', %s)" % (ipnet, country, 0))

    i += 1
    if i == 1000:
        i = 0
        j += 1
        print (j * 1000)

sqlite_con.commit()
f.close()

sqlite_cur.execute("DELETE FROM prefixes WHERE prefix='1::1/128'")
sqlite_cur.execute("DELETE FROM prefixes WHERE prefix='2::2/128'")
sqlite_con.commit()

sqlite_con.close()
