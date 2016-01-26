#!/usr/bin/python

import time
import re
import nmap
import os
import sys
import hashlib

SYSLOG     = "/var/log/syslog"
OUTPUT_DIR = "."

regex    = re.compile("scanme \{ICMP\} (\d+\.\d+\.\d+\.\d+)")
position = 0
nm       = nmap.PortScanner()

def scan_syslog():
    global regex
    global positio

    try:
        syslog = open(SYSLOG, "r")
    except Exception, e:
        print "Unable to open syslog: %s" % e 

    syslog.seek(position)

    now = int(time.time())
 
    output_path = "%s/%s" % (OUTPUT_DIR, now)

    for line in syslog:

        match = regex.search(line)

        if not match:
            continue

        ip_addr = match.group(1)

        if not os.path.isdir(output_path):
            try:
                os.makedirs(output_path)
            except Exception, e:
                print "Unable to create output directory: %s" % e
                sys.exit(1)


        print "Scanning %s" % ip_addr

        output_file = "%s/%s" % (output_path, ip_addr)

        # You can't use -oA with the nmap python library because it relies on the XML
        # output to do anything else. As a result we're using -oN and -oG to get the
        # regular and greppable outputs via nmap and then having to write the XML output
        # ourselves afterwards. End result is the same.
        nm.scan(ip_addr, arguments = "-Pn -sC -sV -R --script ip-geolocation-geoplugin --script asn-query --traceroute -oN %s.nmap -oG %s.gnmap" % (output_file, output_file))

        xml = nm.get_nmap_last_output()

        try:
            xml_output = open("%s.xml" % output_file, "w")
        except Exception, e:
            print "Cann't open %s.xml for writing: %s" % (output_file, e)
            sys.exit(1)

        xml_output.write(xml)
        xml_output.close()

        for file in ["%s.xml" % output_file, "%s.nmap" % output_file, "%s.gnmap" % output_file]:
            content = "".join(open(file).readlines())
            md5 = hashlib.md5()
            md5.update(content)
            digest = md5.hexdigest()
            try:
                output = open("%s.md5" % file, "w")
            except Exception, e:
                print "Unable to open %s.md5 for writing: %s" % (file, e)
                sys.exit(1)

            output.write(digest)
            output.close()

    position = syslog.tell()

while 1:
    print "Scanning syslog"
    scan_syslog()
    time.sleep(1)
