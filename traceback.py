import subprocess
import argparse
import re
import time
import os
import glob


def perform_scan(scan_ip, args):
    date_prefix = time.strftime("%m:%d:%Y:%H:%M:%S-",
                                time.localtime())
    cmd = "nmap %s -oA %s %s" % (args.nmap_opts,
                                 os.path.join(args.dst, date_prefix + scan_ip),
                                 scan_ip)
    os.system(cmd)

    for file_path in glob.glob(
            os.path.join(args.dst,
                         date_prefix + scan_ip + "*")):
        if file_path.endswith(".nmap"):
            md5_file_path = os.path.join(args.dst, "md5sums.txt")
            cmd = "md5sum %s >> %s" % (file_path, md5_file_path)
            print "\n*Waiting on instances*\n"
            os.system(cmd)

def monitor_file(args):
    cmd = "tail -n1 -F %s" % args.scanfile[0]
    print "\n*Monitoring for Snort instances*\n\n"
    pipe = os.popen(cmd)
    while True:
        line = pipe.readline().strip()
        m = re.search(args.match_pattern, line)
        if m:
            print "*PATTERN DECTECTED* {{%s}}" % line
            m = re.search(args.extract_pattern, line)
            if m is not None:
                scan_ip = m.group(1)
                perform_scan(scan_ip, args)

def main():
    parser = argparse.ArgumentParser(description="monitor syslog and create nmap files")
    parser.add_argument("-dst", required=True,
                        help="where nmap files are stored")
    parser.add_argument("scanfile" , nargs=1,
                        help="file to scan")
    parser.add_argument("-nmap-opts",
                        default = "-A --script ip-geolocation-geoplugin --script asn-query --traceroute",
                        help="nmap scan options")
    parser.add_argument("-match-pattern", default = "(\[\d+\:\d+\:\d+\])",
                        help='match pattern to search for')
    parser.add_argument("-extract-pattern",
                        default = "(\d+\.\d+\.\d+\.\d+)",
                        help="extract pattern used to get source ip")

    args = parser.parse_args()
    monitor_file(args)

if __name__ == "__main__":
    main()
