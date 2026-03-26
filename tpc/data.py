"""
TPC Terminal Port Crawler — static data: port database, service metadata, constants.
"""

import os
from pathlib import Path

VERSION = "1.3.0"

_data_dir = Path.home() / ".tpc"
_data_dir.mkdir(parents=True, exist_ok=True)
HISTORY_FILE = str(_data_dir / "scan_history.log")

known_ports = {
    7:     {"service": "Echo",                    "protocols": ["TCP", "UDP"]},
    19:    {"service": "CHARGEN",                 "protocols": ["TCP", "UDP"]},
    20:    {"service": "FTP-data",                "protocols": ["TCP", "SCTP"]},
    21:    {"service": "FTP",                     "protocols": ["TCP", "UDP", "SCTP"]},
    22:    {"service": "SSH/SCP/SFTP",            "protocols": ["TCP", "UDP", "SCTP"]},
    23:    {"service": "Telnet",                  "protocols": ["TCP"]},
    25:    {"service": "SMTP",                    "protocols": ["TCP"]},
    42:    {"service": "WINS Replication",        "protocols": ["TCP", "UDP"]},
    43:    {"service": "WHOIS",                   "protocols": ["TCP", "UDP"]},
    49:    {"service": "TACACS",                  "protocols": ["UDP", "TCP"]},
    53:    {"service": "DNS",                     "protocols": ["TCP", "UDP"]},
    67:    {"service": "DHCP/BOOTP",              "protocols": ["UDP"]},
    68:    {"service": "DHCP/BOOTP",              "protocols": ["UDP"]},
    69:    {"service": "TFTP",                    "protocols": ["UDP"]},
    70:    {"service": "Gopher",                  "protocols": ["TCP"]},
    79:    {"service": "Finger",                  "protocols": ["TCP"]},
    80:    {"service": "HTTP",                    "protocols": ["TCP", "UDP", "SCTP"]},
    88:    {"service": "Kerberos",                "protocols": ["TCP", "UDP"]},
    102:   {"service": "MS Exchange ISO-TSAP",    "protocols": ["TCP"]},
    110:   {"service": "POP3",                    "protocols": ["TCP"]},
    113:   {"service": "Ident",                   "protocols": ["TCP"]},
    119:   {"service": "NNTP (Usenet)",            "protocols": ["TCP"]},
    123:   {"service": "NTP",                     "protocols": ["UDP"]},
    135:   {"service": "Microsoft RPC EPMAP",     "protocols": ["TCP", "UDP"]},
    137:   {"service": "NetBIOS-ns",              "protocols": ["TCP", "UDP"]},
    138:   {"service": "NetBIOS-dgm",             "protocols": ["TCP", "UDP"]},
    139:   {"service": "NetBIOS-ssn",             "protocols": ["TCP", "UDP"]},
    143:   {"service": "IMAP",                    "protocols": ["TCP", "UDP"]},
    161:   {"service": "SNMP (unencrypted)",      "protocols": ["UDP"]},
    162:   {"service": "SNMP-trap (unencrypted)", "protocols": ["UDP"]},
    179:   {"service": "BGP",                     "protocols": ["TCP"]},
    389:   {"service": "LDAP",                    "protocols": ["TCP", "UDP"]},
    443:   {"service": "HTTPS",                   "protocols": ["TCP", "UDP", "SCTP"]},
    445:   {"service": "Microsoft DS SMB",        "protocols": ["TCP", "UDP"]},
    464:   {"service": "Kerberos",                "protocols": ["TCP", "UDP"]},
    465:   {"service": "SMTP over TLS/SSL",       "protocols": ["TCP"]},
    500:   {"service": "IPSec / ISAKMP / IKE",    "protocols": ["UDP"]},
    512:   {"service": "rexec",                   "protocols": ["TCP"]},
    513:   {"service": "rlogin",                  "protocols": ["TCP"]},
    514:   {"service": "syslog",                  "protocols": ["UDP"]},
    515:   {"service": "LPD/LPR",                 "protocols": ["TCP"]},
    520:   {"service": "RIP",                     "protocols": ["UDP"]},
    548:   {"service": "AFP",                     "protocols": ["TCP"]},
    554:   {"service": "RTSP",                    "protocols": ["TCP", "UDP"]},
    587:   {"service": "SMTP",                    "protocols": ["TCP"]},
    631:   {"service": "IPP",                     "protocols": ["TCP"]},
    636:   {"service": "LDAP over TLS/SSL",       "protocols": ["TCP", "UDP"]},
    691:   {"service": "Microsoft Exchange",      "protocols": ["TCP"]},
    873:   {"service": "rsync",                   "protocols": ["TCP"]},
    902:   {"service": "VMware Server",           "protocols": ["TCP", "UDP"]},
    912:   {"service": "VMware Auth",             "protocols": ["TCP", "UDP"]},
    989:   {"service": "FTPS",                    "protocols": ["TCP"]},
    990:   {"service": "FTPS",                    "protocols": ["TCP"]},
    993:   {"service": "IMAP over SSL",           "protocols": ["TCP"]},
    995:   {"service": "POP3 over SSL",           "protocols": ["TCP", "UDP"]},
    3306:  {"service": "MySQL",                   "protocols": ["TCP"]},
    3389:  {"service": "RDP (Remote Desktop)",    "protocols": ["TCP", "UDP"]},
    5432:  {"service": "PostgreSQL",              "protocols": ["TCP"]},
    5900:  {"service": "VNC",                     "protocols": ["TCP"]},
    6379:  {"service": "Redis",                   "protocols": ["TCP"]},
    8080:  {"service": "HTTP Alternate",          "protocols": ["TCP"]},
    8443:  {"service": "HTTPS Alternate",         "protocols": ["TCP"]},
    27017: {"service": "MongoDB",                 "protocols": ["TCP"]},
}

SERVICE_META = {
    "web":      {"color": "green",   "label": "Web",      "services": ["HTTP", "HTTPS", "Gopher"]},
    "email":    {"color": "magenta", "label": "Email",    "services": ["SMTP", "POP3", "IMAP", "NNTP"]},
    "file":     {"color": "yellow",  "label": "File",     "services": ["FTP", "FTP-data", "FTPS", "AFP", "rsync", "TFTP"]},
    "network":  {"color": "cyan",    "label": "Network",  "services": ["DNS", "DHCP", "NTP", "BGP", "RIP", "SNMP"]},
    "windows":  {"color": "blue",    "label": "Windows",  "services": ["Microsoft", "NetBIOS", "MS Exchange"]},
    "security": {"color": "red",     "label": "Security", "services": ["SSH", "Kerberos", "IPSec", "LDAP", "TACACS"]},
    "database": {"color": "yellow",  "label": "Database", "services": ["MySQL", "PostgreSQL", "MongoDB", "Redis"]},
    "remote":   {"color": "red",     "label": "Remote",   "services": ["RDP", "VNC", "Telnet", "rlogin", "rexec"]},
    "vmware":   {"color": "white",   "label": "VMware",   "services": ["VMware"]},
}

SSL_PORTS = {443, 465, 636, 993, 995, 990, 989, 8443}

# Notable CVEs per port — shown in the Analysis tab
PORT_CVES = {
    21:    [("CVE-2011-2523", "vsftpd 2.3.4 backdoor"), ("CVE-2010-4221", "ProFTPD remote code exec")],
    22:    [("CVE-2018-10933", "libssh auth bypass"), ("CVE-2023-38408", "OpenSSH agent hijack")],
    23:    [("CVE-2020-10188", "Telnet remote code exec")],
    25:    [("CVE-2020-7247",  "OpenSMTPD remote exec")],
    80:    [("CVE-2021-41773", "Apache path traversal"), ("CVE-2017-5638", "Apache Struts RCE")],
    135:   [("CVE-2003-0352",  "MS RPC DCOM buffer overflow (Blaster worm)")],
    139:   [("CVE-2017-0144",  "EternalBlue / WannaCry")],
    443:   [("CVE-2014-0160",  "Heartbleed OpenSSL"), ("CVE-2021-44228", "Log4Shell via HTTPS")],
    445:   [("CVE-2017-0144",  "EternalBlue / WannaCry"), ("CVE-2020-0796", "SMBGhost")],
    3306:  [("CVE-2012-2122",  "MySQL auth bypass"), ("CVE-2016-6662", "MySQL remote code exec")],
    3389:  [("CVE-2019-0708",  "BlueKeep RDP RCE"), ("CVE-2019-1182", "DejaBlue RDP RCE")],
    5432:  [("CVE-2019-9193",  "PostgreSQL COPY TO/FROM PROGRAM RCE")],
    5900:  [("CVE-2015-5239",  "VNC integer overflow"), ("CVE-2019-15678", "TigerVNC heap overflow")],
    6379:  [("CVE-2022-0543",  "Redis Lua sandbox escape")],
    8080:  [("CVE-2021-41773", "Apache path traversal (alt port)")],
    27017: [("CVE-2015-7882",  "MongoDB auth bypass"), ("CVE-2013-2132", "MongoDB NULL pointer deref")],
}
