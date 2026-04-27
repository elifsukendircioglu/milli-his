from database import get_db

# (cve_id, service, version, version_start, version_end, severity, cvss_score, description)
SEED_CVES = [
    # ─── APACHE HTTP SERVER ───
    ("CVE-2021-41773", "http_server", "2.4.49",  "2.4.49",  "2.4.49",  "Critical", 9.8,  "Apache 2.4.49'da path traversal ve RCE acigi."),
    ("CVE-2021-42013", "http_server", "2.4.50",  "2.4.50",  "2.4.50",  "Critical", 9.8,  "Apache 2.4.50'de CVE-2021-41773 yamasinin bypass edilmesi."),
    ("CVE-2017-7679",  "http_server", "2.2.34",  "2.0.0",   "2.2.34",  "Critical", 9.8,  "Apache mod_mime buffer overflow acigi."),
    ("CVE-2017-7678",  "http_server", "2.2.34",  "2.0.0",   "2.2.34",  "Medium",   5.3,  "Apache mod_http2 XSS acigi."),
    ("CVE-2022-31813", "http_server", "*",        None,      None,      "High",     7.5,  "Apache HTTP Server X-Forwarded-For header bypass."),
    ("CVE-2019-0211",  "http_server", "*",        "2.4.0",   "2.4.38",  "High",     7.8,  "Apache HTTP Server privilege escalation acigi."),
    ("CVE-2007-3847",  "http_server", "2.2.4",   "2.0.0",   "2.2.4",   "Medium",   5.0,  "Apache mod_proxy DoS acigi."),
    ("CVE-2006-3747",  "http_server", "2.0.58",  "2.0.0",   "2.0.58",  "Critical", 9.3,  "Apache mod_rewrite off-by-one buffer overflow."),

    # ─── OPENSSH ───
    ("CVE-2023-38408", "openssh",     "*",        None,      "9.3",     "Critical", 9.8,  "OpenSSH ssh-agent remote code execution acigi."),
    ("CVE-2016-0777",  "openssh",     "7.1",      "5.4",     "7.1",     "Medium",   6.5,  "OpenSSH roaming ozelliginde bilgi sizintisi."),
    ("CVE-2018-15473", "openssh",     "*",        None,      "7.7",     "Medium",   5.3,  "OpenSSH kullanici adi enumeration acigi."),
    ("CVE-2019-6111",  "openssh",     "7.9",      None,      "7.9",     "Medium",   5.9,  "OpenSSH scp arbitrary file overwrite acigi."),
    ("CVE-2021-28041", "openssh",     "8.3",      "8.2",     "8.3",     "High",     7.1,  "OpenSSH double-free memory corruption."),
    ("CVE-2006-5051",  "openssh",     "4.3",      "1.0",     "4.3",     "High",     7.6,  "OpenSSH signal handler race condition."),
    ("CVE-2002-0083",  "openssh",     "3.1",      "1.0",     "3.1",     "Critical", 10.0, "OpenSSH integer overflow uzaktan kod calistirma."),

    # ─── NGINX ───
    ("CVE-2021-23017", "nginx",       "1.20.0",  "0.6.18",  "1.20.0",  "Critical", 9.4,  "Nginx DNS resolver buffer overflow acigi."),
    ("CVE-2017-7529",  "nginx",       "1.12.1",  "0.5.6",   "1.12.1",  "Medium",   5.3,  "Nginx integer overflow ile bellek bilgisi ifsasi."),
    ("CVE-2019-9511",  "nginx",       "*",        None,      "1.17.2",  "High",     7.5,  "Nginx HTTP/2 DoS (Data Dribble) acigi."),
    ("CVE-2019-9513",  "nginx",       "*",        None,      "1.17.2",  "High",     7.5,  "Nginx HTTP/2 Resource Loop DoS acigi."),
    ("CVE-2013-2028",  "nginx",       "1.4.0",   "1.3.9",   "1.4.0",   "Critical", 9.8,  "Nginx stack-based buffer overflow."),
    ("CVE-2016-0747",  "nginx",       "1.9.9",   "0.6.18",  "1.9.9",   "Medium",   5.3,  "Nginx resolver ile CNAME kayit DoS."),

    # ─── VSFTPD ───
    ("CVE-2011-2523",  "vsftpd",      "2.3.4",   "2.3.4",   "2.3.4",   "Critical", 10.0, "vsftpd 2.3.4 backdoor uzaktan shell acigi."),
    ("CVE-2021-3618",  "vsftpd",      "*",        None,      None,      "High",     7.4,  "vsftpd ALPACA saldirisina acik FTP."),

    # ─── SAMBA ───
    ("CVE-2017-7494",  "samba",       "4.6.3",   "3.5.0",   "4.6.3",   "Critical", 9.8,  "Samba SambaCry uzaktan kod calistirma acigi."),
    ("CVE-2012-1182",  "samba",       "3.6.3",   "3.0.0",   "3.6.3",   "Critical", 10.0, "Samba remote heap overflow acigi."),
    ("CVE-2021-44142", "samba",       "*",        None,      "4.15.2",  "Critical", 9.9,  "Samba vfs_fruit modulunde out-of-bounds write."),
    ("CVE-2020-1472",  "samba",       "*",        None,      None,      "Critical", 10.0, "Zerologon - Netlogon privilege escalation."),
    ("CVE-2018-1057",  "samba",       "4.7.6",   "4.0.0",   "4.7.6",   "High",     8.8,  "Samba AD DC sifre degistirme acigi."),
    ("CVE-2016-2118",  "samba",       "4.4.0",   "3.6.0",   "4.4.0",   "High",     7.5,  "Samba SAMR ve LSA man-in-the-middle acigi (BADLOCK)."),

    # ─── MYSQL / MARIADB ───
    ("CVE-2016-6662",  "mysqld",      "5.7.15",  "5.5.0",   "5.7.15",  "Critical", 9.8,  "MySQL uzaktan kod calistirma acigi (my.cnf inject)."),
    ("CVE-2016-6663",  "mysqld",      "5.7.15",  "5.5.0",   "5.7.15",  "High",     7.0,  "MySQL yerel privilege escalation acigi."),
    ("CVE-2012-2122",  "mysqld",      "5.5.29",  "5.1.0",   "5.5.29",  "High",     7.5,  "MySQL kimlik dogrulama bypass acigi."),
    ("CVE-2021-27928", "mysqld",      "*",        None,      "10.5.9",  "High",     7.2,  "MariaDB/MySQL wsrep uzaktan kod calistirma."),
    ("CVE-2023-21980", "mysqld",      "8.0.32",  "8.0.0",   "8.0.32",  "High",     7.1,  "MySQL Client uzaktan kod calistirma acigi."),

    # ─── POSTGRESQL ───
    ("CVE-2019-10164", "postgres",    "11.3",    "10.0",    "11.3",    "Critical", 9.8,  "PostgreSQL stack overflow uzaktan kod calistirma."),
    ("CVE-2016-5423",  "postgres",    "9.5.3",   "9.1.0",   "9.5.3",   "High",     8.3,  "PostgreSQL nested CASE ifadelerinde bellek bozulmasi."),
    ("CVE-2018-10915", "postgres",    "10.4",    "9.3.0",   "10.4",    "High",     8.8,  "PostgreSQL dblink modulu guvenlik bypass."),

    # ─── PROFTPD ───
    ("CVE-2010-4221",  "proftpd",     "1.3.3",   "1.3.0",   "1.3.3",   "Critical", 10.0, "ProFTPD telnet IAC stack overflow uzaktan RCE."),
    ("CVE-2019-12815", "proftpd",     "1.3.6",   "1.3.0",   "1.3.6",   "Critical", 9.8,  "ProFTPD mod_copy kimlik dogrulamasiz dosya kopyalama."),
    ("CVE-2011-4130",  "proftpd",     "1.3.3",   "1.3.0",   "1.3.3",   "Critical", 9.0,  "ProFTPD use-after-free uzaktan kod calistirma."),

    # ─── TELNET ───
    ("CVE-2020-10188", "telnetd",     "*",        None,      None,      "Critical", 9.8,  "telnetd uzaktan buffer overflow acigi."),
    ("CVE-2001-0554",  "telnetd",     "*",        None,      None,      "High",     7.5,  "BSD telnetd buffer overflow uzaktan RCE."),

    # ─── BIND / DNS ───
    ("CVE-2020-8617",  "named",       "9.16.2",  "9.0.0",   "9.16.2",  "High",     7.5,  "BIND named TSIG kayitinda DoS acigi."),
    ("CVE-2016-2776",  "named",       "9.11.0",  "9.0.0",   "9.11.0",  "High",     7.5,  "BIND named buffer.c assertion failure DoS."),
    ("CVE-2021-25216", "named",       "9.16.11", "9.0.0",   "9.16.11", "Critical", 9.8,  "BIND GSSAPI guvenlik bypass ve RCE acigi."),
    ("CVE-2015-5477",  "named",       "*",        None,      "9.10.2",  "High",     7.8,  "BIND TKEY sorgusu ile uzaktan DoS."),

    # ─── DNSMASQ ───
    ("CVE-2020-25681", "dnsmasq",     "2.82",    "2.0",     "2.82",    "Critical", 8.1,  "dnsmasq DNS yanitinda heap buffer overflow (DNSpooq)."),
    ("CVE-2020-25682", "dnsmasq",     "2.82",    "2.0",     "2.82",    "Critical", 8.1,  "dnsmasq DHCP6 isteginde buffer overflow (DNSpooq)."),
    ("CVE-2020-25683", "dnsmasq",     "2.82",    "2.0",     "2.82",    "High",     5.9,  "dnsmasq heap-based buffer overflow acigi."),
    ("CVE-2017-14491", "dnsmasq",     "2.78",    "2.0",     "2.78",    "Critical", 9.8,  "dnsmasq DNS yanitinda heap overflow RCE."),
    ("CVE-2017-14492", "dnsmasq",     "2.78",    "2.0",     "2.78",    "Critical", 9.8,  "dnsmasq DHCP6 heap overflow acigi."),

    # ─── EXIM ───
    ("CVE-2019-10149", "exim",        "4.91",    "4.87",    "4.91",    "Critical", 9.8,  "Exim deliver_message() uzaktan kod calistirma."),
    ("CVE-2020-28017", "exim",        "4.94",    "4.0",     "4.94",    "Critical", 9.8,  "Exim receive_add_recipient heap overflow."),
    ("CVE-2021-38371", "exim",        "*",        None,      "4.94.2",  "Medium",   5.9,  "Exim STARTTLS MITM acigi."),

    # ─── REDIS ───
    ("CVE-2022-0543",  "redis",       "6.2.6",   "6.0.0",   "6.2.6",   "Critical", 10.0, "Redis Lua sandbox escape ile uzaktan kod calistirma."),
    ("CVE-2021-32761", "redis",       "6.2.4",   "6.0.0",   "6.2.4",   "High",     7.5,  "Redis 32-bit sistemlerde integer overflow."),
    ("CVE-2023-28425", "redis",       "7.0.9",   "7.0.0",   "7.0.9",   "Medium",   5.5,  "Redis MSETNX ile denial of service acigi."),

    # ─── MONGODB ───
    ("CVE-2019-2392",  "mongod",      "4.2.1",   "4.0.0",   "4.2.1",   "Medium",   6.5,  "MongoDB aggregation asamasinda bellek bozulmasi."),
    ("CVE-2021-20328", "mongod",      "4.4.3",   "4.4.0",   "4.4.3",   "Medium",   6.8,  "MongoDB sifreleme dogrulama eksikligi."),

    # ─── WORDPRESS ───
    ("CVE-2022-21661", "wordpress",   "5.8.2",   "3.7.0",   "5.8.2",   "High",     8.8,  "WordPress SQL injection acigi (WP_Query)."),
    ("CVE-2019-8942",  "wordpress",   "5.0.0",   "3.9.0",   "5.0.0",   "High",     8.8,  "WordPress uzaktan kod calistirma (meta bilgisi ile)."),
    ("CVE-2021-29447", "wordpress",   "5.6.2",   "5.6.0",   "5.6.2",   "Medium",   6.5,  "WordPress XXE ile dosya okuma acigi."),

    # ─── TOMCAT ───
    ("CVE-2020-1938",  "tomcat",      "9.0.30",  "9.0.0",   "9.0.30",  "Critical", 9.8,  "Apache Tomcat AJP connector Ghostcat dosya okuma/RCE."),
    ("CVE-2019-0232",  "tomcat",      "9.0.17",  "9.0.0",   "9.0.17",  "Critical", 9.8,  "Apache Tomcat Windows CGI servlet RCE acigi."),
    ("CVE-2017-12617", "tomcat",      "8.5.22",  "8.5.0",   "8.5.22",  "High",     8.1,  "Apache Tomcat JSP dosyasi yukleme ile RCE."),
    ("CVE-2016-8735",  "tomcat",      "8.5.8",   "8.5.0",   "8.5.8",   "Critical", 9.8,  "Apache Tomcat JMX RMI deserialization RCE."),

    # ─── SPRING ───
    ("CVE-2022-22965", "spring",      "*",        None,      "5.3.17",  "Critical", 9.8,  "Spring4Shell - Spring Framework RCE acigi."),
    ("CVE-2022-22950", "spring",      "5.3.16",  "5.3.0",   "5.3.16",  "Medium",   6.5,  "Spring Framework DoS acigi."),

    # ─── LOG4J ───
    ("CVE-2021-44228", "log4j",       "2.14.1",  "2.0.0",   "2.14.1",  "Critical", 10.0, "Log4Shell - Log4j2 JNDI injection ile uzaktan RCE."),
    ("CVE-2021-45046", "log4j",       "2.15.0",  "2.0.0",   "2.15.0",  "Critical", 9.0,  "Log4j2 CVE-2021-44228 yamasinin bypass edilmesi."),
    ("CVE-2021-45105", "log4j",       "2.16.0",  "2.0.0",   "2.16.0",  "High",     7.5,  "Log4j2 StackOverflowError DoS acigi."),

    # ─── POSTFIX ───
    ("CVE-2011-1720",  "postfix",     "2.8.2",   "2.0.0",   "2.8.2",   "High",     7.6,  "Postfix SMTP sunucu memory corruption acigi."),

    # ─── RDP ───
    ("CVE-2019-0708",  "ms-wbt-server","*",       None,      None,      "Critical", 9.8,  "BlueKeep - Windows RDP uzaktan kod calistirma."),
    ("CVE-2019-1181",  "ms-wbt-server","*",       None,      None,      "Critical", 9.8,  "DejaBlue - Windows RDP uzaktan kod calistirma."),
    ("CVE-2012-0002",  "ms-wbt-server","*",       None,      None,      "Critical", 9.3,  "MS12-020 Windows RDP uzaktan DoS/kod calistirma."),

    # ─── SMB ───
    ("CVE-2017-0144",  "microsoft-ds","*",        None,      None,      "Critical", 9.3,  "EternalBlue - SMBv1 uzaktan kod calistirma (WannaCry)."),
    ("CVE-2020-0796",  "microsoft-ds","*",        None,      None,      "Critical", 10.0, "SMBGhost - SMBv3 uzaktan kod calistirma acigi."),
    ("CVE-2017-0145",  "microsoft-ds","*",        None,      None,      "Critical", 9.3,  "EternalRomance - SMBv1 RCE acigi."),
]


def seed_cves():
    conn = get_db()
    cur = conn.cursor()

    inserted = 0
    skipped = 0

    for row in SEED_CVES:
        cve_id, service, version, version_start, version_end, severity, cvss_score, description = row
        try:
            cur.execute("""
                INSERT OR IGNORE INTO cves
                (id, service, version, version_start, version_end, severity, cvss_score, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (cve_id, service.lower(), version, version_start, version_end, severity, cvss_score, description))
            if cur.rowcount > 0:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"Hata ({cve_id}): {e}")

    conn.commit()
    conn.close()
    print(f"Tamamlandi: {inserted} eklendi, {skipped} zaten vardi.")


if __name__ == "__main__":
    seed_cves()