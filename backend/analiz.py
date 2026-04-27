import re
from database import get_db

# ─────────────────────────────────────────────
# SERVİS HARİTASI
# Nmap servis adı / banner kelimesi → DB service adı
# Kesin eşleştirme, tahmin yok.
# ─────────────────────────────────────────────

# Nmap servis adından DB servisine (port adı kesin biliniyorsa)
NMAP_SERVICE_MAP = {
    "ssh":           ["openssh"],
    "ftp":           ["vsftpd", "proftpd"],
    "ftps":          ["vsftpd", "proftpd"],
    "smtp":          ["postfix", "exim"],
    "smtps":         ["postfix", "exim"],
    "domain":        ["dnsmasq"],
    "microsoft-ds":  ["microsoft-ds"],
    "netbios-ssn":   ["samba"],
    "ms-wbt-server": ["ms-wbt-server"],
    "rdp":           ["ms-wbt-server"],
    "mysql":         ["mysqld"],
    "postgresql":    ["postgres"],
    "redis":         ["redis"],
    "mongodb":       ["mongod"],
    "telnet":        ["telnetd"],
    "ajp13":         ["tomcat"],
    "ajp":           ["tomcat"],
}

# Banner'dan ürün tespiti — kesin ürün adı eşleştirmesi
# Her giriş: (aranacak_kelime, DB_service, versiyon_prefix_kontrolü)
# versiyon_prefix_kontrolü: banner'da bu kelimeden sonra gelen versiyonu al
BANNER_PRODUCT_MAP = [
    ("vsftpd",          "vsftpd"),
    ("proftpd",         "proftpd"),
    ("openssh",         "openssh"),
    ("apache tomcat",   "tomcat"),
    ("tomcat",          "tomcat"),
    ("apache httpd",    "http_server"),
    ("apache/",         "http_server"),
    ("nginx/",          "nginx"),
    ("nginx",           "nginx"),
    ("postfix",         "postfix"),
    ("exim",            "exim"),
    ("dnsmasq",         "dnsmasq"),
    ("named",           "named"),
    ("bind",            "named"),
    ("mysql",           "mysqld"),
    ("mariadb",         "mysqld"),
    ("postgresql",      "postgres"),
    ("redis",           "redis"),
    ("mongodb",         "mongod"),
    ("wordpress",       "wordpress"),
    ("microsoft-iis",   "http_server"),
    ("samba",           "samba"),
]


# ─────────────────────────────────────────────
# VERSİYON PARSE
# ─────────────────────────────────────────────

def parse_version(ver_str):
    """
    Versiyon stringini integer tuple'a çevirir.
    "2.4.49" → (2, 4, 49)
    "7.9p1"  → (7, 9, 1)
    Başarısız olursa None döner.
    """
    if not ver_str or ver_str.strip() in ("*", "-", "?", ""):
        return None
    nums = re.findall(r'\d+', ver_str)
    if not nums:
        return None
    return tuple(int(n) for n in nums[:4])


def extract_version_from_banner(banner):
    """
    Nmap banner'ından versiyon numarasını çıkar.
    "OpenSSH 7.9p1 Debian" → "7.9"
    "dnsmasq-2.45"         → "2.45"
    "Apache/2.4.49"        → "2.4.49"
    """
    if not banner:
        return None
    # x.y.z veya x.y formatını yakala
    m = re.search(r'(\d+\.\d+(?:\.\d+)*)', banner)
    return m.group(1) if m else None


# ─────────────────────────────────────────────
# SERVİS TESPİTİ
# ─────────────────────────────────────────────

def detect_services(nmap_service, banner):
    """
    Nmap servis adı ve banner'dan DB servis adlarını tespit et.
    Önce banner'a bak (daha güvenilir), sonra servis adına.

    Dönüş: list of str (DB service adları)
    """
    services = []

    # 1. Banner'dan kesin ürün tespiti
    if banner:
        banner_lower = banner.lower()
        for keyword, db_service in BANNER_PRODUCT_MAP:
            if keyword in banner_lower:
                if db_service not in services:
                    services.append(db_service)
                break  # İlk eşleşmede dur, birden fazla ürün ekleme

    # 2. Banner'dan tespit yapılamadıysa servis adına bak
    if not services and nmap_service in NMAP_SERVICE_MAP:
        services = NMAP_SERVICE_MAP[nmap_service].copy()

    return services


# ─────────────────────────────────────────────
# VERSİYON ARALIK KONTROLÜ
# ─────────────────────────────────────────────

def version_in_range(detected_str, v_start_str, v_end_str, v_exact_str):
    """
    Tespit edilen versiyon, CVE'nin kapsadığı aralıkta mı?

    KURAL 1: detected_str None ise → eşleşme YOK (False döner)
             Versiyon bilinmiyorsa hiç CVE atama.

    KURAL 2: v_start veya v_end varsa → matematiksel aralık kontrolü.
             v_start <= detected <= v_end

    KURAL 3: v_exact = "*" ve aralık yoksa → detected varsa eşleşir.

    KURAL 4: v_exact belirli bir versiyonsa → prefix eşleştirme.
             DB: 2.4 → hedef: 2.4.49 eşleşir
             DB: 2.4 → hedef: 2.5.0 eşleşmez
    """
    # KURAL 1: Versiyon bilinmiyorsa eşleşme yok
    if detected_str is None:
        return False

    detected = parse_version(detected_str)
    if detected is None:
        return False

    # KURAL 2: Aralık kontrolü
    if v_start_str or v_end_str:
        v_start = parse_version(v_start_str)
        v_end = parse_version(v_end_str)
        if v_start and detected < v_start:
            return False
        if v_end and detected > v_end:
            return False
        return True

    # KURAL 3: Wildcard — versiyon varsa eşleşir
    if not v_exact_str or v_exact_str == "*":
        return True

    # KURAL 4: Tek versiyon — prefix eşleştirme
    v_exact = parse_version(v_exact_str)
    if v_exact is None:
        return True
    min_len = min(len(v_exact), len(detected))
    return v_exact[:min_len] == detected[:min_len]


# ─────────────────────────────────────────────
# CVE SORGULAMA
# ─────────────────────────────────────────────

def query_cves(cur, db_service, detected_version):
    """
    Belirli bir servis için CVE'leri sorgula ve versiyon filtrele.
    detected_version None ise boş liste döner (KURAL 1).
    """
    if detected_version is None:
        return []

    cur.execute("""
        SELECT id, version, version_start, version_end,
               severity, cvss_score, description
        FROM cves
        WHERE LOWER(service) = ?
        ORDER BY cvss_score DESC
    """, (db_service.lower(),))

    results = []
    for r in cur.fetchall():
        r = dict(r)
        if version_in_range(
            detected_version,
            r.get("version_start"),
            r.get("version_end"),
            r.get("version"),
        ):
            results.append({
                "id":          r["id"],
                "severity":    r["severity"],
                "cvss_score":  r["cvss_score"] or 0.0,
                "description": r["description"] or "",
            })
    return results


# ─────────────────────────────────────────────
# RİSK SKORU
# ─────────────────────────────────────────────

def calculate_port_risk(cves):
    """Port risk skoru = en yüksek CVSS skoru. Bonus yok."""
    if not cves:
        return 0.0
    return round(max(c["cvss_score"] for c in cves), 1)


# ─────────────────────────────────────────────
# ANA ANALİZ FONKSİYONLARI
# ─────────────────────────────────────────────

def analyze_ports(ports):
    conn = get_db()
    cur = conn.cursor()
    results = []
    total_score = 0.0

    for p in ports:
        nmap_service    = p.get("service", "").lower().strip()
        banner          = p.get("version", "").strip()
        detected_version = extract_version_from_banner(banner)

        db_services = detect_services(nmap_service, banner)

        all_cves = []
        seen_ids = set()

        for db_service in db_services:
            for cve in query_cves(cur, db_service, detected_version):
                if cve["id"] not in seen_ids:
                    seen_ids.add(cve["id"])
                    all_cves.append(cve)

        all_cves.sort(key=lambda c: c["cvss_score"], reverse=True)
        port_risk = calculate_port_risk(all_cves)
        total_score += port_risk

        results.append({
            "port":             p["port"],
            "protocol":         p.get("protocol", "tcp"),
            "service":          nmap_service,
            "version":          banner,
            "detected_version": detected_version or "-",
            "cves":             all_cves,
            "risk_score":       port_risk,
        })

    conn.close()
    final_score = round(total_score / max(len(ports), 1), 2) if ports else 0.0
    return results, final_score


def analyze(hosts):
    """
    hosts: { "192.168.1.1": {"hostname": "...", "ports": [...]}, ... }
    """
    analyzed_hosts = {}
    all_scores = []

    for ip, data in hosts.items():
        ports    = data.get("ports", [])
        hostname = data.get("hostname", "")

        port_results, risk_score = analyze_ports(ports)

        analyzed_hosts[ip] = {
            "ip":        ip,
            "hostname":  hostname,
            "ports":     port_results,
            "risk_score": risk_score,
        }
        all_scores.append(risk_score)

    # Genel skor: en yüksek 3 host'un ortalaması
    top3 = sorted(all_scores, reverse=True)[:3]
    overall = round(sum(top3) / max(len(top3), 1), 2) if top3 else 0.0

    return {
        "hosts":      analyzed_hosts,
        "risk_score": overall,
    }