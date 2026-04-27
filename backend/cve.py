import requests
from database import get_db

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def extract_cpe(cpe_str):
    parts = cpe_str.split(":")
    if len(parts) >= 6:
        return parts[3], parts[4], parts[5]
    return None, None, None

def fetch_all_cves():
    start = 0
    per_page = 2000
    total_inserted = 0

    conn = get_db()
    cur = conn.cursor()

    print("CVE veritabani dolduruluyor...")

    while True:
        url = f"{BASE_URL}?resultsPerPage={per_page}&startIndex={start}"
        print(f"  Indiriliyor: startIndex={start}")
        try:
            res = requests.get(url, timeout=60)
            data = res.json()
        except Exception as e:
            print(f"  Hata: {e}")
            break

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print("  Daha fazla kayit yok, tamamlandi.")
            break

        for v in vulns:
            cve = v["cve"]
            cve_id = cve["id"]

            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d["lang"] == "en"), "")

            metrics = cve.get("metrics", {})
            severity = "Unknown"
            score = 0.0

            if "cvssMetricV31" in metrics:
                m = metrics["cvssMetricV31"][0]["cvssData"]
                severity = m["baseSeverity"]
                score = m["baseScore"]
            elif "cvssMetricV30" in metrics:
                m = metrics["cvssMetricV30"][0]["cvssData"]
                severity = m["baseSeverity"]
                score = m["baseScore"]
            elif "cvssMetricV2" in metrics:
                m = metrics["cvssMetricV2"][0]["cvssData"]
                severity = metrics["cvssMetricV2"][0].get("baseSeverity", "Unknown")
                score = m["baseScore"]

            published = cve.get("published", "")

            configurations = cve.get("configurations", [])
            for conf in configurations:
                for node in conf.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable"):
                            cpe = match["criteria"]
                            vendor, product, version = extract_cpe(cpe)
                            if not product:
                                continue

                            version_start = match.get("versionStartIncluding") or match.get("versionStartExcluding") or None
                            version_end = match.get("versionEndIncluding") or match.get("versionEndExcluding") or None

                            # Tek versiyon varsa version_start ve version_end aynı olsun
                            if version and version != "*" and not version_start and not version_end:
                                version_start = version
                                version_end = version

                            cur.execute("""
                                INSERT OR IGNORE INTO cves
                                (id, service, version, version_start, version_end, severity, cvss_score, description, published_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                cve_id,
                                product.lower(),
                                version if version else "*",
                                version_start,
                                version_end,
                                severity,
                                score,
                                desc,
                                published,
                            ))
                            total_inserted += 1

        conn.commit()
        start += per_page

        total_results = data.get("totalResults", 0)
        if start >= total_results:
            print(f"  Tum kayitlar indirildi. Toplam: {total_results}")
            break

    conn.close()
    print(f"Tamamlandi. Eklenen kayit sayisi: {total_inserted}")

if __name__ == "__main__":
    fetch_all_cves()