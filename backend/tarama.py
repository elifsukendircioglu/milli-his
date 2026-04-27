import subprocess
import re


def run_nmap(target):
    try:
        cmd = ["nmap", "-Pn", "-sV", "--open", target]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if res.returncode != 0 and not res.stdout:
            return {"error": f"nmap hatasi: {res.stderr}", "hosts": {}}
        hosts = parse_output(res.stdout)
        return {"error": None, "hosts": hosts}
    except FileNotFoundError:
        return {"error": "nmap bulunamadi. Lutfen yukleyin.", "hosts": {}}
    except subprocess.TimeoutExpired:
        return {"error": "Tarama zaman asimina ugradi.", "hosts": {}}
    except Exception as e:
        return {"error": str(e), "hosts": {}}


def parse_output(out):
    hosts = {}
    current_ip = None
    current_hostname = ""

    for line in out.split("\n"):
        line = line.strip()

        # Host satırı: "Nmap scan report for 192.168.1.5"
        # veya "Nmap scan report for hostname (192.168.1.5)"
        if line.startswith("Nmap scan report for"):
            raw = line.replace("Nmap scan report for ", "").strip()
            ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', raw)
            if ip_match:
                current_ip = ip_match.group(1)
                current_hostname = raw.split("(")[0].strip()
            else:
                current_ip = raw
                current_hostname = ""
            hosts[current_ip] = {"hostname": current_hostname, "ports": []}
            continue

        if current_ip is None:
            continue

        # Port satırı: "22/tcp   open  ssh     OpenSSH 7.9p1"
        port_match = re.search(r"(\d+)/tcp\s+open\s+([\w\-]+)\s*(.*)", line)
        if port_match:
            hosts[current_ip]["ports"].append({
                "port": int(port_match.group(1)),
                "protocol": "tcp",
                "service": port_match.group(2).lower().strip(),
                "version": port_match.group(3).strip(),
            })

    # Portu olmayan hostları temizle
    hosts = {ip: data for ip, data in hosts.items() if data["ports"]}
    return hosts