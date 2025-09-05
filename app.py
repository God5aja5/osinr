#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify
import requests, re, json, socket, ssl, datetime
from urllib.parse import quote
from bs4 import BeautifulSoup

app = Flask(__name__)

REQUEST_TIMEOUT = 15
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SimpleOSINT/1.0)"}

# ---------- Helpers ----------
def safe_get(url, **kwargs):
    try:
        return requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, **kwargs)
    except Exception:
        return None

def unique_str(seq):
    seen = set()
    out = []
    for x in seq:
        if isinstance(x, str) and x not in seen:
            seen.add(x)
            out.append(x)
        elif not isinstance(x, str):  # keep dicts/lists as-is
            out.append(x)
    return out

def parse_date(ts, fmt_in="%b %d %H:%M:%S %Y %Z"):
    try:
        return datetime.datetime.strptime(ts, fmt_in).isoformat()
    except Exception:
        return ts

# ---------- WHOIS ----------
def fetch_whois(domain: str):
    url = f"https://www.whois.com/whois/{domain}"
    r = safe_get(url)
    if not r or r.status_code != 200:
        return {"error": f"Failed to fetch whois page"}

    soup = BeautifulSoup(r.text, "html.parser")
    data = {}
    for row in soup.select(".whois-data .df-row"):
        label = row.select_one(".df-label")
        value = row.select_one(".df-value")
        if not label or not value:
            continue
        key = label.get_text(strip=True).rstrip(":")
        val = value.get_text(" ", strip=True).replace("\n", " ").strip()
        val = re.sub(r"\s{2,}", " ", val)
        data[key] = val

    if "Status" in data:
        data["Status"] = [s.strip() for s in data["Status"].split() if s.strip()]

    if "Name Servers" in data:
        ns_list = [n.strip() for n in re.split(r"[\s,]+", data["Name Servers"]) if "." in n]
        data["Name Servers"] = unique_str(ns_list)

    return data or {"error": "No whois fields parsed."}

# ---------- DNS ----------
def dns_query(domain: str, rrtype: str):
    type_map = {"A":1,"AAAA":28,"CNAME":5,"MX":15,"NS":2,"TXT":16,"SOA":6}
    qtype = type_map.get(rrtype.upper(), 1)
    url = f"https://dns.google/resolve?name={quote(domain)}&type={qtype}"
    r = safe_get(url)
    out = []
    if r and r.ok:
        j = r.json()
        for ans in j.get("Answer", []) or []:
            datum = ans.get("data")
            if not datum:
                continue
            if rrtype.upper() == "MX":
                m = re.match(r"(\d+)\s+(.+)", datum)
                if m:
                    out.append({"preference": int(m.group(1)), "exchange": m.group(2).rstrip(".")})
                else:
                    out.append({"raw": datum})
            elif rrtype.upper() == "TXT":
                out.append(datum.strip('"'))
            else:
                out.append(datum.rstrip("."))
    return out

def fetch_dns_bundle(domain: str):
    return {
        "A": dns_query(domain, "A"),
        "AAAA": dns_query(domain, "AAAA"),
        "NS": dns_query(domain, "NS"),
        "MX": dns_query(domain, "MX"),
        "TXT": dns_query(domain, "TXT"),
        "CNAME": dns_query(domain, "CNAME"),
        "SOA": dns_query(domain, "SOA"),
    }

# ---------- IP Info ----------
def fetch_ip_profile(domain: str):
    r = safe_get(f"https://ipwhois.app/json/{quote(domain)}")
    if not r or not r.ok:
        return {"error": "ipwhois.app lookup failed"}
    return r.json()

# ---------- SSL ----------
def fetch_ssl_info(domain: str, port: int = 443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                sans = [val for typ, val in cert.get("subjectAltName", []) if typ.lower()=="dns"]
                return {
                    "subject_CN": subject.get("commonName"),
                    "issuer_CN": issuer.get("commonName"),
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter"),
                    "SANs": unique_str(sans),
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher(),
                }
    except Exception as e:
        return {"error": str(e)}

# ---------- HTTP ----------
def fetch_http_profile(domain: str):
    info = {}
    for scheme in ("https","http"):
        try:
            r = requests.get(f"{scheme}://{domain}", headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            chain = [{"status": h.status_code, "url": h.url} for h in r.history] + [{"status": r.status_code, "url": r.url}]
            info[scheme] = {
                "final_url": r.url,
                "status": r.status_code,
                "redirect_chain": chain,
                "headers": dict(r.headers),
                "cookies": {c.name:c.value for c in r.cookies}
            }
        except Exception as e:
            info[scheme] = {"error": str(e)}
    return info

# ---------- Main Runner ----------
def run_osint(domain: str):
    report = {"domain": domain, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    report["whois"] = fetch_whois(domain)
    report["dns"] = fetch_dns_bundle(domain)
    report["ip_profile"] = fetch_ip_profile(domain)
    report["ssl"] = fetch_ssl_info(domain)
    report["http"] = fetch_http_profile(domain)
    return report

# ---------- Flask Route ----------
@app.route("/osint")
def osint_api():
    domain = request.args.get("url")
    if not domain:
        return jsonify({"error": "Missing url param ?url=domain.com"}), 400
    result = run_osint(domain.strip())
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
