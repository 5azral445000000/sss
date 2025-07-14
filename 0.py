from mitmproxy import http
from mitmproxy import ctx
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
import requests
import base64
import time
import re
import hashlib
import threading
import logging
from urllib.parse import urlparse
import asyncio
import urllib3
import socks
import socket
from fake_useragent import UserAgent

# Global SOCKS5 Tor proxy
socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
socket.socket = socks.socksocket

# Disable cert warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Logger setup
logging.basicConfig(level=logging.INFO, format='[VTX] %(message)s')
logger = logging.getLogger("vtx")

VT_API_KEYS = [""]  # Primary VT key(s)
VT_SECONDARY_KEY = ""  # Use this for file/download-only checks
GSB_API_KEY = ""
TIMEOUT = 5
ua = UserAgent()

AD_PATTERNS = ["doubleclick", "googlesyndication", "ads.", "/ads?", "tracker.", "pixel.", "analytics"]

def get_spoofed_headers():
    return {
        "User-Agent": ua.random,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close"
    }

def is_tracker_or_ad(url):
    return any(pat in url.lower() for pat in AD_PATTERNS)

def hash_str(s): 
    return hashlib.sha256(s.encode()).hexdigest()

def vt_check(url, api_key):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        headers = {"x-apikey": api_key}
        headers.update(get_spoofed_headers())
        r = requests.get(analysis_url, headers=headers, timeout=5, verify=False)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0
    except Exception:
        pass
    return None

def check_virustotal(url):
    for api_key in VT_API_KEYS:
        if not api_key:
            continue
        vt = vt_check(url, api_key)
        if vt is not None:
            return vt
    return None

def check_gsb(url):
    if not GSB_API_KEY:
        return None
    gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": {"clientId": "edu-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        headers = get_spoofed_headers()
        r = requests.post(gsb_url, headers=headers, json=payload, timeout=5, verify=False)
        return r.status_code == 200 and "matches" in r.json()
    except Exception:
        pass
    return None

SAFE_BLOCK_HTML = """
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Blocked by VTX Antivirus</title>
<style>body{background:#181818;color:#fff;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.box{background:#222;padding:32px;border-radius:12px;box-shadow:0 6px 24px #0008;text-align:center}h1{color:#ff0}.danger{color:#f00;font-size:1.2em}.tip{color:#0ff;margin-top:1.6em}button{margin-top:2em;padding:12px 30px;font-weight:bold;background:#f00;border:none;color:white;border-radius:6px;cursor:pointer}</style>
</head><body><div class="box"><h1>VTX Antivirus: VIRUS ALERT</h1>
<div class="danger">Malicious content detected.<br>Access blocked for your safety.</div>
<div class="tip">Go back or proceed at your own risk.</div>
<button onclick="window.location.href='about:blank'">Go Back</button></div></body></html>
"""

class VTXAntivirusOverlay:
    def __init__(self):
        self.vt_cache = {}
        self.lock = threading.Lock()

    def scan_virus(self, url, urlid, download_scan=False):
        # Use secondary key if download scan
        vt = vt_check(url, VT_SECONDARY_KEY if download_scan else VT_API_KEYS[0]) if download_scan and VT_SECONDARY_KEY else check_virustotal(url)
        if vt is None and not download_scan:
            vt = check_gsb(url)
        with self.lock:
            self.vt_cache[urlid] = vt
        return vt

    def block_download(self, flow):
        flow.response.headers["Content-Disposition"] = "inline; filename=blocked.txt"
        flow.response.content = b"Virus detected in file download, blocked by VTX."
        flow.response.status_code = 403

    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        content_type = flow.response.headers.get("content-type", "").lower()
        is_html = "text/html" in content_type
        content_disp = flow.response.headers.get("content-disposition", "").lower()
        is_download = "attachment" in content_disp or "filename=" in content_disp
        urlid = hash_str(url)

        # Ad/tracker blocking
        if is_tracker_or_ad(url):
            ctx.log.info(f"[VTX] Tracker/Ad blocked: {url}")
            flow.response.text = "<html><body><h2>Ad/Tracker blocked by VTX</h2></body></html>"
            flow.response.headers["content-type"] = "text/html"
            flow.response.status_code = 403
            return

        # Skip cache for downloads: always check with secondary key
        if is_download:
            ctx.log.info(f"[VTX] Download detected: {url}")
            result = self.scan_virus(url, urlid, download_scan=True)
            if result:
                ctx.log.warn(f"[VTX] File download is malicious: {url}")
                self.block_download(flow)
            else:
                ctx.log.info(f"[VTX] File download is clean: {url}")
            return

        # Check cached result or scan normally
        virus_detected = self.vt_cache.get(urlid, None)
        if virus_detected is None:
            t = threading.Thread(target=self.scan_virus, args=(url, urlid))
            t.start()
            t.join(TIMEOUT)
            virus_detected = self.vt_cache.get(urlid, None)

        if virus_detected is True:
            ctx.log.warn(f"[VTX] VIRUS ALERT: {url}")
            if is_html:
                flow.response.text = SAFE_BLOCK_HTML
                flow.response.headers["content-type"] = "text/html; charset=utf-8"
            else:
                self.block_download(flow)
            return

        ctx.log.info(f"[VTX] Clean: {url}")

addons = [VTXAntivirusOverlay()]

async def main():
    opts = Options(
        listen_host="0.0.0.0",
        listen_port=8080,
        ssl_insecure=True,
        confdir="/home/ntb/certs"
    )
    m = DumpMaster(options=opts)
    for addon in addons:
        m.addons.add(addon)

    print("[VTX] Running VTX Antivirus Proxy on http://0.0.0.0:8080")
    try:
        await m.run()
    except KeyboardInterrupt:
        print("[VTX] Shutting down")
        await m.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
