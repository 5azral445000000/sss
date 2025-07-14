add to this IP MASKING + ad and TRACKER BLOCKING + USERAGENT hiding             please put real using tor circuit or i dont know put real logic Můžeš použít Tor klienta (Tor Browser nebo systémový Tor daemon), který běží jako speciální proxy na localhostu (většinou port 9050/9051).
from mitmproxy import http
from mitmproxy import ctx
import requests
import base64
import time
import re
import hashlib
import threading
import logging
from urllib.parse import urlparse
import asyncio
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format='[VTX] %(message)s')
logger = logging.getLogger("vtx")

VT_API_KEYS = [
    ""
]
GSB_API_KEY = ""

TIMEOUT = 5

def hash_str(s): 
    return hashlib.sha256(s.encode()).hexdigest()

def check_virustotal(url):
    scan_url = "https://www.virustotal.com/api/v3/urls"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    for api_key in VT_API_KEYS:
        if not api_key:
            continue
        try:
            headers = {"x-apikey": api_key}
            r = requests.get(analysis_url, headers=headers, timeout=2)
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious > 0 or suspicious > 0:
                    return True
                else:
                    return False
            elif r.status_code == 429:
                time.sleep(0.5)
                continue
        except Exception:
            continue
    return None

def check_gsb(url):
    if not GSB_API_KEY:
        return None
    gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": { "clientId": "yourcompanyname", "clientVersion": "1.0" },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [ {"url": url} ]
        }
    }
    try:
        r = requests.post(gsb_url, json=payload, timeout=2)
        if r.status_code == 200:
            data = r.json()
            if "matches" in data:
                return True
            else:
                return False
    except Exception:
        pass
    return None

# This is a *safe* HTML warning page. No original content/scripts/styles are present!
SAFE_BLOCK_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Blocked by VTX Antivirus</title>
    <style>
        body { background:#181818; color:#fff; font-family:monospace; display:flex; flex-direction:column; justify-content:center; align-items:center; height:100vh; margin:0;}
        .box { background:#222; border-radius:12px; padding:38px 38px 32px 38px; box-shadow:0 6px 24px #0008; text-align:center; max-width:560px;}
        h1 { color:#ff0; font-size:2.4rem; margin-bottom:0.7em;}
        .danger { color:#f00; font-weight:bold; font-size:1.3em;}
        button { background:#f00; color:#fff; border:none; border-radius:6px; padding:12px 30px; font-size:1.15em; font-weight:bold; margin-top:2em; cursor:pointer;}
        .tip { color:#0ff; margin-top:1.6em;}
    </style>
</head>
<body>
    <div class="box">
        <h1>&#9888;&#xFE0F; VTX Antivirus: VIRUS ALERT &#9888;&#xFE0F;</h1>
        <div class="danger">This page has been detected as <span>malicious</span>.<br>
        All content is blocked for your safety.</div>
        <div class="tip">It is recommended to <b>go back</b>.<br>
        If you wish, you can proceed at your own risk.</div>
        <button onclick="window.location.href='about:blank'">Go Back</button>
    </div>
</body>
</html>
"""

class VTXAntivirusOverlay:
    def __init__(self):
        self.vt_cache = {}
        self.lock = threading.Lock()

    def scan_virus(self, url, urlid):
        vt = check_virustotal(url)
        if vt is None:
            vt = check_gsb(url)
        with self.lock:
            self.vt_cache[urlid] = vt
        return vt

    def block_download(self, flow):
        flow.response.headers["Content-Disposition"] = "inline; filename=blocked.txt"
        flow.response.content = b"Virus detected in file download, download blocked by VTX Antivirus."
        flow.response.status_code = 403

    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        content_type = flow.response.headers.get("content-type", "").lower()
        is_html = "text/html" in content_type
        content_disp = flow.response.headers.get("content-disposition", "").lower()
        is_download = bool(content_disp and ("attachment" in content_disp or "filename=" in content_disp))
        urlid = hash_str(url)

        virus_detected = self.vt_cache.get(urlid, None)
        if virus_detected is None:
            t = threading.Thread(target=self.scan_virus, args=(url, urlid))
            t.start()
            t.join(TIMEOUT)
            virus_detected = self.vt_cache.get(urlid, None)
        if virus_detected is True:
            ctx.log.info(f"VIRUS ALERT: {url}")
            print(f"[VTX] VIRUS ALERT for {url} (VT/GSB detected)")
            if is_html:
                flow.response.text = SAFE_BLOCK_HTML
                flow.response.headers["content-type"] = "text/html; charset=utf-8"
            else:
                self.block_download(flow)
            return

        ctx.log.info(f"[VTX] Clean page or download: {url}")

addons = [VTXAntivirusOverlay()]

async def main():
    opts = Options(
        listen_host="0.0.0.0",
        listen_port=8080,
        ssl_insecure=True,
        confdir="/home/ntb/Stažené",
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
    asyncio.run(main()) use stem and pysocks
