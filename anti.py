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
import random
from stem import Signal
from stem.control import Controller

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format='[VTX] %(message)s')
logger = logging.getLogger("vtx")

VT_API_KEYS = [
    ""
]
GSB_API_KEY = ""

TIMEOUT = 5

TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_PASSWORD = "your_password"  # Set this in your torrc and here

# Common ad and tracker domains/patterns (expand as needed)
AD_TRACKER_PATTERNS = [
    "doubleclick.net", "adservice.google.com", "adserver.", "googlesyndication.", "ads.", "pixel.", "tracking.",
    "facebook.com/tr/", "analytics.", "googletagmanager.", "scorecardresearch.com", "quantserve.com", "adnxs.com",
    "criteo.com", "taboola.com", "outbrain.com", "clickserve.", "bidswitch.net", "bluekai.com",
]

def hash_str(s): 
    return hashlib.sha256(s.encode()).hexdigest()

def is_ad_or_tracker(url):
    for pattern in AD_TRACKER_PATTERNS:
        if pattern in url:
            return True
    return False

def get_random_useragent():
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"
    ]
    return random.choice(agents)

def renew_tor_ip():
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate(password=TOR_PASSWORD)
            controller.signal(Signal.NEWNYM)
            logger.info("[VTX] Tor IP renewed (NEWNYM signal sent).")
    except Exception as e:
        logger.error(f"[VTX] Error renewing Tor IP: {e}")

def tor_session():
    session = requests.Session()
    session.proxies = {
        'http': f'socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}',
        'https': f'socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}',
    }
    return session

def tor_request(method, url, **kwargs):
    session = tor_session()
    try:
        return session.request(method, url, timeout=5, verify=False, **kwargs)
    except Exception as e:
        logger.info(f"Tor request error: {e}")
        return None

def check_virustotal(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    for api_key in VT_API_KEYS:
        if not api_key:
            continue
        try:
            headers = {"x-apikey": api_key}
            r = tor_request("GET", analysis_url, headers=headers)
            if r and r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious > 0 or suspicious > 0:
                    return True
                else:
                    return False
            elif r and r.status_code == 429:
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
        r = tor_request("POST", gsb_url, json=payload)
        if r and r.status_code == 200:
            data = r.json()
            if "matches" in data:
                return True
            else:
                return False
    except Exception:
        pass
    return None

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
        self.last_ip_renew = time.time()

    def scan_virus(self, url, urlid):
        # Periodically renew Tor IP (every 10 min)
        if time.time() - self.last_ip_renew > 600:
            renew_tor_ip()
            self.last_ip_renew = time.time()
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

    def request(self, flow: http.HTTPFlow):
        # Mask client IP in headers
        flow.request.headers["X-Forwarded-For"] = "127.0.0.1"
        flow.request.headers["X-Real-IP"] = "127.0.0.1"
        # Hide/munge User-Agent
        flow.request.headers["User-Agent"] = get_random_useragent()
        # Block known ads/trackers
        if is_ad_or_tracker(flow.request.pretty_url):
            ctx.log.info(f"Blocked ad/tracker: {flow.request.pretty_url}")
            flow.response = http.HTTPResponse.make(
                403, b"Blocked by VTX Antivirus: Ad/Tracker Domain", {"Content-Type": "text/plain"}
            )
            return

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

        # Ad/tracker blocking in response (e.g. HTML/script injection)
        if is_html and is_ad_or_tracker(url):
            flow.response.text = "<!-- Blocked Ad/Tracker by VTX Antivirus -->"
            flow.response.headers["content-type"] = "text/html; charset=utf-8"
            ctx.log.info(f"[VTX] Blocked ad/tracker in response: {url}")
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
    asyncio.run(main())
