# -*- coding: utf-8 -*-
import asyncio, re, sys, os, time, json, random, string, threading, base64
from urllib.parse import urljoin, urlparse, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "Aws-Waf-Solver"))

from curl_cffi import requests
from bs4 import BeautifulSoup
import waf.solver as S

import requests as std_requests
from flask import Flask, jsonify

# ============================================
# Config
# ============================================
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "proxy": "http://5vvdu3axlr-mobile.res-country-SN-hold-query:kJotXFiDUkbwwhHh@175.110.115.169:9999",
    "countryphone": "SN",
    "delay_between_numbers": 60,
    "numbers_per_email": 6,
    "num_workers": 50,
    "use_sticky_proxy_per_worker": False,
    "stagger_workers_sec": 0,
    "captcha_proxy": "http://5vvdu3axlr-mobile.res-country-SN-hold-query:kJotXFiDUkbwwhHh@175.110.115.169:9999",
    "captcha_proxy_type": "http",
    "gmail_otp_timeout": 300,
    "gmail_otp_poll": 6,
}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"⚠️ لم أجد {CONFIG_FILE} — سأنشئه")
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        merged = DEFAULT_CONFIG.copy(); merged.update(cfg)
        return merged
    except Exception as e:
        print(f"⚠️ config: {e} — defaults")
        return DEFAULT_CONFIG.copy()


CFG = load_config()
PROXY = CFG.get("proxy") or None
COUNTRYPHONE = (CFG.get("countryphone") or "IT").upper()
DELAY_BETWEEN_NUMBERS = int(CFG.get("delay_between_numbers") or 60)
NUMBERS_PER_EMAIL = int(CFG.get("numbers_per_email") or 6)
NUM_WORKERS = int(CFG.get("num_workers") or 1)
USE_STICKY_PROXY = bool(CFG.get("use_sticky_proxy_per_worker", False))
STAGGER_WORKERS_SEC = float(CFG.get("stagger_workers_sec") or 0)
CAPTCHA_PROXY = CFG.get("captcha_proxy") or None
CAPTCHA_PROXY_TYPE = (CFG.get("captcha_proxy_type") or "http").lower()
GMAIL_OTP_TIMEOUT = int(CFG.get("gmail_otp_timeout") or 300)
GMAIL_OTP_POLL = int(CFG.get("gmail_otp_poll") or 6)

# ✅ التأخيرات (بالثواني)
MIN_REQUEST_DELAY = 2.0        # الحد الأدنى بين كل طلب وطلب
MAX_REQUEST_DELAY = 3.5        # الحد الأعلى
OTP_TO_SUBMIT_DELAY = 3.0      # بين جلب OTP وإرساله

# ============================================
# 🎭 Browser Profiles
# ============================================
WORKER_PROFILES = [
    {"name": "chrome120-linux", "impersonate": "chrome120",
     "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
     "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
     "sec_ch_ua_mobile": "?0", "sec_ch_ua_platform": '"Linux"',
     "accept_language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"},
    {"name": "chrome124-windows", "impersonate": "chrome124",
     "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
     "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
     "sec_ch_ua_mobile": "?0", "sec_ch_ua_platform": '"Windows"',
     "accept_language": "fr-FR,fr;q=0.9,en;q=0.8"},
]


class WorkerContext:
    def __init__(self, wid, profile, proxy):
        self.wid = wid
        self.profile = profile
        self.proxy = proxy

    @property
    def impersonate(self):
        return self.profile["impersonate"]

    def base_headers(self):
        return {
            'Accept-Language': self.profile["accept_language"],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'User-Agent': self.profile["ua"],
            'Sec-Ch-Ua': self.profile["sec_ch_ua"],
            'Sec-Ch-Ua-Mobile': self.profile["sec_ch_ua_mobile"],
            'Sec-Ch-Ua-Platform': self.profile["sec_ch_ua_platform"],
        }

    def merge_headers(self, extra=None):
        h = self.base_headers()
        if extra: h.update(extra)
        return h

    def jitter(self, mn=MIN_REQUEST_DELAY, mx=MAX_REQUEST_DELAY):
        # ✅ تأخير 2-3.5s بين كل طلب وطلب
        time.sleep(random.uniform(mn, mx))


_tls = threading.local()

def get_ctx():
    ctx = getattr(_tls, "ctx", None)
    if ctx is None: raise RuntimeError("_tls.ctx غير معرّف")
    return ctx


# ============================================
# ✅ تنظيف HTML/CSS قبل البحث
# ============================================
def clean_html_text(html):
    if not html:
        return ""
    html = re.sub(r'<style[^>]*>.*?</style>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<script[^>]*>.*?</script>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<[^>]+>', ' ', html)
    html = html.replace('&nbsp;', ' ')
    html = re.sub(r'&[a-zA-Z#0-9]{1,8};', ' ', html)
    html = re.sub(r'\s+', ' ', html)
    return html.strip()


def extract_otp(text, log_debug=False):
    if not text:
        return None
    clean = clean_html_text(text)
    if log_debug:
        print(f"     🧹 نص نظيف (300 حرف): {clean[:300]}")
    patterns = [
        r'code\s+(?:de\s+)?(?:s[ée]curit[ée]|v[ée]rification|validation|confirmation)[^\d\n]{0,30}?\b(\d{4,8})\b',
        r'votre\s+code[^\d\n]{0,30}?\b(\d{4,8})\b',
        r'\bcode\b[^\d\n]{0,20}?\b(\d{4,8})\b',
        r'(?<![\d#a-fA-F])(\d{6})(?![\d#a-fA-F])',
        r'(?<!\d)(\d{4,8})(?!\d)',
    ]
    for pat in patterns:
        for m in re.finditer(pat, clean, re.IGNORECASE):
            code = m.group(1)
            if log_debug:
                s, e = m.start(), m.end()
                snippet = clean[max(0, s-80):min(len(clean), e+80)]
                snippet = re.sub(r'\s+', ' ', snippet)
                print(f"     🔍 [{pat[:40]}...] → {code}")
                print(f"        context: ...{snippet}...")
            return code
    return None


def extract_otp_with_warning(text):
    otp = extract_otp(text, log_debug=True)
    if not otp:
        return None, None
    warnings = []
    for pat in [rf'#\s*{otp}\b', rf'\bcolor\s*:\s*#?{otp}\b', rf'background\s*:\s*#?{otp}\b']:
        if re.search(pat, text, re.IGNORECASE):
            warnings.append(f"⚠️ الرقم {otp} يظهر كلون CSS (#{otp})")
            break
    if len(set(otp)) <= 2:
        warnings.append(f"⚠️ الرقم {otp} نمط متكرر مشبوه")
    return otp, " | ".join(warnings) if warnings else None


# ============================================
# 🍪 WAF cookie
# ============================================
def set_waf_cookie(session, token):
    for dom in (".ankama.com", "auth.ankama.com", "account.ankama.com"):
        try:
            session.cookies.clear(domain=dom, path="/", name="aws-waf-token")
        except Exception:
            pass
    session.cookies.set("aws-waf-token", token, domain=".ankama.com", path="/")


def get_waf_token_debug(session):
    try:
        for c in session.cookies.jar:
            if c.name == "aws-waf-token":
                v = c.value or ""
                return {"len": len(v),
                        "format": "long(2captcha)" if len(v) > 200 else "short(PoW)"}
    except Exception:
        pass
    return None


print("=" * 60)
print("⚙️  الإعدادات:")
safe_proxy = re.sub(r'://[^@]+@', '://***:***@', PROXY) if PROXY else None
print(f"   Proxy           : {safe_proxy or '❌'}")
print(f"   Country         : {COUNTRYPHONE}")
print(f"   Numbers/Email   : {NUMBERS_PER_EMAIL}")
print(f"   Workers         : {NUM_WORKERS}")
print(f"   Req Delay       : {MIN_REQUEST_DELAY}-{MAX_REQUEST_DELAY}s")
print(f"   OTP→Submit      : {OTP_TO_SUBMIT_DELAY}s")
print(f"   Email Service   : social-browser.com")
print("=" * 60)


# ============================================
# 🚨 Dump 403
# ============================================
DUMP_403_DIR = "dumps_403"
os.makedirs(DUMP_403_DIR, exist_ok=True)
_dump_403_counter = 0
_dump_403_lock = threading.Lock()
_403_stats = {}


def _bump_403_stats(url):
    try: key = urlparse(url).path or "/"
    except Exception: key = str(url)[:80]
    with _dump_403_lock:
        _403_stats[key] = _403_stats.get(key, 0) + 1


def print_403_stats():
    if not _403_stats:
        print("\n✅ لا توجد ردود 403"); return
    total = sum(_403_stats.values())
    print(f"\n📊 إحصائيات 403 (الإجمالي: {total}):")
    for path, cnt in sorted(_403_stats.items(), key=lambda x: -x[1]):
        print(f"   {cnt:5d}  ×  {path}")


def dump_403(resp, url, label="", extra=None):
    if resp is None or resp.status_code != 403: return
    global _dump_403_counter
    _bump_403_stats(url)
    try:
        ctx = getattr(_tls, "ctx", None)
        wid = ctx.wid if ctx else 0
    except Exception:
        wid = 0
    with _dump_403_lock:
        _dump_403_counter += 1
        n = _dump_403_counter
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_label = re.sub(r'[^a-zA-Z0-9_-]', '_', label or "req")[:40]
    fpath = os.path.join(DUMP_403_DIR, f"W{wid}_403_{ts}_{n:04d}_{safe_label}.txt")

    body = resp.text or ""
    try:
        readable = BeautifulSoup(body, "html.parser").get_text(" ", strip=True)
        readable = re.sub(r'\s+', ' ', readable)[:500]
    except Exception:
        readable = ""

    print(f"\n🚨 403 [{label}] {url[:100]}")
    if readable:
        print(f"🚨 نص مقروء: {readable}")

    try:
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(f"403 #{n}\nTime: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"URL: {url}\n")
            if extra:
                try: f.write(f"Extra: {json.dumps(extra, ensure_ascii=False, default=str)}\n")
                except Exception: pass
            f.write("\n--- REQUEST HEADERS ---\n")
            if hasattr(resp, "request") and resp.request:
                for k, v in dict(resp.request.headers).items(): f.write(f"{k}: {v}\n")
            f.write("\n--- RESPONSE HEADERS ---\n")
            for k, v in resp.headers.items(): f.write(f"{k}: {v}\n")
            f.write("\n--- BODY ---\n")
            f.write(body)
    except Exception as e:
        print(f"⚠️ dump save: {e}")


# ============================================
# 📧 Email Manager — social-browser.com
# ============================================
FIRST_NAMES = [
    "Ahmed", "Mohammed", "Ali", "Hassan", "Hussein", "Omar", "Osama", "Khaled",
    "Sami", "Rami", "Ziad", "Tarek", "Amr", "Yasser", "Nasser", "Ibrahim",
    "Ismail", "Yousef", "Mousa", "Adam", "Nabil", "Rashid", "Sultan", "Fahd",
    "Saud", "Mansour", "Nawaf", "Faisal", "Turki", "Bandar", "Meshal", "Mishaal"
]
LAST_NAMES = [
    "Al-Otaibi", "Al-Mutairi", "Al-Dosari", "Al-Harbi", "Al-Ghamdi", "Al-Zahrani",
    "Al-Shammari", "Al-Anzi", "Al-Hajri", "Al-Kaabi", "Al-Mansouri", "Al-Sulaiti",
    "Al-Marri", "Al-Hassan", "Al-Naimi", "Al-Thani", "Al-Kuwari", "Al-Malki",
    "Al-Omari", "Al-Qahtani", "Al-Saud", "Al-Faisal", "Al-Rashid", "Al-Sabah"
]
DEFAULT_EMAIL_DOMAINS = ["social-browser.com"]


class EmailGenerator:
    """توليد أسماء وإيميلات عشوائية"""

    def __init__(self, domains=None):
        self.domains = domains or DEFAULT_EMAIL_DOMAINS

    def generate_random_name(self):
        return random.choice(FIRST_NAMES), random.choice(LAST_NAMES)

    def generate_random_email(self, first_name, last_name):
        domain = random.choice(self.domains)
        num = random.randint(100, 999)
        first_clean = first_name.lower()
        last_clean = last_name.lower().replace("-", "")
        return f"{first_clean}{last_clean}{num}@{domain}"

    def generate(self):
        first, last = self.generate_random_name()
        email = self.generate_random_email(first, last)
        return {
            "first_name": first, "last_name": last,
            "full_name": f"{first} {last}", "email": email,
        }


class EmailFetcher:
    """جلب الرسائل من emails.social-browser.com"""

    API_URL = "https://emails.social-browser.com/api/emails/all"

    DEFAULT_HEADERS = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "ar-AE",
        "Connection": "keep-alive",
        "Content-Type": "application/json;charset=UTF-8",
        "Cookie": (
            "access_token=3fbee1cc565e137a7002cedfd2c0bb2b; "
            "_ga=GA1.1.348400085.1788060441; "
            "_ga_3591JBECHZ=GS2.1.s1788060441$o1$g0$t1788060443$j60$l0$h1926413840"
        ),
        "Origin": "https://emails.social-browser.com",
        "Referer": "https://emails.social-browser.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36"
        ),
        "sec-ch-ua": (
            '"Chromium";v="127", "Not)A;Brand";v="99", '
            '"Microsoft Edge Simulate";v="127", "Lemur";v="127"'
        ),
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
    }

    def __init__(self, cookie=None, proxies=None, timeout=10):
        self.headers = dict(self.DEFAULT_HEADERS)
        if cookie:
            self.headers["Cookie"] = cookie
        self.proxies = proxies
        self.timeout = timeout

    def fetch_all(self, email_to, limit=500):
        """جلب كل الرسائل الواردة لهذا الإيميل (مع text/html لاستخراج OTP)"""
        payload = {
            "where": {"to": email_to},
            "limit": limit,
            "select": {
                "id": 1, "guid": 1, "from": 1, "to": 1,
                "subject": 1, "date": 1, "folder": 1,
                "text": 1, "html": 1,
            },
        }
        try:
            r = std_requests.post(self.API_URL, headers=self.headers,
                                  json=payload, proxies=self.proxies,
                                  timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                if data.get("done") and data.get("list"):
                    return data["list"]
            return []
        except Exception as e:
            print(f"   ⚠️ خطأ في جلب البريد: {e}")
            return []


class SocialEmailClient:
    """Wrapper موحّد يدير التوليد + الجلب + استخراج OTP مع تتبع المُستهلك"""

    def __init__(self):
        self.generator = EmailGenerator()
        self.fetcher = EmailFetcher()
        self._seen_ids = set()
        self._used_otps = set()
        self._lock = threading.Lock()

    def make_new_email(self):
        info = self.generator.generate()
        print(f"\n📧 [New] {info['email']} ({info['full_name']})")
        return info

    def wait_for_otp(self, address, timeout=GMAIL_OTP_TIMEOUT,
                     poll=GMAIL_OTP_POLL, label="OTP"):
        print(f"\n⏳ [Email] انتظار {label} لـ {address}")
        start = time.time()
        last_diag = 0

        while time.time() - start < timeout:
            elapsed = int(time.time() - start)
            emails = self.fetcher.fetch_all(address)

            if elapsed - last_diag >= 25:
                print(f"  🔬 [{elapsed}s] رسائل: {len(emails)}")
                last_diag = elapsed

            for e in emails:
                eid = str(e.get("id") or e.get("guid") or "")
                if not eid:
                    continue
                with self._lock:
                    if eid in self._seen_ids:
                        continue

                # دمج text + html لاستخراج OTP بأمان
                text = (e.get("text") or "") + "\n" + (e.get("html") or "")
                if not text.strip():
                    text = e.get("subject", "")

                otp, warning = extract_otp_with_warning(text)
                if not otp:
                    continue

                with self._lock:
                    if eid in self._seen_ids:
                        continue
                    if otp in self._used_otps:
                        continue
                    self._seen_ids.add(eid)
                    self._used_otps.add(otp)

                subj = (e.get("subject") or "")[:60]
                print(f"  📨 [{elapsed}s] subj={subj}")
                if warning:
                    print(f"     {warning}")
                print(f"  🔑 {label} = \033[32m{otp}\033[0m")
                return otp

            time.sleep(poll)

        raise TimeoutError(f"{label} timeout ({timeout}s)")


_email_client = SocialEmailClient()

# ============================================
# Constants
# ============================================
API_KEY = "d91eeed6965d64ef9352aeb67a1327ec"
TARGET_URL = "https://account.ankama.com/en/account/information/change-telephone"
PHONE_PAGE_URL = TARGET_URL
NUMBERS_FILE = "numbers.txt"


# ============================================
# HTTP helpers
# ============================================
def sget(s, url, **kw):
    ctx = getattr(_tls, "ctx", None)
    if ctx is not None:
        ctx.jitter()  # ✅ 2-3.5s
        kw["headers"] = ctx.merge_headers(kw.get("headers"))
    last_exc = None
    for i in range(3):
        try:
            r = s.get(url, **kw)
            if r.status_code == 403:
                try: label = "GET_" + (urlparse(url).path.strip("/").replace("/", "_") or "root")
                except Exception: label = "GET"
                dump_403(r, url, label=label, extra={"attempt": i + 1})
            return r
        except Exception as e:
            last_exc = e
            print("   SSL", i + 1, e); time.sleep(2 + i)
    raise RuntimeError(f"fail: {last_exc}")


def spost(s, url, **kw):
    ctx = getattr(_tls, "ctx", None)
    if ctx is not None:
        ctx.jitter()  # ✅ 2-3.5s
        kw["headers"] = ctx.merge_headers(kw.get("headers"))
    last_exc = None
    for i in range(3):
        try:
            r = s.post(url, **kw)
            if r.status_code == 403:
                try: label = "POST_" + (urlparse(url).path.strip("/").replace("/", "_") or "root")
                except Exception: label = "POST"
                data_keys = list((kw.get("data") or {}).keys()) if isinstance(kw.get("data"), dict) else None
                dump_403(r, url, label=label, extra={"attempt": i + 1, "data_keys": data_keys})
            return r
        except Exception as e:
            last_exc = e
            print("   SSL", i + 1, e); time.sleep(2 + i)
    raise RuntimeError(f"fail: {last_exc}")


def make_session(ctx):
    kwargs = {"impersonate": ctx.impersonate}
    if ctx.proxy: kwargs["proxy"] = ctx.proxy
    return requests.Session(**kwargs)


def bootstrap(ctx):
    for attempt in range(1, 8):
        s = make_session(ctx)
        print(f"\n[{ctx.profile['name']}] === bootstrap {attempt}/7 ===")
        try:
            r1 = sget(s, TARGET_URL, headers={
                'Sec-Fetch-Site': 'none', 'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
                allow_redirects=False)
        except Exception:
            time.sleep(8 * attempt); continue
        if r1.status_code != 302:
            time.sleep(10 * attempt); continue
        r2 = sget(s, 'https://account.ankama.com/webauth/authorize?from=' + TARGET_URL,
            headers={'Referer': TARGET_URL, 'Sec-Fetch-Site': 'none',
                     'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-User': '?1',
                     'Sec-Fetch-Dest': 'document'}, allow_redirects=False)
        loc2 = r2.headers.get("Location")
        if r2.status_code != 302 or not loc2:
            time.sleep(8 * attempt); continue
        r3 = sget(s, loc2, headers={'Referer': TARGET_URL, 'Sec-Fetch-Site': 'none',
                     'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-User': '?1',
                     'Sec-Fetch-Dest': 'document'}, allow_redirects=False)
        if r3.status_code != 200:
            time.sleep(8 * attempt); continue
        soup = BeautifulSoup(r3.text, "html.parser")
        tag = soup.find("script", src=re.compile(r"challenge\.js"))
        if not tag:
            time.sleep(8 * attempt); continue
        print("   [1] 302 | [2] 302 | [3] 200")
        return s, r3, loc2, soup, tag["src"]
    raise RuntimeError("bootstrap failed")


async def fake_discover(client, site, ua):
    return _tls.chal_base, False, None

S._discover = fake_discover


def solve_pow_waf(session, reason=""):
    ctx = get_ctx()
    print(f"\n>>> PoW WAF ({reason})")
    async def _run():
        result, _ = await S.solve(
            "https://account.ankama.com", ctx.profile["ua"],
            proxy=ctx.proxy, cookies=session.cookies.get_dict())
        return result.get("token")
    token = asyncio.run(_run())
    print(f"    token ({len(token or '')} chars)")
    set_waf_cookie(session, token)
    return token


def parse_proxy_for_2captcha(proxy_url, ptype="http"):
    if not proxy_url: return None
    s = proxy_url.strip()
    m = re.match(r'^(https?|socks4|socks5)://(.+)$', s)
    rest = m.group(2) if m else s
    login = password = None
    if "@" in rest:
        auth, host_port = rest.rsplit("@", 1)
        if ":" in auth: login, password = auth.split(":", 1)
        else: login = auth
    else: host_port = rest
    host, port = host_port.rsplit(":", 1)
    r = {"proxyType": ptype, "proxyAddress": host, "proxyPort": int(port)}
    if login: r["proxyLogin"] = login
    if password: r["proxyPassword"] = password
    return r


def solve_captcha_2captcha(website_url, key, iv, context, chal_script, captcha_script=None):
    ctx = get_ctx()
    print(f"\n>>> 2Captcha")
    chosen_proxy = CAPTCHA_PROXY or ctx.proxy or PROXY
    task = {
        "type": "AmazonTask" if chosen_proxy else "AmazonTaskProxyless",
        "websiteURL": website_url, "websiteKey": key, "iv": iv,
        "context": context, "challengeScript": chal_script,
    }
    if captcha_script: task["captchaScript"] = captcha_script
    if chosen_proxy:
        try:
            proxy_fields = parse_proxy_for_2captcha(chosen_proxy, CAPTCHA_PROXY_TYPE)
        except Exception as e:
            raise RuntimeError(f"proxy parse: {e}")
        task.update(proxy_fields)
    resp = requests.post("https://api.2captcha.com/createTask",
        json={"clientKey": API_KEY, "task": task},
        impersonate=ctx.impersonate, timeout=30)
    data = resp.json()
    print("    createTask:", data)
    if data.get("errorId", 0) != 0:
        raise RuntimeError(f"2Captcha: {data}")
    tid = data["taskId"]
    start = time.time()
    while time.time() - start < 300:
        time.sleep(5)
        r = requests.post("https://api.2captcha.com/getTaskResult",
            json={"clientKey": API_KEY, "taskId": tid},
            impersonate=ctx.impersonate, timeout=30)
        res = r.json()
        print(f"    poll: {res.get('status')}")
        if res.get("errorId", 0) != 0:
            raise RuntimeError(f"2Captcha: {res}")
        if res.get("status") == "ready":
            sol = res["solution"]
            tok = (sol.get("existing_token") or sol.get("captcha_voucher") or sol.get("token"))
            print(f"    ✅ token ({len(tok or '')} chars)")
            return tok
    raise TimeoutError("2captcha timeout")


def _is_waf_challenge(resp):
    if resp is None: return False
    if resp.status_code not in (200, 202, 400, 403, 405, 429, 502, 503): return False
    txt = (resp.text or "")[:12000].lower()
    return "gokuprops" in txt


def handle_captcha(session, resp, url, referer, method="GET", data=None):
    if resp is None: return resp
    if not _is_waf_challenge(resp): return resp

    print(f"\n>>> WAF Challenge at {url[:80]} (status={resp.status_code})")
    soup_c = BeautifulSoup(resp.text, "html.parser")
    goku_json = None
    for script in soup_c.find_all("script"):
        txt = script.string or ""
        m = re.search(r'window\.gokuProps\s*=\s*(\{.*?\});', txt, re.DOTALL)
        if m: goku_json = m.group(1); break
    if not goku_json:
        print("    ⚠️ gokuProps not found"); return resp
    try: goku = json.loads(goku_json)
    except Exception as e:
        print(f"    ⚠️ parse: {e}"); return resp

    chal_tag = soup_c.find("script", src=re.compile(r"challenge\.js"))
    cap_tag = soup_c.find("script", src=re.compile(r"captcha\.js"))
    chal_src = chal_tag["src"] if chal_tag else None
    cap_src = cap_tag["src"] if cap_tag else None

    print(f"    goku key={goku.get('key','')[:30]}...")
    captcha_token = solve_captcha_2captcha(
        url, goku["key"], goku["iv"], goku["context"], chal_src, cap_src)
    set_waf_cookie(session, captcha_token)

    print(f"    🔑 إعادة الطلب ({method}) بعد 3s...")
    time.sleep(3)

    ctx = getattr(_tls, "ctx", None)
    replay_headers = ctx.merge_headers({
        'Referer': referer, 'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
    }) if ctx else {'Referer': referer}

    if method.upper() == "POST":
        replay_headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://auth.ankama.com',
        })
        r = spost(session, url, headers=replay_headers, data=data or {}, allow_redirects=False)
    else:
        r = sget(session, url, headers=replay_headers, allow_redirects=False)
    print(f"    ↳ بعد التحدي: {r.status_code}")
    return r


def follow_redirects(session, start_url, referer, max_hops=10, label="hop"):
    current_url = start_url
    current_resp = None
    seen = set()
    for hop in range(1, max_hops + 1):
        if current_url in seen:
            print(f"   ⚠️ loop"); break
        seen.add(current_url)
        r = sget(session, current_url,
            headers={'Referer': referer, 'Sec-Fetch-Site': 'same-origin',
                     'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-User': '?1',
                     'Sec-Fetch-Dest': 'document'}, allow_redirects=False)
        print(f"   [{label}.{hop}] {r.status_code}")
        if _is_waf_challenge(r):
            r = handle_captcha(session, r, current_url, referer, method="GET")
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if not loc: current_resp = r; break
            current_url = urljoin(current_url, loc); continue
        else:
            current_resp = r; break
    return current_resp, current_url


# ============================================
# Phone form
# ============================================
def load_numbers(path):
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write("+22370000001\n+22370000002\n+22370000003\n")
    with open(path, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]


def get_phone_form(s):
    r = sget(s, PHONE_PAGE_URL,
        headers={'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
                 'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
        allow_redirects=True)
    if r.status_code != 200:
        print(f"❌ GET phone page: {r.status_code}"); return None, None, None
    soup = BeautifulSoup(r.text, "html.parser")
    form = None
    for f in soup.find_all("form"):
        if f.find("input", {"name": "gsm"}): form = f; break
    return r.url, form, soup


CC_PREFIX_MAP = {
    "IT": "39", "FR": "33", "ES": "34", "DE": "49", "MA": "212",
    "DZ": "213", "TN": "216", "EG": "20", "SA": "966", "AE": "971",
    "GB": "44", "US": "1", "PT": "351", "BE": "32", "NL": "31",
    "CH": "41", "ML": "223", "SN": "221", "CI": "225", "GM": "220",
    "GN": "224", "BF": "226", "NE": "227", "TG": "228", "BJ": "229",
    "MR": "222", "GH": "233", "NG": "234",
}


def strip_country_prefix(phone, cc_code):
    clean = re.sub(r'\D', '', phone)
    prefix = CC_PREFIX_MAP.get(cc_code, "")
    if prefix and clean.startswith(prefix):
        local = clean[len(prefix):]
        if len(local) >= 6: return local
    return clean


def parse_form_fields(form, overrides=None):
    data = {}
    if form is None: return overrides or {}
    for field in form.find_all(["input", "select", "textarea"]):
        n = field.get("name")
        if not n: continue
        tag = field.name.lower()
        typ = (field.get("type") or "").lower()
        if tag == "select":
            sel = field.find("option", selected=True) or field.find("option")
            if sel: data[n] = sel.get("value", "")
            continue
        if typ in ("submit", "button", "reset", "image", "file"): continue
        if typ in ("checkbox", "radio"):
            if field.has_attr("checked"): data[n] = field.get("value", "on")
            continue
        data[n] = field.get("value", "")
    if overrides: data.update(overrides)
    return data


def submit_phone(s, form_url, phone):
    print(f"\n{'='*60}\n📱 إرسال: {phone}\n{'='*60}")
    r0 = sget(s, form_url, headers={'Referer': PHONE_PAGE_URL,
             'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
             'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
             allow_redirects=False)
    if r0.status_code != 200:
        print(f"   ⚠️ GET form: {r0.status_code}"); return False, None
    soup0 = BeautifulSoup(r0.text, "html.parser")
    form = None
    for f in soup0.find_all("form"):
        if f.find("input", {"name": "gsm"}): form = f; break
    if not form:
        print("   ❌ لا يوجد gsm"); return False, None

    data = parse_form_fields(form)
    data["countryphone"] = COUNTRYPHONE
    if phone.strip().startswith("+"):
        data["gsm"] = strip_country_prefix(phone, COUNTRYPHONE)
    else:
        clean = re.sub(r'\D', '', phone)
        prefix = CC_PREFIX_MAP.get(COUNTRYPHONE, "")
        if prefix and clean.startswith(prefix) and len(clean) > len(prefix):
            data["gsm"] = clean[len(prefix):]
        else:
            data["gsm"] = clean

    action = urljoin(form_url, form.get("action") or form_url)
    resp = spost(s, action, headers={
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://account.ankama.com', 'Referer': form_url,
        'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
        data=data, allow_redirects=False)
    print(f"   POST: {resp.status_code}")
    resp = handle_captcha(s, resp, action, form_url, method="POST", data=data)
    print(f"   post-captcha: {resp.status_code}")

    soup_r = BeautifulSoup(resp.text, "html.parser")
    full_text = soup_r.get_text(" ", strip=True).lower()
    is_success = (
        resp.status_code in (301, 302, 303) or
        "verification code has been sent" in full_text or
        soup_r.find("input", {"name": "security_code"}) is not None
    )
    ctx = get_ctx()
    safe = re.sub(r'\D', '', phone)
    if is_success:
        print(f"   ✅✅✅ نجح")
        return True, resp
    for msg in soup_r.select("[class*=alert], [class*=error], [class*=success], [class*=message]"):
        t = msg.get_text(strip=True)
        if t and len(t) < 300: print(f"   💬 {t}")
    return True, resp


def back_to_form(s):
    r = sget(s, PHONE_PAGE_URL, headers={'Referer': PHONE_PAGE_URL,
             'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
             'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
             allow_redirects=True)
    if r.status_code != 200:
        print(f"   ⚠️ BACK: {r.status_code}"); return False
    soup = BeautifulSoup(r.text, "html.parser")
    has_gsm = any(f.find("input", {"name": "gsm"}) for f in soup.find_all("form"))
    print(f"   {'✅' if has_gsm else '⚠️'} BACK")
    return has_gsm


# ============================================
# إنشاء حساب جديد
# ============================================
def setup_new_account(worker_id, ctx):
    wtag = f"[W{worker_id}|{ctx.profile['name']}]"
    print(f"\n{wtag} " + "=" * 50)
    print(f"{wtag} 🆕 إنشاء حساب جديد")
    print(f"{wtag} " + "=" * 50)

    email_info = _email_client.make_new_email()
    new_email = email_info["email"]
    print(f"{wtag} 📧 {new_email}")

    session, r3, location_2, soup, challenge_js_url = bootstrap(ctx)
    chal_base = challenge_js_url.rsplit("/challenge.js", 1)[0]
    _tls.chal_base = chal_base

    solve_pow_waf(session, "initial")

    ACCOUNT = {
        "email": new_email, "password": "Ak_1029384756",
        "firstname": email_info["first_name"],
        "lastname": email_info["last_name"],
        "bday_day": "01", "bday_month": "01", "bday_year": "2000",
        "newsletter": "on",
    }

    login_link = next((a["href"] for a in soup.find_all("a", href=True) if "/login/ankama?" in a["href"]), None)
    login_url = urljoin("https://auth.ankama.com", login_link)
    r5 = sget(session, login_url, headers={'Referer': location_2,
        'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'}, allow_redirects=False)
    login_form_url = urljoin("https://auth.ankama.com", r5.headers.get("Location"))
    r6 = sget(session, login_form_url, headers={'Referer': login_url,
        'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'}, allow_redirects=False)

    soup2 = BeautifulSoup(r6.text, "html.parser")
    register_href = next((a["href"] for a in soup2.find_all("a", href=True) if "/register/ankama/form" in a["href"]), None)
    register_url = urljoin("https://auth.ankama.com", register_href)

    rr = sget(session, register_url, headers={'Referer': login_form_url,
        'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'}, allow_redirects=False)
    rr = handle_captcha(session, rr, register_url, login_form_url, method="GET")
    if rr.status_code != 200:
        raise RuntimeError(f"register page: {rr.status_code}")

    soup3 = BeautifulSoup(rr.text, "html.parser")
    form = soup3.find("form", {"action": re.compile(r"/register/ankama/form-submit")})
    form_data = parse_form_fields(form, overrides={
        "email": ACCOUNT["email"], "password": ACCOUNT["password"],
        "lastname": ACCOUNT["lastname"], "firstname": ACCOUNT["firstname"],
        "birthday-day": ACCOUNT["bday_day"], "birthday-month": ACCOUNT["bday_month"],
        "birthday-year": ACCOUNT["bday_year"],
    })
    if ACCOUNT.get("newsletter"): form_data["newsletterSubscribe"] = "on"

    action_url = urljoin("https://auth.ankama.com", form.get("action"))
    resp = spost(session, action_url, headers={
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://auth.ankama.com', 'Referer': register_url,
        'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
        data=form_data, allow_redirects=False)
    print(f"{wtag} [1] register POST: {resp.status_code}")
    resp = handle_captcha(session, resp, action_url, register_url,
                          method="POST", data=form_data)
    print(f"{wtag} [1] post-captcha: {resp.status_code}")
    if resp.status_code not in (301, 302, 303):
        raise RuntimeError(f"register post failed: {resp.status_code}")

    code_url = urljoin(action_url, resp.headers.get("Location", ""))
    print(f"{wtag} [2] code_url: {code_url[:120]}")
    parsed_q = urlparse(code_url)
    state_from_url = (parse_qs(parsed_q.query).get("state", [None])[0]) or ""

    rc = sget(session, code_url, headers={'Referer': register_url,
        'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'}, allow_redirects=False)
    print(f"{wtag} [2] GET code: {rc.status_code}")

    if rc.status_code == 405:
        solve_pow_waf(session, "code-405-retry"); time.sleep(2)
        rc = spost(session, code_url, headers={
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://auth.ankama.com', 'Referer': register_url,
            'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
            data={"state": state_from_url}, allow_redirects=False)

    rc = handle_captcha(session, rc, code_url, register_url,
                        method="POST", data={"state": state_from_url})
    if rc.status_code != 200:
        raise RuntimeError(f"code page: {rc.status_code}")

    soup_code = BeautifulSoup(rc.text, "html.parser")
    code_form = soup_code.find("form", {"action": re.compile(r"/register/ankama/code")})
    real_action_1 = urljoin("https://auth.ankama.com", code_form.get("action"))

    # ⭐ جلب OTP تلقائيًا
    otp1 = _email_client.wait_for_otp(new_email, timeout=GMAIL_OTP_TIMEOUT,
                                      poll=GMAIL_OTP_POLL, label="OTP-1")

    # ✅ تأخير 3s بين جلب OTP وإرساله
    print(f"{wtag}   ⏱️ تأخير {OTP_TO_SUBMIT_DELAY}s قبل إرسال OTP-1...")
    time.sleep(OTP_TO_SUBMIT_DELAY)

    otp1_data = parse_form_fields(code_form, overrides={"code": otp1})
    print(f"{wtag} [3] POST OTP-1: {otp1}")
    r1_resp = spost(session, real_action_1, headers={
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://auth.ankama.com', 'Referer': code_url,
        'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
        data=otp1_data, allow_redirects=False)
    print(f"{wtag} [3] status: {r1_resp.status_code}")

    r1_resp = handle_captcha(session, r1_resp, real_action_1, code_url,
                             method="POST", data=otp1_data)
    if r1_resp.status_code not in (301, 302, 303):
        try:
            txt = BeautifulSoup(r1_resp.text, "html.parser").get_text(" ", strip=True)
            txt = re.sub(r'\s+', ' ', txt)[:300]
            print(f"{wtag} ❌ فشل OTP-1 — رد السيرفر: {txt}")
        except Exception:
            pass
        raise RuntimeError(f"otp1 failed: {r1_resp.status_code}")

    next_url = urljoin(real_action_1, r1_resp.headers.get("Location", ""))
    print(f"{wtag} [4] → {next_url[:120]}")

    rn = sget(session, next_url, headers={'Referer': real_action_1,
        'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'}, allow_redirects=False)
    rn = handle_captcha(session, rn, next_url, real_action_1, method="GET")
    print(f"{wtag} [4] Félicitations: {rn.status_code}")

    soup_c = BeautifulSoup(rn.text, "html.parser")
    continuer_href = None
    for a in soup_c.find_all("a", href=True):
        if "continu" in a.get_text(strip=True).lower():
            continuer_href = a["href"]; break
    if not continuer_href:
        for f in soup_c.find_all("form"):
            if "continu" in f.get_text(strip=True).lower():
                continuer_href = f.get("action"); break

    cont_url = urljoin(next_url, continuer_href) if continuer_href else (rn.headers.get("Location") or next_url)
    print(f"{wtag} [5] Continuer → {cont_url[:120]}")

    current_resp, current_url = follow_redirects(session, cont_url, next_url, max_hops=8, label="cont")

    # OTP-2 إن وُجد
    soup_final = BeautifulSoup(current_resp.text, "html.parser")
    otp2_form = None
    for f in soup_final.find_all("form"):
        if f.find("input", {"name": re.compile(r"code|otp", re.I)}):
            otp2_form = f; break

    if otp2_form:
        print(f"{wtag} 🔑 OTP-2...")
        action_2 = urljoin(current_url, otp2_form.get("action") or current_url)
        otp2 = _email_client.wait_for_otp(new_email, timeout=GMAIL_OTP_TIMEOUT,
                                          poll=GMAIL_OTP_POLL, label="OTP-2")

        # ✅ تأخير 3s بين جلب OTP وإرساله
        print(f"{wtag}   ⏱️ تأخير {OTP_TO_SUBMIT_DELAY}s قبل إرسال OTP-2...")
        time.sleep(OTP_TO_SUBMIT_DELAY)

        otp2_data = parse_form_fields(otp2_form, overrides={
            otp2_form.find("input", {"name": re.compile(r"code|otp", re.I)}).get("name"): otp2
        })
        r2_resp = spost(session, action_2, headers={
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://auth.ankama.com', 'Referer': current_url,
            'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
            data=otp2_data, allow_redirects=False)
        r2_resp = handle_captcha(session, r2_resp, action_2, current_url,
                                 method="POST", data=otp2_data)
        if r2_resp.status_code in (301, 302, 303):
            next_2 = urljoin(action_2, r2_resp.headers.get("Location", ""))
            current_resp, current_url = follow_redirects(session, next_2, action_2, max_hops=6, label="otp2")

    soup_rem = BeautifulSoup(current_resp.text, "html.parser")
    title_rem = soup_rem.find("title")
    if title_rem and "remember this device" in title_rem.get_text(strip=True).lower():
        print(f"{wtag} ✨ Remember device")
        r_yes = spost(session, current_url, headers={
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://account.ankama.com', 'Referer': current_url,
            'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
            data={}, allow_redirects=False)
        r_yes = handle_captcha(session, r_yes, current_url, current_url,
                               method="POST", data={})
        if r_yes.status_code in (301, 302, 303):
            loc_yes = urljoin(current_url, r_yes.headers.get("Location", ""))
            current_resp, current_url = follow_redirects(session, loc_yes, current_url, max_hops=6, label="yes")

    form_url, form, _ = get_phone_form(session)
    if not form:
        raise RuntimeError("phone form not found")

    print(f"{wtag} ✅ الحساب {new_email} جاهز | form_url={form_url}")
    return session, new_email, form_url


# ============================================
# Worker
# ============================================
def worker_sync(worker_id, proxy, numbers, results, lock):
    profile = WORKER_PROFILES[(worker_id - 1) % len(WORKER_PROFILES)]
    ctx = WorkerContext(worker_id, profile, proxy)
    _tls.ctx = ctx

    wtag = f"[W{worker_id}|{profile['name']}]"
    def wp(*a): print(wtag, *a)

    wp("=" * 55)
    wp(f"🚀 بدأ | profile={profile['name']}")
    wp("=" * 55)

    current_session = None
    current_email = None
    current_form_url = None
    processed_in_current = 0
    accounts_used = []

    for idx, phone in enumerate(numbers, 1):
        need_new = (current_session is None) or (processed_in_current >= NUMBERS_PER_EMAIL)

        if need_new:
            if current_email:
                wp(f"🔁 استُهلك {NUMBERS_PER_EMAIL} على {current_email}")
            ok_new = False
            for attempt in range(1, 4):
                try:
                    current_session, current_email, current_form_url = \
                        setup_new_account(worker_id, ctx)
                    accounts_used.append((current_email, []))
                    processed_in_current = 0
                    ok_new = True
                    break
                except Exception as e:
                    wp(f"❌ فشل ({attempt}/3): {e}")
                    time.sleep(random.uniform(10, 20))
            if not ok_new:
                wp("❌ إيقاف العامل"); break

        wp(f"\n{'#'*55}")
        wp(f"# {idx}/{len(numbers)}: {phone} ({current_email})")
        wp(f"{'#'*55}")

        try:
            ok, resp = submit_phone(current_session, current_form_url, phone)
            if ok:
                processed_in_current += 1
                if accounts_used and accounts_used[-1][0] == current_email:
                    accounts_used[-1][1].append(phone)
        except Exception as e:
            wp(f"❌ submit_phone: {e}")

        time.sleep(2)
        try: back_to_form(current_session)
        except Exception as e: wp(f"⚠️ back: {e}")

        if idx < len(numbers):
            wp(f"   ⏱️ {DELAY_BETWEEN_NUMBERS}s...")
            for remaining in range(DELAY_BETWEEN_NUMBERS, 0, -10):
                time.sleep(min(10, remaining))
            wp("   ✅ جاهز")

    with lock: results.extend(accounts_used)
    wp(f"✅ انتهى — {len(accounts_used)} حساب، {sum(len(x[1]) for x in accounts_used)} رقم")


# ============================================
# Main
# ============================================
async def main_async():
    numbers = load_numbers(NUMBERS_FILE)
    print(f"\n📋 أرقام: {len(numbers)} | أرقام/إيميل: {NUMBERS_PER_EMAIL} | عمال: {NUM_WORKERS}")

    if not numbers:
        print("❌ لا توجد أرقام"); return

    n = len(numbers)
    size = (n + NUM_WORKERS - 1) // NUM_WORKERS
    chunks = [numbers[i*size:(i+1)*size] for i in range(NUM_WORKERS)]
    chunks = [c for c in chunks if c]
    actual_workers = len(chunks)

    print(f"\n📊 توزيع:")
    for i, c in enumerate(chunks):
        prof = WORKER_PROFILES[i % len(WORKER_PROFILES)]
        print(f"   👷 W{i+1} [{prof['name']}]: {len(c)} رقم")

    results = []
    lock = threading.Lock()
    print(f"\n🚀 انطلاق {actual_workers} عمال...\n" + "=" * 55)

    tasks = []
    for i in range(actual_workers):
        worker_id = i + 1
        tasks.append(asyncio.to_thread(
            worker_sync, worker_id, PROXY, chunks[i], results, lock))

    await asyncio.gather(*tasks)

    print(f"\n\n{'='*60}\n🎉 انتهى!\n{'='*60}")

    with open("accounts_summary.json", "w", encoding="utf-8") as f:
        json.dump([{"email": e, "numbers": nums} for e, nums in results],
                  f, indent=2, ensure_ascii=False)

    total_nums = sum(len(nums) for _, nums in results)
    print(f"\n📧 حسابات: {len(results)} | 📱 أرقام: {total_nums}")
    print_403_stats()
    print(f"\n🔑 كلمة المرور: Ak_1029384756")


# ============================================
# 🌐 Flask Web Server (for Render)
# ============================================
flask_app = Flask(__name__)


@flask_app.route("/")
@flask_app.route("/health")
def _flask_health():
    """Render health check"""
    return jsonify({
        "status": "running",
        "time": time.time(),
        "workers": NUM_WORKERS,
        "country": COUNTRYPHONE,
    }), 200


@flask_app.route("/summary")
def _flask_summary():
    """ملخص الحسابات المُنشأة"""
    try:
        with open("accounts_summary.json", "r", encoding="utf-8") as f:
            return jsonify(json.load(f)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@flask_app.route("/403stats")
def _flask_403():
    """إحصائيات ردود 403"""
    return jsonify(_403_stats), 200


def _run_bot_background():
    """تشغيل البوت داخل خيط منفصل حتى لا يوقف Flask"""
    try:
        asyncio.run(main_async())
    except Exception as e:
        print(f"❌ [bot] background error: {e}")


if __name__ == "__main__":
    # 1) شغّل البوت في خيط منفصل
    bot_thread = threading.Thread(target=_run_bot_background, daemon=True)
    bot_thread.start()

    # 2) شغّل Flask على PORT (Render يستخدمه للـ health check)
    port = int(os.environ.get("PORT", 10000))
    print(f"\n🌐 Flask listening on 0.0.0.0:{port}")
    flask_app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)