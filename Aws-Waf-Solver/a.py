import asyncio
import re
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from curl_cffi import requests
from bs4 import BeautifulSoup
import waf.solver as S

TARGET = "https://account.ankama.com/en/account/information/change-telephone"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"

BASE_HDR = {
    'Accept-Language': 'ar',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': UA,
}

# ============================================
# المرحلة 1: Bootstrap للحصول على challenge URL
# ============================================
print("[1] Bootstrap...")
session = requests.Session(impersonate="chrome120")

r1 = session.get(TARGET,
    headers={**BASE_HDR, 'Sec-Fetch-Site': 'none', 'Sec-Fetch-Mode': 'navigate',
             'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
    allow_redirects=False)
print("   r1:", r1.status_code, "| SID:", session.cookies.get("SID"))

if r1.status_code != 302:
    print("   ⚠️ IP محظور؟ انتظر 15 دقيقة")
    sys.exit(1)

r2 = session.get(
    'https://account.ankama.com/webauth/authorize?from=' + TARGET,
    headers={**BASE_HDR, 'Referer': TARGET, 'Sec-Fetch-Site': 'none',
             'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
    allow_redirects=False)
loc2 = r2.headers.get("Location")
print("   r2:", r2.status_code, "| Loc:", (loc2 or "")[:80])

r3 = session.get(loc2,
    headers={**BASE_HDR, 'Referer': TARGET, 'Sec-Fetch-Site': 'none',
             'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document'},
    allow_redirects=False)
print("   r3:", r3.status_code)

soup = BeautifulSoup(r3.text, "html.parser")
tag = soup.find("script", src=re.compile(r"challenge\.js"))
if not tag:
    print("   ❌ لم نجد challenge.js")
    sys.exit(1)

challenge_js_url = tag["src"]
chal_base = challenge_js_url.rsplit("/challenge.js", 1)[0]
print("   challenge base:", chal_base)

# ============================================
# المرحلة 2: تجاوز _discover
# ============================================
async def fake_discover(client, site, ua):
    # (chal_url, same_origin, goku_props)
    return chal_base, False, None

S._discover = fake_discover

# ============================================
# المرحلة 3: حل التحدي
# ============================================
async def main():
    cookies = session.cookies.get_dict()
    print("[2] Cookies:", list(cookies.keys()))

    result, client = await S.solve(
        "https://account.ankama.com",
        UA,
        cookies=cookies,
    )
    print("\n" + "=" * 60)
    print("RESULT:", result)
    print("=" * 60)

    token = result.get("token")
    if token:
        with open("waf_token.txt", "w") as f:
            f.write(token)
        print(f"💾 تم حفظ التوكن في waf_token.txt")

asyncio.run(main())
