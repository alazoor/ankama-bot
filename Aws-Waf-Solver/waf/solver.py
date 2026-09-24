import re
import json
import time
import base64
import asyncio
import hashlib

from rnet import Client, Impersonate, Proxy
import pyscrypt
import structlog

from waf.crypto   import encode, encrypt
from waf.signal   import build_signal
from waf.metrics  import build_metrics

log = structlog.get_logger()

RE_CHAL_SAME = re.compile(r'(/__challenge_[A-Za-z0-9]+/[a-f0-9]+/[a-f0-9]+)')
RE_CHAL_EXT  = re.compile(r'(https://[a-z0-9]+\.[a-z0-9]+\.[a-z0-9-]+\.token\.awswaf\.com/[^/\s"]+/[^/\s"]+/[^/\s"]+)')
RE_CHAL_SDK  = re.compile(r'(https://[a-z0-9]+\.edge\.sdk\.awswaf\.com/[a-z0-9]+/[a-z0-9]+)/challenge\.js')
RE_GOKU      = re.compile(r'window\.gokuProps\s*=\s*(\{[^}]+\})')

ENDPOINT = {
    "HashcashScrypt":   "verify",
    "SHA256":           "verify",
    "NetworkBandwidth": "mp_verify",
}

BWDTH_SIZES = {1: 1024, 2: 10240, 3: 102400, 4: 1048576, 5: 10485760}

BRANDS = {
    0: '"Not/A)Brand";v="8", "Chromium";v="{v}", "Google Chrome";v="{v}"',
    1: '"Not A(Brand";v="24", "Chromium";v="{v}", "Google Chrome";v="{v}"',
    2: '"Chromium";v="{v}", "Not(A:Brand";v="24", "Google Chrome";v="{v}"',
    3: '"Not:A-Brand";v="8", "Chromium";v="{v}", "Google Chrome";v="{v}"',
}


def _parse_ua(ua: str) -> tuple[str, str]:
    m = re.search(r"Chrome/(\d+)", ua)
    ver = m.group(1) if m else "144"
    platform = "Windows" if "windows" in ua.lower() else "Linux"
    brand = BRANDS[int(ver) % 4].replace("{v}", ver)
    return brand, platform


def _nav_headers(site: str, ua: str) -> dict:
    brand, platform = _parse_ua(ua)
    return {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "en-US,en;q=0.9",
        "sec-ch-ua": brand,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": f'"{platform}"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": ua,
    }


def _api_headers(site: str, ua: str, same_origin: bool = True) -> dict:
    brand, platform = _parse_ua(ua)
    return {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-cache",
        "ect": "4g",
        "origin": site,
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": f"{site}/",
        "sec-ch-ua": brand,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": f'"{platform}"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin" if same_origin else "cross-site",
        "user-agent": ua,
    }


def _check_zeros(h: bytes, difficulty: int) -> bool:
    z = 0
    for b in h:
        if b == 0:
            z += 8
        else:
            for i in range(7, -1, -1):
                if (b & (1 << i)) == 0:
                    z += 1
                else:
                    break
            break
    return z >= difficulty


def _solve_pow(challenge_input: str, checksum: str, difficulty: int, ctype: str, memory: int = 128) -> str:
    if ctype == "HashcashScrypt":
        combined = challenge_input + checksum
        salt = checksum.encode()
        for n in range(100000000):
            if _check_zeros(pyscrypt.hash(f"{combined}{n}".encode(), salt, memory, 8, 1, 32), difficulty):
                return str(n)
    elif ctype == "SHA256":
        base = (challenge_input + checksum).encode()
        for n in range(100000000):
            if _check_zeros(hashlib.sha256(base + str(n).encode()).digest(), difficulty):
                return str(n)
    return "0"


def _solve_bandwidth(difficulty: int) -> str:
    sz = BWDTH_SIZES.get(difficulty)
    if not sz:
        return base64.b64encode(b"\x00" * 1024).decode()
    return base64.b64encode(b"\x00" * sz).decode()


async def _discover(client: Client, site: str, ua: str) -> tuple[str, bool, dict | None]:
    resp = await client.get(site, headers=_nav_headers(site, ua))
    html = await resp.text()

    m = RE_CHAL_SAME.search(html)
    if m:
        chal_url = f"{site}{m.group(1)}"
        same = True
    else:
        m = RE_CHAL_EXT.search(html)
        if not m:
            m = RE_CHAL_SDK.search(html)
        if m:
            chal_url = m.group(1)
            same = False
        else:
            raise RuntimeError("challenge URL not found")

    goku = None
    gm = RE_GOKU.search(html)
    if gm:
        goku = json.loads(gm.group(1))

    return chal_url, same, goku


def _prepare(site: str, ua: str, has_token: bool) -> tuple[str, str, list]:
    metrics, fp_metrics = build_metrics(has_token=has_token)
    fp       = build_signal(f"{site}/", fp_metrics, ua)
    encoded  = encode(fp)
    checksum = encoded.split("#")[0]
    encrypted = encrypt(encoded)
    return checksum, encrypted, metrics


def _build_body(domain: str, challenge: dict, solution: str,
                checksum: str, encrypted: str, metrics: list,
                existing_token: str = None, goku_props: dict = None) -> str:
    d = {
        "challenge": challenge,
        "solution": solution,
        "signals": [{"name": "Zoey", "value": {"Present": encrypted}}],
        "checksum": checksum,
        "existing_token": existing_token,
        "client": "Browser",
        "domain": domain,
        "metrics": metrics,
    }
    if goku_props:
        d["goku_props"] = goku_props
    return json.dumps(d, separators=(",", ":"))


def _build_multipart(domain: str, challenge: dict, solution_data: str,
                     checksum: str, encrypted: str, metrics: list,
                     existing_token: str = None, goku_props: dict = None) -> tuple[str, str]:
    meta = {
        "challenge": challenge,
        "solution": None,
        "signals": [{"name": "Zoey", "value": {"Present": encrypted}}],
        "checksum": checksum,
        "existing_token": existing_token,
        "client": "Browser",
        "domain": domain,
        "metrics": metrics,
    }
    if goku_props:
        meta["goku_props"] = goku_props

    boundary = "----WebKitFormBoundary" + "".join(
        __import__("random").choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=16)
    )
    parts = []
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"solution_data\"\r\n\r\n{solution_data}")
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"solution_metadata\"\r\n\r\n{json.dumps(meta, separators=(',', ':'))}")
    parts.append(f"--{boundary}--\r\n")
    body = "\r\n".join(parts)
    ct = f"multipart/form-data; boundary={boundary}"
    return body, ct


def _make_client(proxy: str = None) -> Client:
    opts = {"emulation": Impersonate.Chrome136, "cookie_store": True}
    if proxy:
        opts["proxies"] = [Proxy.all(proxy)]
    return Client(**opts)


async def _do_verify(client: Client, chal_url: str, endpoint: str, body: str,
                     cookies: dict, hdrs: dict, content_type: str) -> dict:
    h = {**hdrs, "content-type": content_type}
    resp = await client.post(f"{chal_url}/{endpoint}", body=body, cookies=cookies, headers=h)
    return await resp.json()


async def solve(site: str, ua: str, proxy: str = None,
                cookies: dict = None, client: Client = None) -> tuple[dict, Client]:
    site = site.rstrip("/")
    domain = site.split("//")[1].split("/")[0]
    cookies = cookies or {}

    if client is None:
        client = _make_client(proxy)
    t0 = time.time()

    chal_url, same_origin, goku = await _discover(client, site, ua)
    hdrs = _api_headers(site, ua, same_origin)
    token = None

    for round_idx in range(2):
        has_token = round_idx > 0
        checksum, encrypted, metrics = _prepare(site, ua, has_token)

        t_inp = time.time()
        resp = await client.get(f"{chal_url}/inputs?client=browser", cookies=cookies, headers=hdrs)
        inp_latency = round((time.time() - t_inp) * 1000, 1)
        inputs = await resp.json()
        challenge = inputs["challenge"]
        try:  # _PATCHED_V2
            decoded = json.loads(base64.b64decode(challenge["input"]))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _p = challenge["input"]
            _pad = "=" * (-len(_p) % 4)
            try:
                decoded = json.loads(base64.urlsafe_b64decode(_p + _pad))
            except Exception:
                log.warning("challenge not decodable, defaults")
                decoded = {"challenge_type": "NetworkBandwidth", "difficulty": 1}
        ctype = decoded.get("challenge_type", "")
        difficulty = decoded.get("difficulty", 1)
        memory = decoded.get("memory", 128)

        log.info("challenge", round=round_idx, type=ctype, difficulty=difficulty)

        if has_token:
            metrics.insert(0, {"name": "0", "value": inp_latency, "unit": "2"})

        endpoint = ENDPOINT.get(ctype, "verify")

        if ctype == "NetworkBandwidth":
            sol_data = _solve_bandwidth(difficulty)
            body, ct = _build_multipart(
                domain, challenge, sol_data, checksum, encrypted, metrics,
                existing_token=None,
                goku_props=goku
            )
        else:
            solution = _solve_pow(challenge["input"], checksum, difficulty, ctype, memory)
            body = _build_body(
                domain, challenge, solution, checksum, encrypted, metrics,
                existing_token=None,
                goku_props=goku
            )
            ct = "text/plain;charset=UTF-8"

        result = await _do_verify(client, chal_url, endpoint, body, cookies, hdrs, ct)

        if round_idx == 0:
            token = result.get("token")
        else:
            token = result.get("token", token)

    log.info("solved", time=f"{time.time() - t0:.2f}s", token=token[:40] if token else "")
    return {"token": token}, client


if __name__ == "__main__":
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
    result, _ = asyncio.run(solve("https://www.booking.com", ua))
    print(result)
