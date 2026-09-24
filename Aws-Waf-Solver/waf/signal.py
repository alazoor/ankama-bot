import uuid
import time
import json
import random
from pathlib import Path

PLUGINS = [
    {"name": "PDF Viewer",                "str": "PDF Viewer "},
    {"name": "Chrome PDF Viewer",         "str": "Chrome PDF Viewer "},
    {"name": "Chromium PDF Viewer",       "str": "Chromium PDF Viewer "},
    {"name": "Microsoft Edge PDF Viewer", "str": "Microsoft Edge PDF Viewer "},
    {"name": "WebKit built-in PDF",       "str": "WebKit built-in PDF "},
]

PLUGIN_STR = "".join(p["str"] for p in PLUGINS)
SCREEN     = "1920-1080-1080-24-*-*-*"

_GPU_POOL = json.loads((Path(__file__).parent / "webgl.json").read_text())

BASE_BINS = [
    14469,36,41,46,47,49,28,22,44,24,38,15,39,49,32,42,31,29,22,33,
    32,27,40,28,47,12,31,32,42,20,27,35,118,22,22,31,22,13,27,26,
    27,17,27,33,15,29,29,30,33,32,27,38,31,16,35,23,22,24,19,18,
    25,23,20,22,102,15,22,13,19,19,18,24,13,26,10,15,26,16,14,19,
    16,20,18,26,18,49,15,19,24,22,19,17,15,20,21,22,103,27,50,38,
    55,31,496,25,19,15,25,24,18,53,32,13,19,19,21,20,29,18,28,30,
    19,15,14,23,28,12,33,131,41,35,33,29,8,15,13,17,28,33,41,21,
    35,23,26,33,19,20,74,34,12,24,15,20,19,71,20,9,20,18,22,84,
    20,19,27,7,31,18,21,24,13,14,40,20,39,16,27,24,29,17,18,27,
    16,14,16,26,13,17,14,22,20,15,20,99,15,9,18,16,15,20,31,13,
    28,35,27,48,52,48,33,47,32,47,42,13,28,21,25,26,30,25,15,23,
    21,27,24,115,41,30,16,20,26,17,24,36,24,32,24,60,28,33,25,37,
    48,32,31,26,19,51,34,50,31,43,43,53,76,57,50,13659,
]

MATH = {
    "tan": "-1.4214488238747245",
    "sin": "0.8178819121159085",
    "cos": "-0.5753861119575491",
}


def _rand_canvas() -> tuple[int, list[int]]:
    bins = []
    for v in BASE_BINS:
        if v > 500:
            bins.append(v + random.randint(-200, 200))
        elif v > 80:
            bins.append(v + random.randint(-15, 15))
        else:
            bins.append(max(1, v + random.randint(-3, 3)))
    h = random.randint(100000000, 999999999)
    return h, bins


def build_signal(site: str, fp_metrics: dict, ua: str) -> dict:
    now = int(time.time() * 1000)
    gpu = random.choice(_GPU_POOL)
    c_hash, c_bins = _rand_canvas()
    return {
        "metrics":      fp_metrics,
        "start":        now,
        "flashVersion": None,
        "plugins":      PLUGINS,
        "dupedPlugins": f"{PLUGIN_STR}||{SCREEN}",
        "screenInfo":   SCREEN,
        "referrer":     "",
        "userAgent":    ua,
        "location":     site,
        "webDriver":    False,
        "capabilities": {
            "css": {
                "textShadow": 1, "WebkitTextStroke": 1, "boxShadow": 1,
                "borderRadius": 1, "borderImage": 1, "opacity": 1,
                "transform": 1, "transition": 1,
            },
            "js": {
                "audio": True, "geolocation": True, "localStorage": "supported",
                "touch": False, "video": True, "webWorker": True,
            },
            "elapsed": fp_metrics["capabilities"],
        },
        "gpu":  gpu,
        "dnt":  None,
        "math": MATH,
        "automation": {
            "wd":      {"properties": {"document": [], "window": [], "navigator": []}},
            "phantom": {"properties": {"window": []}},
        },
        "stealth": {"t1": 0, "t2": 0, "i": 1, "mte": 0, "mtd": False},
        "crypto": {
            "crypto": 1, "subtle": 1,
            "encrypt": True, "decrypt": True, "wrapKey": True, "unwrapKey": True,
            "sign": True, "verify": True, "digest": True,
            "deriveBits": True, "deriveKey": True,
            "getRandomValues": True, "randomUUID": True,
        },
        "canvas": {
            "hash":          c_hash,
            "emailHash":     None,
            "histogramBins": c_bins,
        },
        "formDetected":    False,
        "numForms":        0,
        "numFormElements": 0,
        "be":      {"si": False},
        "end":     now + 1,
        "errors":  [],
        "version": "2.4.0",
        "id":      str(uuid.uuid4()),
    }
