import random

COLLECTORS = [
    ("fp2",          "100",       0.5, 3),
    ("browser",      "101",       0,   1),
    ("capabilities", "102",       2,   8),
    ("gpu",          "103",       3,   12),
    ("dnt",          "104",       0,   1),
    ("math",         "105",       0,   1),
    ("screen",       "106",       0,   1),
    ("navigator",    "107",       0,   1),
    ("auto",         "108",       0,   1),
    ("stealth",      "undefined", 1,   4),
    ("subtle",       "110",       0,   1),
    ("canvas",       "111",       80,  200),
    ("formdetector", "112",       0,   3),
    ("be",           "undefined", 0,   1),
]


def _r(lo: float, hi: float) -> float:
    return round(random.uniform(lo, hi), 1)


def build_metrics(has_token: bool = False) -> tuple[list, dict]:
    collectors = [(n, mid, _r(lo, hi)) for n, mid, lo, hi in COLLECTORS]
    fp_metrics = {n: int(v) for n, _, v in collectors}

    enc     = _r(0.5, 3)   # signal encoding time
    crypt   = _r(2, 8)     # signal encryption time
    coll    = sum(v for _, _, v in collectors)
    acq     = round(coll + enc + crypt + _r(2, 6), 1)  # signal acquisition = collectors + enc + encrypt + overhead
    chall   = _r(2, 8)     # pow solve time
    cookie  = _r(0.1, 1)   # aws-waf-token cookie fetch
    total   = round(acq + chall + cookie, 1)            # total = acq + challenge + cookie

    m = [{"name": "2", "value": enc, "unit": "2"}]                          # SignalEncodingTime
    m += [{"name": mid, "value": v, "unit": "2"} for _, mid, v in collectors]
    m += [
        {"name": "3", "value": crypt,                 "unit": "2"},         # SignalEncryptionTime
        {"name": "7", "value": 1 if has_token else 0, "unit": "4"},         # ExistingTokenFound (count)
        {"name": "1", "value": acq,                    "unit": "2"},        # SignalAcquisitionTime
        {"name": "4", "value": chall,                  "unit": "2"},        # ChallengeExecutionTime
        {"name": "5", "value": cookie,                 "unit": "2"},        # CookieFetchTime
        {"name": "6", "value": total,                  "unit": "2"},        # TotalTime
        {"name": "8", "value": 1,                      "unit": "4"},        # ChallengeExpiredRetryBucket (count)
    ]

    return m, fp_metrics