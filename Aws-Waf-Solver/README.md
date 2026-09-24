<div align="center">

# aws-waf-solver

open source solver for AWS WAF browser challenges + deobfuscator for the challenge.js script

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white&labelColor=0a0a0f)](https://python.org)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=flat-square&logo=node.js&logoColor=white&labelColor=0a0a0f)](https://nodejs.org)
[![License](https://img.shields.io/badge/License-MIT-e040fb?style=flat-square&labelColor=0a0a0f)](LICENSE)

</div>

---

## what is this

solves AWS WAF browser challenges without a browser. handles HashcashScrypt, SHA256, and NetworkBandwidth challenge types. generates realistic browser fingerprints so tokens pass server-side validation.

also includes a deobfuscator for the `challenge.js` script.

---

## how it works

1. discovers the challenge url from the page
2. solves the proof of work (scrypt, sha256, or bandwidth)
3. generates a realistic browser fingerprint
4. submits solution to get back a valid `aws-waf-token`

---

## setup

```bash
pip install rnet pyscrypt structlog
```

for the deobfuscator:
```bash
cd deobf
npm install @babel/parser @babel/traverse @babel/generator @babel/types
```

---

## usage

### solver

```python
import asyncio
from waf.solver import solve

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"

async def main():
    result, client = await solve("https://www.booking.com", UA)
    print(result)

asyncio.run(main())
```

output:
```
2026-03-24 16:48:51 [info     ] challenge                      difficulty=1 round=0 type=NetworkBandwidth
2026-03-24 16:48:51 [info     ] challenge                      difficulty=1 round=1 type=NetworkBandwidth
2026-03-24 16:48:51 [info     ] solved                         time=0.42s token=1f4c91d7-3103-4b01-a06f-163b85d1d0cf:Hgo
{'token': '1f4c91d7-3103-4b01-a06f-163b85d1d0cf:HgoAagRNx4jMAAAA:tOJ9eADeb8wz...'}
```

with proxy:
```python
result, client = await solve("https://www.booking.com", UA, proxy="socks5://host:port")
```

you can also reuse the client (keeps cookies/session):
```python
result, client = await solve("https://www.booking.com", UA)
# client is an rnet.Client with cookie_store enabled
# use it for subsequent requests
resp = await client.get("https://www.booking.com/whatever")
```

### deobfuscator

feed it the obfuscated `challenge.js` from any AWS WAF protected site:

```bash
cd deobf
node deobf.js challenge.js
```

output:
```
deobfuscating challenge.js...

  rotation: 471ms | blocks=881 wrappers=148
  strings: 128ms | 2779
  proxy-objects: 367ms | 315
  props+hex: 129ms | {"props":17581,"hex":28280}
  const-fold: 331ms | 2742
  ...

done in 2374ms -> challenge.clean.js
```

what it does:
- resolves all string array rotations (the `a0_0x` accessor pattern)
- inlines proxy/wrapper functions (`obj['abc'](x, y)` -> `x + y`)
- decodes base64 property names
- folds constants and simplifies dead branches
- converts hex literals to decimal
- expands comma sequences
- inlines constant arrays
- converts bracket notation to dot notation (`obj['foo']` -> `obj.foo`)

---

## project structure

```
.
├── main.py                  # example usage
├── waf/
│   ├── solver.py            # main solver - discovery, pow, verify flow
│   ├── crypto.py            # aes-gcm encryption for fingerprint payload
│   ├── signal.py            # browser fingerprint generation
│   ├── metrics.py           # timing metrics that mimic real browser
│   └── webgl.json           # gpu string pool for webgl fingerprint
└── deobf/
    ├── deobf.js             # entry point
    └── lib/
        ├── utils.js          # identifier checks, base64, constant eval
        ├── rotation.js       # string array + accessor vm bootstrap
        ├── resolver.js       # resolve obfuscated string calls
        └── transforms.js     # proxy inlining, folding, cleanup
```

---

## contact

<div align="center">

[![Discord](https://img.shields.io/badge/Discord-switch3301-5865F2?style=flat-square&logo=discord&logoColor=white&labelColor=0a0a0f)](https://discord.com/users/1168899693447741472)
&nbsp;
[![Telegram](https://img.shields.io/badge/Telegram-switch3301-2CA5E0?style=flat-square&logo=telegram&logoColor=white&labelColor=0a0a0f)](https://t.me/switch3301)
&nbsp;
[![Discord Server](https://img.shields.io/badge/Server-JS%20Reversing-5865F2?style=flat-square&logo=discord&logoColor=white&labelColor=0a0a0f)](https://discord.gg/jsreversing)

</div>

---

<div align="center">
  <sub>for educational and research purposes</sub>
</div>
