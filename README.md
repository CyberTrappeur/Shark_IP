# Shark_IP 🦈

**Sense the drop of blood in the ocean.** A shark can detect a single drop of
blood diluted in a vast body of water. Shark_IP does the same with information:
it surfaces *every piece of legally obtainable data* about a single IP address
among billions — fast, clean, and **strictly passively**.

Shark_IP is a modular CLI that enriches one IP from several open sources in a
**read-only** way. It never scans or probes the target host — it only reads
public, third-party data *about* the address and prints a clean, categorized
console report (powered by [`rich`](https://github.com/Textualize/rich)).

> Built as an educational / demonstration tool for OSINT and cyber-reconnaissance.

---

## What it shows

| Category | Fields | Source |
|---|---|---|
| **Geolocation** | city, region, country, coordinates, timezone | ip-api.com |
| **Infrastructure** | ASN, ISP, organization, hosting/mobile flags, open ports, services & software banners | ip-api.com, Censys |
| **Linked domains** | TLS certificate SANs, passive-DNS resolutions | Censys, VirusTotal |
| **Reputation & activity** | abuse confidence score, report count, VT detections & community votes | AbuseIPDB, VirusTotal |
| **Risk & network type** | Tor exit, VPN, proxy, relay | Tor list, vpnapi.io, ip-api.com |
| **P2P history** *(optional, sensitive)* | torrent contents historically observed for the IP | IKWYD |

## Sources

| Module | Key required | Free tier | Get a key |
|---|---|---|---|
| ip-api.com | no | yes | — |
| Tor exit list | no | yes | — |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | yes | <https://www.abuseipdb.com/account/api> |
| VirusTotal v3 | `VT_API_KEY` | yes | <https://www.virustotal.com/gui/my-apikey> |
| Censys Platform | `CENSYS_API_TOKEN` (+ optional `CENSYS_ORG_ID`) | yes | <https://platform.censys.io> → user icon → API Access |
| vpnapi.io | `VPNAPI_KEY` | yes | <https://vpnapi.io/dashboard> |
| IKWYD (P2P history) | `IKWYD_API_KEY` | paid/trial | <https://iknowwhatyoudownload.com/en/api/> |

Any module whose key is missing is **politely skipped** — the script never
crashes on a missing key or a failing source. The **IKWYD module is off by
default**: it runs only when you explicitly provide its key.

## Install

```bash
git clone https://github.com/<you>/Shark_IP.git
cd Shark_IP
pip install -r requirements.txt
cp .env.example .env    # then fill in whatever keys you have
```

## Usage

```bash
python shark_ip.py --help                # show all options
python shark_ip.py --setup               # enter/update your API keys
python shark_ip.py 8.8.8.8               # scan an IP
python shark_ip.py 1.1.1.1 --json        # machine-readable output
python shark_ip.py 9.9.9.9 --timeout 15  # slower networks
```

### Setting your API keys

You have two ways to store your keys. Both save them **locally** to a
git-ignored `.env` file — they are never pushed and never leave your machine.
Enter a key once; every later scan reuses it automatically.

**Option A — guided (recommended):**

```bash
python shark_ip.py --setup
```

It asks for each key in turn. Press **Enter** to skip a key you don't have, or
to keep the one already saved (shown masked). Keys you skip simply leave their
module disabled.

**Option B — manual:**

```bash
cp .env.example .env     # Windows PowerShell: Copy-Item .env.example .env
# then open .env in any text editor and paste your keys after the = signs
```

Every key is optional: a module with no key is politely skipped, never fatal.

## Design notes

- One function per source, each returning a normalized `ModuleResult`.
- Strict error handling: a network error, bad JSON, or unexpected exception in
  one module is caught and reported, never fatal.
- `--json` emits the raw structured result for piping into other tools.

---

## ⚖️ Legal & responsible use — read before use

Shark_IP is published for **education, research, and authorized security
assessment only**. By using it you accept the following.

### Scope of the tool

- Shark_IP performs **passive reconnaissance only**. It queries public,
  third-party APIs *about* an IP address. It does **not** connect to, scan,
  port-probe, exploit, or otherwise interact with the target host.
- It returns only information those third-party sources already hold and make
  available. Shark_IP creates no new intrusion.

### An IP address is personal data

- Under EU law, an IP address can be **personal data**, and an IP combined with
  **activity history is personal data**, whether or not you tie it to a name
  (CJEU, *Breyer v. Germany*, C-582/14). Processing it engages the **GDPR** and
  equivalent national laws.
- The **P2P / torrent history module (IKWYD)** is the most sensitive part of
  this tool. It associates observed download activity with an address. It is
  **disabled by default** and must be switched on deliberately. Enable it only
  where you have a **lawful basis** and **authorization**.

### Authorized targets only

- Use Shark_IP **only** against IP addresses that **you own**, or that you have
  **explicit, documented authorization** to investigate (e.g. a signed
  engagement, a client mandate, a bug-bounty scope, your own infrastructure).
- Do **not** use it to profile, surveil, harass, stalk, dox, or make decisions
  about a private individual. Do not use it to build files on people.

### No warranty, no liability

- This software is provided **"as is"**, without warranty of any kind (see
  [LICENSE](LICENSE)).
- **The author and contributors accept no liability** for any use of this tool
  or for any consequence arising from it. **You alone** are responsible for how
  you use Shark_IP and for ensuring your use complies with all laws and terms
  applicable to you.
- You are responsible for complying with the **Terms of Service of every API**
  Shark_IP queries. Those terms, and the data each source returns, are outside
  the author's control and may change.

### Responsible-use summary

> Use it on what is yours or what you are allowed to touch. Stay passive.
> Treat results as personal data. Don't attach a name to an address without a
> reason the law would accept. If in doubt, don't.

Misuse of this tool may be illegal in your jurisdiction and is entirely your
own responsibility.

## License

MIT — see [LICENSE](LICENSE).
