# ⚡ Bug Bounty Scanner CLI

A lightweight, automated bug bounty reconnaissance tool built to run entirely in the terminal — no GUI, no heavy dependencies, and fully compatible with **Termux on Android**.

Written in pure Python 3 using only the standard library, so it works right out of the box without any `pip install` headaches.

---

## 🔍 What It Scans

| Check | Description |
|---|---|
| 🌐 Basic Info | DNS resolution, IP lookup, HTTPS availability |
| 🛡️ Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and more |
| 🔒 SSL / TLS | Protocol version, certificate validity, expiry warning |
| 📂 Sensitive Paths | `.git`, `.env`, `/admin`, `/api-docs`, `/backup.sql`, and 20+ more |
| ⚠️ Reflected XSS | Basic reflected XSS probe via query parameters |
| 🔁 Open Redirect | Common redirect parameter probe |
| 🔑 Info Leaks | AWS keys, SQL errors, stack traces, internal IPs in page body |
| 🌍 CORS | Misconfigured cross-origin resource sharing detection |
| 🍪 Cookies | HttpOnly, Secure, and SameSite flag checks |

Results can be saved to a `.txt` report file at the end of each scan.

---

## 📱 Setup on Termux (Android)

### 1. Install Termux
Download Termux from [F-Droid](https://f-droid.org/packages/com.termux/) (recommended over Play Store).

### 2. Update packages and install Python
```bash
pkg update && pkg upgrade -y
pkg install python git -y
```

### 3. Give Termux storage access
```bash
termux-setup-storage
```
Accept the permission popup when it appears.

### 4. Clone the repository
```bash
git clone https://github.com/YOURUSERNAME/Bug-Bounty-Scanner-CLI.git
cd Bug-Bounty-Scanner-CLI
```

### 5. Run the scanner
```bash
python bugbounty_scanner_cli.py
```

Enter your target URL when prompted (e.g. `https://example.com`) and the scan will begin automatically.

---

## 💻 Setup on Linux / Mac / Windows / Termux

Requires Python 3.6+. 

```bash
git clone https://github.com/YOURUSERNAME/Bug-Bounty-Scanner-CLI.git
cd Bug-Bounty-Scanner-CLI
python3 bugbounty_scanner_cli.py
```

---

## 📄 Example Output

```
──────────────────────────────────────────────────
  1 · Basic Target Info
──────────────────────────────────────────────────
  [*] Target : https://example.com
  [+] Resolved IP : 93.184.216.34
  [+] HTTPS version is reachable

──────────────────────────────────────────────────
  2 · Security Headers
──────────────────────────────────────────────────
  [+] HSTS (Strict-Transport-Security) — present
  [!] CSP (Content-Security-Policy) — MISSING
  [!] Server header leaks: 'Apache/2.4.41'
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes and authorized security testing only**.  
Only scan targets you own or have **explicit written permission** to test.  
Unauthorized scanning may be illegal in your country. The author is not responsible for any misuse.

---

## 📜 License

MIT License — free to use, modify, and distribute.
