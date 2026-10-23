# QuantumVault

A local, **quantum-resistant** password generator with an encrypted vault and a web dashboard.

- Generates passwords with **at least 256 bits of entropy** — still **128-bit secure against a quantum computer**.
- Stores them in a vault encrypted with **AES-256-GCM**, keyed by **Argon2id** from your master password.
- Runs **entirely on your machine** (`127.0.0.1` only). No cloud, no telemetry, no network calls.
- Dashboard: create passwords with a title and notes, see them all in one place, reveal, copy, rename, regenerate and delete.

## Why it resists quantum computers

| Threat | Quantum attack | What QuantumVault does |
| --- | --- | --- |
| Guessing a generated password | **Grover's algorithm** turns a search over 2ⁿ possibilities into ~2ⁿ⁄² steps | Every password has **≥ 256 bits** of entropy, so a quantum attacker still faces **≥ 2¹²⁸** operations. The generator *refuses* weaker settings. |
| Breaking the vault encryption | Grover halves the key length of symmetric ciphers | **AES-256** keeps 128-bit post-quantum security — the level NIST recommends for the quantum era. |
| Breaking public-key crypto (RSA, ECC) | **Shor's algorithm** breaks these completely | **No public-key cryptography is used anywhere**, so Shor's algorithm has nothing to attack. |
| Brute forcing the master password | Grover + massive parallel hardware | **Argon2id** with 256 MiB of memory and 4 passes per guess makes every attempt expensive on any hardware. |

For scale: 2¹²⁸ operations at a (wildly optimistic) billion billion quantum operations per second would take about 10¹³ years — nearly a thousand times the age of the universe.

### How passwords are generated

- Randomness comes only from the operating system's CSPRNG (Python's `secrets` module).
- Each character is drawn uniformly with rejection sampling — no modulo bias.
- When several character sets are enabled, each one is guaranteed to appear. This is done by redrawing the *whole* password until it qualifies, which keeps the result uniform over all valid passwords.
- The reported entropy is the exact value (computed by inclusion–exclusion), not an estimate.
- The default is 48 characters from all 94 printable ASCII characters ≈ **314 bits** (157-bit post-quantum).

## Requirements

- Python 3.10 or newer

## Installation

```bash
git clone https://github.com/D3NIZ-D/quantumvault.git
cd quantumvault
python -m venv .venv
```

Activate the virtual environment:

```bash
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python -m quantumvault
```

Your browser opens `http://127.0.0.1:8765/`. On the first run you create a master password; after that you unlock the vault with it.

| Option | Default | Description |
| --- | --- | --- |
| `--port` | `8765` | Port for the local dashboard |
| `--vault` | `~/.quantumvault/vault.json` | Location of the encrypted vault file |
| `--idle-timeout` | `600` | Lock the vault after this many idle seconds |
| `--no-browser` | off | Don't open a browser automatically |

### Dashboard

- **New password** — give it a title (and optional notes), pick a length and character sets, and press *Generate & save*. A live meter shows the entropy; settings below 256 bits are blocked.
- **Your passwords** — every saved password, masked by default. Search by title or notes. For each entry you can:
  - 👁 reveal (auto-hides after 20 s)
  - copy (clipboard is cleared after 30 s)
  - rename
  - regenerate (replace with a fresh password)
  - delete
- **Lock vault** — wipes the key from memory. The vault also locks itself after the idle timeout.

## Security details

**Vault file.** A single JSON document containing the Argon2id salt and parameters, a random 96-bit nonce, and the AES-256-GCM ciphertext of all entries. Titles, notes and passwords are all encrypted. The header is authenticated as associated data, so any tampering is detected. A new nonce is used on every save, and writes are atomic so a crash can't corrupt the vault.

**Local web server hardening.**
- Listens on `127.0.0.1` only — not reachable from your network.
- Host header allow-list to block DNS-rebinding attacks.
- Per-launch CSRF token and Origin check on every state-changing request.
- Session cookie is random, `HttpOnly` and `SameSite=Strict`.
- Strict Content-Security-Policy (no inline scripts), `X-Frame-Options: DENY`, `Cache-Control: no-store`.
- Exponential back-off after repeated wrong master passwords.

**Your master password matters.** The vault is exactly as strong as your master password. Use a long, random passphrase — for example 8 or more randomly chosen words — and keep it somewhere safe. **It cannot be recovered.** If you lose it, the vault cannot be decrypted by anyone, including you.

**Back up your vault.** Copy `~/.quantumvault/vault.json` to a safe place regularly. The file is useless without the master password.

**Limitations.** QuantumVault protects data at rest and keeps the dashboard private to your machine. It cannot protect you if your computer is already compromised (malware, keyloggers). Python cannot guarantee that secrets are wiped from RAM after locking.

## Development

```bash
pip install -r requirements.txt pytest
python -m pytest
```

Project layout:

```
quantumvault/
├── generator.py   # password generation and entropy policy
├── vault.py       # Argon2id + AES-256-GCM encrypted storage
├── server.py      # local Flask API and security hardening
├── __main__.py    # command-line entry point
├── templates/     # dashboard HTML
└── static/        # dashboard JS / CSS
tests/             # pytest suite
```

## License

[MIT](LICENSE)
