# Sanitize — Zero-Dependency Privacy Engineering, Media Metadata Scrubbing & PII Redaction Engine

**Production DevSecOps Privacy Gateway, Pure-Python Binary Media Scrubber, Dotfile Redactor, and Git History Forensic Auditor**

`sanitize-guard` is an autonomous, zero-dependency privacy engineering toolkit written in pure Python 3.10+. It performs deep deterministic detection of machine-specific filesystem paths (`/home/<user>`, `/Users/<user>`, `C:\Users\<user>`), local OS usernames, hostnames, RFC 1918 private IPv4 subnets, EUI-48 MAC addresses, cryptographic private keys, and API tokens. It features a bit-accurate binary parser and stripper for PNG ancillary chunks, JPEG EXIF/GPS segments, and GIF comment blocks, alongside automated dotfile public template generation and git commit-graph forensic auditing with OASIS SARIF v2.1.0 reporting.

![Sanitize Guard Banner](assets/banner.svg)

---

## Table of Contents

1. [Architectural Overview](#1-architectural-overview)
2. [Mathematical & Binary Foundations](#2-mathematical--binary-foundations)
   - [2.1 PNG Chunk Stripping & CRC32 Cyclic Redundancy Algebra](#21-png-chunk-stripping--crc32-cyclic-redundancy-algebra)
   - [2.2 JPEG Marker Parsing & Entropy Byte-Stuffing Invariants](#22-jpeg-marker-parsing--entropy-byte-stuffing-invariants)
   - [2.3 GIF 89a Comment Extension Sub-Block Dissection](#23-gif-89a-comment-extension-sub-block-dissection)
   - [2.4 Subnet Mask Algebra: RFC 1918 Private vs RFC 5737 Documentation Classification](#24-subnet-mask-algebra-rfc-1918-private-vs-rfc-5737-documentation-classification)
3. [Detection Taxonomy & Rule Matrix](#3-detection-taxonomy--rule-matrix)
4. [Dotfile Public Template Generation](#4-dotfile-public-template-generation)
5. [Git Commit-Graph Forensics & Automated Hooks](#5-git-commit-graph-forensics--automated-hooks)
6. [CLI Reference & Usage](#6-cli-reference--usage)
7. [OASIS SARIF v2.1.0 & CI/CD Matrix](#7-oasis-sarif-v210--cicd-matrix)
8. [Zero-Leak Security Audit Gate & Verification](#8-zero-leak-security-audit-gate--verification)

---

## 1. Architectural Overview

`sanitize-guard` is engineered to operate in air-gapped forensic environments, restricted CI/CD runner pipelines, and developer pre-commit hooks with zero third-party package dependencies.

```
Sanitize/
├── pyproject.toml              # Packaging metadata & CLI script entrypoints
├── .gitignore                  # Git hygiene and exclusion rules
├── README.md                   # Technical specification and mathematical documentation
├── sanitize_guard/             # Core production package
│   ├── __init__.py             # Public API exports and version specification
│   ├── pii_engine.py           # Regex & heuristic PII, path, IP, MAC & secret detector
│   ├── media_scrubber.py       # Pure-Python binary parser & stripper for PNG/JPEG/GIF
│   ├── dotfile_redactor.py     # Template transformer for shell, git, WM, and env configs
│   ├── sarif.py                # OASIS SARIF v2.1.0 & high-contrast ASCII table formatters
│   └── cli.py                  # CLI dispatcher (audit, scrub-media, redact-dotfiles, check-git, install-hook)
├── samples/
│   └── synthetic_dotfiles/     # Synthetic vulnerable fixtures (.zshrc, .gitconfig, hyprland.conf, .env)
├── scripts/
│   ├── security-audit.sh       # Zero-leak DevSecOps gate (paths, usernames, credentials, emojis)
│   └── ci-matrix.yml           # GitHub Actions multi-OS / multi-Python matrix workflow
├── assets/
│   ├── banner.svg              # Vector branding and feature matrix graphic
│   ├── preview.png             # High-contrast metadata-stripped raster asset
│   └── demo.gif                # Terminal demonstration animation
└── tests/
    ├── __init__.py             # Test package initialization
    └── test_sanitize.py        # 22 automated unit & integration tests (100% pass rate)
```

---

## 2. Mathematical & Binary Foundations

### 2.1 PNG Chunk Stripping & CRC32 Cyclic Redundancy Algebra

The Portable Network Graphics (PNG, ISO/IEC 15948) format structures data as an 8-byte magic header (`89 50 4E 47 0D 0A 1A 0A`) followed by a contiguous sequence of chunks. Each chunk conforms to the strict 4-tuple layout:

$$\text{Chunk} = \langle \text{Length}_{4\text{B}}, \text{Type}_{4\text{B}}, \text{Data}_{L\text{B}}, \text{CRC32}_{4\text{B}} \rangle$$

The cyclic redundancy check ($\text{CRC32}$) is calculated over the concatenation of the 4-byte chunk type and the $L$-byte chunk data (excluding the length field). It operates over the Galois Field $\text{GF}(2)$ using the IEEE 802.3 generator polynomial $G(x)$:

$$G(x) = x^{32} + x^{26} + x^{23} + x^{22} + x^{16} + x^{12} + x^{11} + x^{10} + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1$$

In bitwise representation, $G = \mathtt{0xEDB88320}$. The remainder polynomial $R(x)$ computed via modulo-2 division is stored as a 4-byte big-endian integer:

$$R(x) = \left( x^{32} \cdot D(x) \right) \pmod{G(x)}$$

#### Chunk Stripping Policy
`media_scrubber.py` validates the CRC32 of every incoming chunk before deciding whether to retain or strip it:

| Chunk Type | Purpose | Criticality | Scrubber Action |
| :--- | :--- | :--- | :--- |
| `IHDR` | Image header (width, height, bit depth, color type, compression) | Critical | **Preserved & Verified** |
| `PLTE` | Palette index table | Critical (Index Color) | **Preserved & Verified** |
| `IDAT` | Deflate-compressed raster scanline data | Critical | **Preserved & Verified** |
| `IEND` | End-of-file trailer | Critical | **Preserved & Verified** |
| `tEXt` | Latin-1 uncompressed key/value metadata (`Author`, `Software`) | Ancillary | **Stripped** |
| `zTXt` | Zlib-compressed textual metadata | Ancillary | **Stripped** |
| `iTXt` | UTF-8 international text, XMP serialization, Dublin Core | Ancillary | **Stripped** |
| `eXIf` | Raw EXIF metadata block (ISO 12234-2, camera tags, GPS) | Ancillary | **Stripped** |
| `tIME` | Last image modification timestamp | Ancillary | **Stripped** |

Stripping metadata chunks removes embedded tracking identifiers without recompressing or quantizing raster scanlines, ensuring lossless image fidelity and zero generation loss.

---

### 2.2 JPEG Marker Parsing & Entropy Byte-Stuffing Invariants

JPEG (ITU-T T.81 / ISO/IEC 10918-1) files commence with the Start of Image (SOI) marker `0xFF 0xD8` and conclude with the End of Image (EOI) marker `0xFF 0xD9`. Variable-length marker segments are encoded as:

$$\text{Segment} = \langle \mathtt{0xFF}, \text{Marker}_{1\text{B}}, \text{Length}_{2\text{B}}, \text{Payload}_{(L-2)\text{B}} \rangle$$

where $\text{Length}$ includes the 2 length bytes themselves ($L \ge 2$).

#### Scrubber Stripping Targets
`media_scrubber.py` traverses marker segments from offset 2, removing:
- **`APP1` (`0xFF 0xE1`)**: EXIF metadata, GPS latitude/longitude/altitude IFDs, camera serial numbers, and Adobe XMP packets.
- **`APP2` (`0xFF 0xE2`)**: ICC color profiles and Flashpix metadata.
- **`COM` (`0xFF 0xFE`)**: Arbitrary ASCII text comments.

#### Entropy Scan Preservation & Byte-Stuffing Invariant
When the Start of Scan (SOS, `0xFF 0xDA`) marker is reached, the Huffman- or arithmetic-coded bitstream begins. The parser preserves the standard JPEG byte-stuffing invariant:
- Literal `0xFF` data bytes in the entropy stream are escaped by a zero byte (`0xFF 0x00`).
- Restart markers (`0xFF 0xD0` through `0xFF 0xD7`) carry no length fields and synchronize entropy decode intervals.
- The scan continues until a non-stuffed marker occurs (typically `0xFF 0xD9` EOI).

The scrubber retains the entire entropy payload verbatim, truncating zero raster bits and preventing desynchronization.

---

### 2.3 GIF 89a Comment Extension Sub-Block Dissection

The Graphics Interchange Format (GIF87a/GIF89a) encodes metadata through extension blocks introduced by the byte `0x21`:

$$\text{Extension} = \langle \mathtt{0x21}, \text{Label}_{1\text{B}}, \{\text{SubBlockLength}_{1\text{B}}, \text{SubBlockData}\}^*, \mathtt{0x00} \rangle$$

The comment extension is designated by label `0xFE`:

```
Offset   Bytes               Interpretation
+00      0x21                Extension Introducer
+01      0xFE                Comment Extension Label
+02      N (0x01 - 0xFF)     Length of first sub-block
+03      Data[0..N-1]        Text comment payload
...      ...                 Subsequent sub-blocks
+K       0x00                Block Terminator
```

`media_scrubber.py` strips all `0x21 0xFE` Comment Extension blocks while strictly preserving:
- **`0x21 0xF9` (Graphic Control Extension)**: Frame delay time ($t / 100\text{ s}$), disposal method, and transparent color index.
- **`0x21 0xFF` (Application Extension)**: `NETSCAPE2.0` animation iteration loops.
- **`0x2C` (Image Descriptor)**: Local color tables, interlacing flags, and LZW raster sub-blocks.

---

### 2.4 Subnet Mask Algebra: RFC 1918 Private vs RFC 5737 Documentation Classification

IPv4 addresses $\mathbf{a} \in \mathbb{N}_{\le 2^{32}-1}$ are evaluated under bitwise masking operations against network prefixes $\mathbf{n} / m$:

$$\mathbf{a} \in \text{Subnet}(\mathbf{n}, m) \iff (\mathbf{a} \land \mathbf{m}) = \mathbf{n}, \quad \text{where } \mathbf{m} = \sum_{k=32-m}^{31} 2^k$$

#### RFC 1918 Private Subnets (Classified as Leaks)
Private IPv4 ranges leak internal host counts, router interfaces, homelab topologies, and VPC network segments:
- `10.0.0.0/8` ($\mathbf{m} = \mathtt{0xFF000000}$): Enterprise subnets.
- `172.16.0.0/12` ($\mathbf{m} = \mathtt{0xFFF00000}$): Docker, Kubernetes, and virtualization overlays.
- `192.168.0.0/16` ($\mathbf{m} = \mathtt{0xFFFF0000}$): SOHO LANs and IoT devices.
- `100.64.0.0/10` ($\mathbf{m} = \mathtt{0xFFC00000}$, RFC 6598): Shared Carrier-Grade NAT.

#### RFC 5737 Documentation Networks (Safe for Public Use)
RFC 5737 explicitly reserves three blocks for documentation, code examples, and public configuration templates:
- `192.0.2.0/24` (TEST-NET-1)
- `198.51.100.0/24` (TEST-NET-2)
- `203.0.113.0/24` (TEST-NET-3)
- IPv6 RFC 3849: `2001:db8::/32`

`pii_engine.py` classifies RFC 5737 addresses as `SAN-005` with `Severity.INFO` (`is_leak = False`). When `dotfile_redactor.py` encounters an RFC 1918 address $\mathbf{x} = \langle x_1, x_2, x_3, x_4 \rangle$, it maps it deterministically into TEST-NET-2:

$$\mathbf{x}_{\text{sanitized}} = \langle 198, 51, 100, x_4 \rangle$$

---

## 3. Detection Taxonomy & Rule Matrix

| Rule ID | Rule Name | Target Artifact | Severity | Default Redaction Placeholder |
| :--- | :--- | :--- | :--- | :--- |
| **`SAN-001`** | `MACHINE_PATH` | `/home/<user>`, `/Users/<user>`, `C:\Users\<user>` | **HIGH** | `${HOME}` or `~` |
| **`SAN-002`** | `OS_USERNAME` | Local system username in text/configs | **MEDIUM** | `<user>` |
| **`SAN-003`** | `HOSTNAME` | Local workstation / internal hostname | **MEDIUM** | `localhost` |
| **`SAN-004`** | `RFC1918_PRIVATE_IP` | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | **MEDIUM** | `198.51.100.<octet>` |
| **`SAN-005`** | `RFC5737_DOC_IP` | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | **INFO** | *(None - Safe Documentation)* |
| **`SAN-006`** | `PUBLIC_IP` | Public routable IPv4 endpoints | **LOW** | `198.51.100.1` |
| **`SAN-007`** | `MAC_ADDRESS` | EUI-48 physical hardware address | **MEDIUM** | `02:00:00:00:00:01` |
| **`SAN-008`** | `PRIVATE_KEY` | RSA, EC, DSA, OPENSSH, PGP Private Keys | **CRITICAL** | `-----BEGIN PRIVATE KEY-----\n<REDACTED>\n-----END PRIVATE KEY-----` |
| **`SAN-009`** | `API_TOKEN` | GitHub, AWS, OpenAI, Anthropic, Slack | **HIGH** | `<REDACTED_API_KEY>` |
| **`SAN-010`** | `MEDIA_METADATA` | PNG chunks (`tEXt`, `iTXt`), JPEG EXIF/GPS, GIF comments | **MEDIUM** | *(Stripped at byte level)* |

---

## 4. Dotfile Public Template Generation

Publishing developer dotfiles on GitHub frequently leads to identity leaks, private network reconnaissance, and credential theft. `sanitize-guard redact-dotfiles` sanitizes live configuration files into production-grade templates while maintaining syntax validity and formatting:

```bash
# Redact dotfiles in-place or generate .template files
sanitize redact-dotfiles ~/.zshrc ~/.gitconfig ~/.config/hypr/hyprland.conf .env
```

### Transformations Applied:
- **ZSH / Bash (`.zshrc`, `.bashrc`)**:
  - Replaces `/home/<user>/bin` with `${HOME}/bin`.
  - Maps LAN cluster endpoints `192.168.1.105` to `198.51.100.105`.
  - Replaces API token exports with placeholder strings.
- **Git (`.gitconfig`)**:
  - Replaces personal author names with public handle `1MEshh`.
  - Enforces `152591660+1MEshh@users.noreply.github.com` email address.
  - Masks personal GPG signing keys: `# signingkey = <YOUR_GPG_KEY_ID>`.
- **Window Managers (`hyprland.conf`, `sway`, `i3`)**:
  - Masks monitor EDID hardware serial descriptors: `desc:<MONITOR_HARDWARE_DESCRIPTION>`.
  - Sanitizes user autostart script paths: `exec-once = ~/.config/hypr/scripts/init.sh`.
- **Environment Files (`.env`, `.env.production`)**:
  - Rewrites database URIs: `postgres://app_user:<REDACTED_PASSWORD>@198.51.100.10:5432/app_db`.

---

## 5. Git Commit-Graph Forensics & Automated Hooks

Credentials removed from the current working tree often persist in git history. `sanitize-guard check-git` inspects the commit DAG:

1. **Author & Committer Identity Verification**:
   - Asserts that every commit author email adheres to the noreply domain (`*@users.noreply.github.com`).
2. **Commit Message Scanning**:
   - Scans commit subjects and bodies for accidentally pasted file paths, hostnames, or API tokens.
3. **Commit Patch Forensics**:
   - Executes `git diff-tree -r -p` for recent commits, inspecting added lines (`+`) for private keys, AWS tokens, and hardcoded home directories.

### Automated Hook Installation
To prevent accidental leaks before git commits or pushes are finalized:

```bash
# Install automated pre-push zero-leak gate
sanitize install-hook --hook pre-push
```

The installed hook executes `sanitize audit . --fail-on high` and `sanitize check-git --fail-on-leak`, blocking git pushes if any leaks are detected.

---

## 6. CLI Reference & Usage

### 6.1 Subcommand: `audit`
Scans directories, source files, and image metadata for privacy leaks.

```bash
# Standard terminal scan with ASCII table output
sanitize audit . --fail-on medium

# Export SARIF v2.1.0 for CI/CD integration
sanitize audit . --format sarif --output report.sarif

# Scan with explicit username and hostname targets
sanitize audit . --target-user devuser --target-host workstation-alpha
```

### 6.2 Subcommand: `scrub-media`
Parses and strips metadata chunks from PNG, JPEG, and GIF files.

```bash
# Strip metadata from assets directory in-place
sanitize scrub-media assets/ --inplace

# Dry-run inspection showing chunks that would be removed
sanitize scrub-media assets/ --dry-run --verbose

# Scrub images and save to an output directory
sanitize scrub-media /path/to/raw_photos/ --output /path/to/cleaned/
```

### 6.3 Subcommand: `redact-dotfiles`
Converts active configuration files into public templates.

```bash
# Generate .template files alongside existing dotfiles
sanitize redact-dotfiles ~/.zshrc ~/.gitconfig

# Directly overwrite target dotfiles in-place
sanitize redact-dotfiles ./samples/synthetic_dotfiles/ --inplace
```

### 6.4 Subcommand: `check-git`
Forensic commit-graph verification.

```bash
# Audit the last 50 commits on the current branch
sanitize check-git --commits 50 --fail-on-leak
```

### 6.5 Subcommand: `install-hook`
Installs git hook security gates.

```bash
# Install pre-push gate
sanitize install-hook --hook pre-push

# Install pre-commit gate
sanitize install-hook --hook pre-commit
```

---

## 7. OASIS SARIF v2.1.0 & CI/CD Matrix

`sanitize-guard` natively produces compliant OASIS SARIF v2.1.0 reports for GitHub Code Scanning, GitLab SAST, and SonarQube:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "sanitize-guard",
          "version": "1.0.0",
          "informationUri": "https://github.com/1MEshh/Sanitize",
          "rules": [
            {
              "id": "SAN-001",
              "name": "MachineSpecificPathLeak",
              "shortDescription": {
                "text": "Machine-specific filesystem path leak (/home/<user>, /Users/<user>)"
              },
              "defaultConfiguration": {
                "level": "error"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "SAN-001",
          "level": "error",
          "message": {
            "text": "Machine-specific filesystem path leak detected: /home/<user>/bin"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "samples/synthetic_dotfiles/sample.zshrc"
                },
                "region": {
                  "startLine": 5,
                  "startColumn": 15
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

The GitHub Actions workflow in `scripts/ci-matrix.yml` validates multi-OS compatibility across Ubuntu and macOS on Python 3.10 through 3.14.

---

## 8. Zero-Leak Security Audit Gate & Verification

The repository enforces a strict zero-leak security gate executed via `scripts/security-audit.sh`. It enforces:
1. Zero machine-specific home paths in production source files.
2. Zero OS username leaks (`whoami`).
3. Zero workstation hostname leaks (`hostname`).
4. Zero active API credentials.
5. Strict zero-emoji compliance.
6. Git committer email privacy (`*@users.noreply.github.com`).
7. 100% pass rate across the 22 automated unit tests.
8. Self-scan of `sanitize_guard` with 0 findings.

### Running Verification Locally

```bash
# Execute automated unit test suite
python3 -m unittest discover -s tests -v

# Execute complete zero-leak DevSecOps security gate
bash scripts/security-audit.sh
```

---

## License

MIT License. Designed and maintained by `1MEshh <152591660+1MEshh@users.noreply.github.com>`.
