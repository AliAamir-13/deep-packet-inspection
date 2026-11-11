# DPI Engine (Python)

A **Deep Packet Inspection** engine written in pure Python. It reads a Wireshark capture (`.pcap`), identifies which application each connection belongs to (YouTube, Facebook, GitHub, ...), applies blocking rules, writes the filtered traffic to a new `.pcap`, and prints a report.

This is a Python port of the C++ project [perryvegehan/Packet_analyzer](https://github.com/perryvegehan/Packet_analyzer). The architecture and behaviour follow the original multi-threaded engine (`dpi_mt.cpp`).

---

## Features

- Parses **Ethernet → IPv4 → TCP/UDP** headers from raw bytes (no external libraries)
- Extracts the **SNI** (domain name) from TLS Client Hello packets, so HTTPS traffic can be identified even though it is encrypted
- Extracts the **Host** header from plain HTTP requests
- Classifies traffic: Google, YouTube, Facebook, Instagram, WhatsApp, Twitter/X, Netflix, Amazon, Microsoft, Apple, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, Cloudflare, DNS, HTTP, HTTPS
- **Flow tracking** by 5-tuple (src IP, dst IP, src port, dst port, protocol)
- **Blocking rules** by source IP, application, or domain substring
- **Multi-threaded** pipeline (load balancers + fast-path workers) or a **single-threaded** mode
- Detailed report: packet counts, per-thread stats, application breakdown, detected domains
- Standard library only, nothing to `pip install`

---

## How it works

```
                 ┌───────────────┐
                 │ Reader (main) │  reads PCAP, parses headers
                 └───────┬───────┘
                         │ hash(5-tuple) % num_lbs
            ┌────────────┴────────────┐
            ▼                         ▼
      ┌───────────┐             ┌───────────┐
      │   LB 0    │             │   LB 1    │   Load Balancers
      └─────┬─────┘             └─────┬─────┘
            │ same 5-tuple → same FP  │
        ┌───┴───┐                 ┌───┴───┐
        ▼       ▼                 ▼       ▼
     ┌─────┐ ┌─────┐           ┌─────┐ ┌─────┐
     │ FP0 │ │ FP1 │           │ FP2 │ │ FP3 │   Fast Paths (DPI work)
     └──┬──┘ └──┬──┘           └──┬──┘ └──┬──┘
        └───────┴────────┬────────┴───────┘
                         ▼
                 ┌───────────────┐
                 │ Output Writer │  writes forwarded packets to PCAP
                 └───────────────┘
```

**Per packet, a Fast Path does:**

1. Look up (or create) the flow for the packet's 5-tuple
2. Classify the flow: TLS SNI on port 443, HTTP Host on port 80, DNS on port 53, otherwise a port-based fallback
3. Check the blocking rules (IP → app → domain)
4. Forward the packet, or drop it if its flow is blocked

Blocking works at **flow level**: once a flow is identified as blocked, every later packet of that flow is dropped. The same 5-tuple always goes to the same worker, so each worker can keep its own flow table without locks.

---

## Project structure

```
Packet_analyzer/
├── dpi_engine.py          # Python DPI engine (this project)
├── generate_test_pcap.py  # Creates test_dpi.pcap with sample traffic
├── test_dpi.pcap          # Sample capture (TLS, HTTP, DNS)
├── README.md
├── include/, src/         # Original C++ implementation (reference, from upstream)
└── CMakeLists.txt         # Original C++ build file
```

### Inside `dpi_engine.py`

| Component | Purpose |
|---|---|
| `PcapReader` | Reads PCAP files (both byte orders) |
| `parse_packet()` | Ethernet, IPv4, TCP/UDP parsing |
| `extract_sni()` | SNI from TLS Client Hello |
| `extract_http_host()` | Host header from HTTP requests |
| `extract_dns_query()`, `extract_quic_sni()` | Extra helpers (ported, not used by the default classifier) |
| `AppType`, `sni_to_app_type()` | Application types and domain → app mapping |
| `Rules` | IP, app and domain blocking rules |
| `Flow`, `PacketProcessor` | Flow table and per-packet processing |
| `LoadBalancer`, `FastPath`, `OutputWriter` | Pipeline threads |
| `DPIEngine` | Orchestrator and report printing |

---

## Requirements

- Python 3.8 or newer
- A `.pcap` capture file (Wireshark: *File → Save As → Wireshark/tcpdump - pcap*; `.pcapng` is not supported)

---

## Installation

```bash
git clone https://github.com/AliAamir-13/deep-packet-inspection.git
cd deep-packet-inspection
```

Optional virtual environment (Windows PowerShell):

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned   # only if activation is blocked
.venv\Scripts\activate
```

---

## Usage

```bash
python dpi_engine.py <input.pcap> <output.pcap> [options]
```

### Options

| Option | Description | Default |
|---|---|---|
| `--block-ip <ip>` | Block all traffic from this source IP (repeatable) | none |
| `--block-app <app>` | Block an application, e.g. `YouTube` (repeatable, case-insensitive) | none |
| `--block-domain <dom>` | Block any SNI/Host containing this text (repeatable) | none |
| `--lbs <n>` | Number of load balancer threads | 2 |
| `--fps <n>` | Fast-path threads per load balancer | 2 |
| `--simple` | Single-threaded mode | off |

### Examples

```bash
# Analyse only, no blocking
python dpi_engine.py test_dpi.pcap output.pcap

# Block YouTube and TikTok, one IP, and any domain containing "facebook"
python dpi_engine.py test_dpi.pcap output.pcap \
    --block-app YouTube --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook

# 4 load balancers x 4 fast paths
python dpi_engine.py input.pcap output.pcap --lbs 4 --fps 4

# Single-threaded
python dpi_engine.py test_dpi.pcap output.pcap --simple
```

### Generate test data

```bash
python generate_test_pcap.py
```

---

## Sample output

```
╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                             ║
║ Total Bytes:                5738                             ║
║ TCP Packets:                  73                             ║
║ UDP Packets:                   4                             ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    70                             ║
║ Dropped:                       7                             ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                      ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                    ║
║ Unknown              16  20.8% ####                          ║
║ DNS                   4   5.2% #                             ║
║ YouTube               1   1.3%  (BLOCKED)                    ║
║ ...                                                          ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - github.com -> GitHub
  ...
```

(Output above uses `--block-app YouTube --block-ip 192.168.1.50 --block-domain facebook` on `test_dpi.pcap`.)

---

## Verification against the C++ original

On `test_dpi.pcap` with the rules above, the Python engine and the original C++ `dpi_mt` produce:

| Metric | C++ | Python |
|---|---|---|
| Forwarded packets | 70 | 70 |
| Dropped packets | 7 | 7 |
| Application breakdown | same | same |
| Packets written to output PCAP | same set | same set |

---

## Differences from the C++ version

| Area | C++ | Python |
|---|---|---|
| Shutdown | Sleeps 500 ms, then stops threads | Sentinel (`None`) flows through the queues, so all queued packets are processed |
| FP selection | Same hash used for LB and FP, so some FPs get no work | FP chosen with `hash // num_lbs`, so work spreads across all FPs |
| `--block-app` | Case-sensitive | Case-insensitive |
| Output headers | Rebuilt | Original packet headers copied through |
| Speed | True parallelism | Python's GIL limits CPU parallelism; use `multiprocessing` for real speed-ups |

---

## Known limitations

- **IPv4 only**: IPv6, ICMP and other protocols are skipped
- **No TCP reassembly**: a TLS Client Hello split across several segments is not detected
- **No QUIC / HTTP3 classification** in the default classifier
- **TLS 1.3 with Encrypted Client Hello** hides the SNI, so those flows stay `HTTPS`
- **Substring domain matching** (inherited from the original): for example `netflix.com` contains `x.com` and is labelled Twitter/X. Matching on the domain suffix would fix this
- Offline analysis of capture files only, not live capture

---

## Ideas for extension

- Domain-suffix matching instead of substrings
- Bandwidth throttling instead of dropping
- Live statistics dashboard thread
- Rules loaded from and saved to a file
- `multiprocessing` for large captures

---

## Credits

- Original C++ project and architecture: [perryvegehan/Packet_analyzer](https://github.com/perryvegehan/Packet_analyzer)
- Python port: [AliAamir-13](https://github.com/AliAamir-13)