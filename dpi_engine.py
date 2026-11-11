#!/usr/bin/env python3
"""
DPI Engine - Deep Packet Inspection (Python port of perryvegehan/Packet_analyzer)

Pipeline (same as dpi_mt.cpp):
    Reader -> Load Balancer threads -> Fast Path threads -> Output writer

Usage:
    python dpi_engine.py input.pcap output.pcap [options]

Options:
    --block-ip <ip>        Block source IP              (repeatable)
    --block-app <app>      Block application           (repeatable, e.g. YouTube)
    --block-domain <dom>   Block domain (substring)     (repeatable)
    --lbs <n>              Number of load balancer threads (default 2)
    --fps <n>              Fast-path threads per LB        (default 2)
    --simple               Single-threaded mode (like main_working.cpp)

Only the Python standard library is used.
"""

import argparse
import queue
import struct
import sys
import threading
import time
from collections import Counter
from enum import Enum

QUEUE_SIZE = 10000
MASK64 = (1 << 64) - 1


# =============================================================================
# types.h / types.cpp
# =============================================================================
class AppType(Enum):
    UNKNOWN = "Unknown"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"
    QUIC = "QUIC"
    GOOGLE = "Google"
    FACEBOOK = "Facebook"
    YOUTUBE = "YouTube"
    TWITTER = "Twitter/X"
    INSTAGRAM = "Instagram"
    NETFLIX = "Netflix"
    AMAZON = "Amazon"
    MICROSOFT = "Microsoft"
    APPLE = "Apple"
    WHATSAPP = "WhatsApp"
    TELEGRAM = "Telegram"
    TIKTOK = "TikTok"
    SPOTIFY = "Spotify"
    ZOOM = "Zoom"
    DISCORD = "Discord"
    GITHUB = "GitHub"
    CLOUDFLARE = "Cloudflare"


# Order matters: first match wins (same order as sniToAppType in types.cpp)
SNI_PATTERNS = [
    (AppType.GOOGLE, ("google", "gstatic", "googleapis", "ggpht", "gvt1")),
    (AppType.YOUTUBE, ("youtube", "ytimg", "youtu.be", "yt3.ggpht")),
    (AppType.FACEBOOK, ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")),
    (AppType.INSTAGRAM, ("instagram", "cdninstagram")),
    (AppType.WHATSAPP, ("whatsapp", "wa.me")),
    (AppType.TWITTER, ("twitter", "twimg", "x.com", "t.co")),
    (AppType.NETFLIX, ("netflix", "nflxvideo", "nflximg")),
    (AppType.AMAZON, ("amazon", "amazonaws", "cloudfront", "aws")),
    (AppType.MICROSOFT, ("microsoft", "msn.com", "office", "azure",
                         "live.com", "outlook", "bing")),
    (AppType.APPLE, ("apple", "icloud", "mzstatic", "itunes")),
    (AppType.TELEGRAM, ("telegram", "t.me")),
    (AppType.TIKTOK, ("tiktok", "tiktokcdn", "musical.ly", "bytedance")),
    (AppType.SPOTIFY, ("spotify", "scdn.co")),
    (AppType.ZOOM, ("zoom",)),
    (AppType.DISCORD, ("discord", "discordapp")),
    (AppType.GITHUB, ("github", "githubusercontent")),
    (AppType.CLOUDFLARE, ("cloudflare", "cf-")),
]


def sni_to_app_type(sni):
    """Map an SNI / Host name to an application type."""
    if not sni:
        return AppType.UNKNOWN
    s = sni.lower()
    for app, patterns in SNI_PATTERNS:
        for p in patterns:
            if p in s:
                return app
    return AppType.HTTPS  # SNI present but not recognised


def ip_to_str(ip):
    return "%d.%d.%d.%d" % (ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255)


def parse_ip(text):
    """Dotted string -> int (same tolerant parsing as the C++ parseIP)."""
    result, octet, parts = 0, 0, []
    for c in text:
        if c == ".":
            parts.append(octet)
            octet = 0
        elif c.isdigit():
            octet = octet * 10 + int(c)
    parts.append(octet)
    for p in parts[:4]:
        result = (result << 8) | (p & 255)
    return result


def five_tuple_hash(t):
    """Boost-style hash combine over the 5-tuple (FiveTupleHash in types.h)."""
    h = 0
    for v in t:
        h ^= (v + 0x9E3779B9 + (h << 6) + (h >> 2)) & MASK64
    return h


# =============================================================================
# pcap_reader.h / pcap_reader.cpp
# =============================================================================
class PcapReader:
    def __init__(self):
        self.file = None
        self.endian = "<"
        self.snaplen = 0
        self.global_header = b""

    def open(self, filename):
        try:
            self.file = open(filename, "rb")
        except OSError:
            print("Error: Could not open file:", filename, file=sys.stderr)
            return False
        hdr = self.file.read(24)
        if len(hdr) < 24:
            print("Error: Could not read PCAP global header", file=sys.stderr)
            self.close()
            return False
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):      # native / little-endian file
            self.endian = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):    # swapped / big-endian file
            self.endian = ">"
        else:
            print("Error: Invalid PCAP magic number: 0x%x" % magic, file=sys.stderr)
            self.close()
            return False
        _, vmaj, vmin, _, _, self.snaplen, network = struct.unpack(
            self.endian + "IHHiIII", hdr)
        self.global_header = hdr
        print("Opened PCAP file:", filename)
        print("  Version: %d.%d" % (vmaj, vmin))
        print("  Snaplen: %d bytes" % self.snaplen)
        print("  Link type: %d%s" % (network, " (Ethernet)" if network == 1 else ""))
        return True

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

    def packets(self):
        """Generator yielding (raw_16_byte_header, data) for each packet."""
        while True:
            raw_hdr = self.file.read(16)
            if len(raw_hdr) < 16:
                return
            _, _, incl_len, _ = struct.unpack(self.endian + "IIII", raw_hdr)
            if incl_len > 65535 or (self.snaplen and incl_len > self.snaplen):
                print("Error: Invalid packet length:", incl_len, file=sys.stderr)
                return
            data = self.file.read(incl_len)
            if len(data) < incl_len:
                print("Error: Could not read packet data", file=sys.stderr)
                return
            yield raw_hdr, data


# =============================================================================
# packet_parser.h / packet_parser.cpp
# =============================================================================
class Packet:
    """Self-contained packet job passed between threads."""
    __slots__ = ("id", "raw_hdr", "data", "src_ip", "dst_ip", "src_port",
                 "dst_port", "protocol", "tcp_flags", "payload_offset",
                 "payload_length", "tuple", "hash")


def parse_packet(pkt_id, raw_hdr, data):
    """Ethernet -> IPv4 -> TCP/UDP. Returns Packet or None (not TCP/UDP over IPv4)."""
    n = len(data)
    if n < 14:
        return None
    if struct.unpack_from("!H", data, 12)[0] != 0x0800:   # IPv4 only
        return None
    off = 14
    if n < off + 20:
        return None
    version_ihl = data[off]
    if (version_ihl >> 4) != 4:
        return None
    ip_hlen = (version_ihl & 0x0F) * 4
    if ip_hlen < 20 or n < off + ip_hlen:
        return None
    protocol = data[off + 9]
    src_ip, dst_ip = struct.unpack_from("!II", data, off + 12)
    off += ip_hlen

    tcp_flags = 0
    if protocol == 6:                                       # TCP
        if n < off + 20:
            return None
        src_port, dst_port = struct.unpack_from("!HH", data, off)
        tcp_hlen = (data[off + 12] >> 4) * 4
        tcp_flags = data[off + 13]
        if tcp_hlen < 20 or n < off + tcp_hlen:
            return None
        off += tcp_hlen
    elif protocol == 17:                                    # UDP
        if n < off + 8:
            return None
        src_port, dst_port = struct.unpack_from("!HH", data, off)
        off += 8
    else:
        return None                                         # ICMP etc. skipped

    p = Packet()
    p.id = pkt_id
    p.raw_hdr = raw_hdr
    p.data = data
    p.src_ip, p.dst_ip = src_ip, dst_ip
    p.src_port, p.dst_port = src_port, dst_port
    p.protocol = protocol
    p.tcp_flags = tcp_flags
    p.payload_offset = off
    p.payload_length = n - off if off < n else 0
    p.tuple = (src_ip, dst_ip, src_port, dst_port, protocol)
    p.hash = five_tuple_hash(p.tuple)
    return p


# =============================================================================
# sni_extractor.h / sni_extractor.cpp
# =============================================================================
def _u16(b, i):
    return (b[i] << 8) | b[i + 1]


def is_tls_client_hello(p):
    if len(p) < 9 or p[0] != 0x16:                 # Handshake record
        return False
    if not (0x0300 <= _u16(p, 1) <= 0x0304):       # SSL3.0 .. TLS1.3
        return False
    if _u16(p, 3) > len(p) - 5:                    # record longer than payload
        return False
    return p[5] == 0x01                            # Client Hello


def extract_sni(p):
    """Return the SNI hostname from a TLS Client Hello, or None."""
    if not is_tls_client_hello(p):
        return None
    n = len(p)
    off = 5 + 4 + 2 + 32          # record hdr + handshake hdr + version + random
    if off >= n:
        return None
    off += 1 + p[off]             # session id
    if off + 2 > n:
        return None
    off += 2 + _u16(p, off)       # cipher suites
    if off >= n:
        return None
    off += 1 + p[off]             # compression methods
    if off + 2 > n:
        return None
    ext_len = _u16(p, off)
    off += 2
    ext_end = min(off + ext_len, n)
    while off + 4 <= ext_end:
        ext_type = _u16(p, off)
        ext_data_len = _u16(p, off + 2)
        off += 4
        if off + ext_data_len > ext_end:
            break
        if ext_type == 0x0000:                      # SNI extension
            if ext_data_len < 5:
                break
            if _u16(p, off) < 3:                    # SNI list length
                break
            if p[off + 2] != 0x00:                  # name type must be hostname
                break
            sni_len = _u16(p, off + 3)
            if sni_len > ext_data_len - 5:
                break
            return p[off + 5: off + 5 + sni_len].decode("latin-1")
        off += ext_data_len
    return None


HTTP_METHOD_PREFIXES = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")


def extract_http_host(p):
    """Return the Host header of an HTTP request (port stripped), or None."""
    if len(p) < 4 or not p.startswith(HTTP_METHOD_PREFIXES):
        return None
    lower = p.lower()
    pos = 0
    while True:
        i = lower.find(b"host:", pos)
        if i == -1:
            return None
        start = i + 5
        while start < len(p) and p[start] in (0x20, 0x09):
            start += 1
        end = start
        while end < len(p) and p[end] not in (0x0D, 0x0A):
            end += 1
        if end > start:
            return p[start:end].decode("latin-1").split(":")[0]
        pos = i + 1


def extract_dns_query(p):
    """Return the queried domain from a DNS query, or None (helper, as in C++)."""
    if len(p) < 12 or (p[2] & 0x80) or _u16(p, 4) == 0:
        return None
    off, labels = 12, []
    while off < len(p):
        ln = p[off]
        if ln == 0 or ln > 63:
            break
        off += 1
        if off + ln > len(p):
            break
        labels.append(p[off:off + ln].decode("latin-1"))
        off += ln
    return ".".join(labels) or None


def extract_quic_sni(p):
    """Simplified QUIC Initial SNI search (helper, as in C++)."""
    if len(p) < 5 or (p[0] & 0x80) == 0:
        return None
    for i in range(5, len(p) - 50):
        if p[i] == 0x01:
            sni = extract_sni(p[i - 5:])
            if sni:
                return sni
    return None


# =============================================================================
# Rules (RuleManager)
# =============================================================================
class Rules:
    def __init__(self):
        self._lock = threading.Lock()
        self.blocked_ips = set()
        self.blocked_apps = set()
        self.blocked_domains = []

    def block_ip(self, ip):
        with self._lock:
            self.blocked_ips.add(parse_ip(ip))
        print("[Rules] Blocked IP:", ip)

    def block_app(self, name):
        with self._lock:
            for app in AppType:
                if app.value.lower() == name.lower() or app.name.lower() == name.lower():
                    self.blocked_apps.add(app)
                    print("[Rules] Blocked app:", app.value)
                    return
        print("[Rules] Unknown app:", name, file=sys.stderr)

    def block_domain(self, domain):
        with self._lock:
            self.blocked_domains.append(domain)
        print("[Rules] Blocked domain:", domain)

    def is_blocked(self, src_ip, app, sni):
        with self._lock:
            if src_ip in self.blocked_ips:
                return True
            if app in self.blocked_apps:
                return True
            for dom in self.blocked_domains:
                if dom in sni:
                    return True
        return False


# =============================================================================
# Flow tracking + classification
# =============================================================================
class Flow:
    __slots__ = ("app", "sni", "packets", "bytes", "blocked", "classified")

    def __init__(self):
        self.app = AppType.UNKNOWN
        self.sni = ""
        self.packets = 0
        self.bytes = 0
        self.blocked = False
        self.classified = False


def classify_flow(pkt, flow):
    # 1) HTTPS: SNI from the TLS Client Hello
    if pkt.dst_port == 443 and pkt.payload_length > 5:
        sni = extract_sni(pkt.data[pkt.payload_offset:])
        if sni:
            flow.sni = sni
            flow.app = sni_to_app_type(sni)
            flow.classified = True
            return
    # 2) HTTP: Host header
    if pkt.dst_port == 80 and pkt.payload_length > 10:
        host = extract_http_host(pkt.data[pkt.payload_offset:])
        if host:
            flow.sni = host
            flow.app = sni_to_app_type(host)
            flow.classified = True
            return
    # 3) DNS
    if pkt.dst_port == 53 or pkt.src_port == 53:
        flow.app = AppType.DNS
        flow.classified = True
        return
    # 4) Port fallback (not final - a later packet may carry the SNI)
    if pkt.dst_port == 443:
        flow.app = AppType.HTTPS
    elif pkt.dst_port == 80:
        flow.app = AppType.HTTP


class PacketProcessor:
    """Per-thread flow table + stats. Used by every FastPath (and --simple mode)."""

    def __init__(self, rules):
        self.rules = rules
        self.flows = {}
        self.forwarded = 0
        self.dropped = 0
        self.app_counts = Counter()
        self.detected_snis = {}

    def handle(self, pkt):
        """Returns True if the packet should be forwarded."""
        flow = self.flows.get(pkt.tuple)
        if flow is None:
            flow = self.flows[pkt.tuple] = Flow()
        flow.packets += 1
        flow.bytes += len(pkt.data)

        if not flow.classified:
            classify_flow(pkt, flow)
        if not flow.blocked:
            flow.blocked = self.rules.is_blocked(pkt.src_ip, flow.app, flow.sni)

        self.app_counts[flow.app] += 1
        if flow.sni:
            self.detected_snis[flow.sni] = flow.app

        if flow.blocked:
            self.dropped += 1
            return False
        self.forwarded += 1
        return True


# =============================================================================
# Threads: FastPath, LoadBalancer, OutputWriter
# (queue.Queue is the thread-safe queue; None is the shutdown sentinel)
# =============================================================================
class FastPath(threading.Thread):
    def __init__(self, fp_id, rules, output_queue):
        super().__init__(name="FP%d" % fp_id, daemon=True)
        self.queue = queue.Queue(QUEUE_SIZE)
        self.output_queue = output_queue
        self.proc = PacketProcessor(rules)
        self.processed = 0

    def run(self):
        while True:
            pkt = self.queue.get()
            if pkt is None:
                self.output_queue.put(None)          # tell the writer this FP is done
                return
            self.processed += 1
            if self.proc.handle(pkt):
                self.output_queue.put(pkt)


class LoadBalancer(threading.Thread):
    def __init__(self, lb_id, fps, num_lbs):
        super().__init__(name="LB%d" % lb_id, daemon=True)
        self.queue = queue.Queue(QUEUE_SIZE)
        self.fps = fps
        self.num_lbs = num_lbs
        self.dispatched = 0

    def run(self):
        n = len(self.fps)
        while True:
            pkt = self.queue.get()
            if pkt is None:
                for fp in self.fps:
                    fp.queue.put(None)
                return
            # Same 5-tuple -> same FP. Using hash // num_lbs (not hash % n) keeps
            # the FP choice independent from the LB choice (which already used
            # hash % num_lbs), so all FPs get work.
            self.fps[(pkt.hash // self.num_lbs) % n].queue.put(pkt)
            self.dispatched += 1


class OutputWriter(threading.Thread):
    def __init__(self, q, out_file, producers):
        super().__init__(name="Writer", daemon=True)
        self.queue = q
        self.out_file = out_file
        self.producers = producers

    def run(self):
        finished = 0
        while finished < self.producers:
            pkt = self.queue.get()
            if pkt is None:
                finished += 1
                continue
            self.out_file.write(pkt.raw_hdr)
            self.out_file.write(pkt.data)


# =============================================================================
# DPI Engine
# =============================================================================
def box_line(text=""):
    return "║" + text.ljust(62) + "║"


class DPIEngine:
    def __init__(self, num_lbs=2, fps_per_lb=2, simple=False):
        self.num_lbs = num_lbs
        self.fps_per_lb = fps_per_lb
        self.simple = simple
        self.rules = Rules()
        self.total_packets = 0
        self.total_bytes = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.fps = []
        self.lbs = []
        self.procs = []
        self._print_banner()

    def _print_banner(self):
        print()
        print("╔" + "═" * 62 + "╗")
        if self.simple:
            print(box_line("              DPI ENGINE v2.0 (Single-threaded)"))
        else:
            total = self.num_lbs * self.fps_per_lb
            print(box_line("              DPI ENGINE v2.0 (Multi-threaded)"))
            print("╠" + "═" * 62 + "╣")
            print(box_line(" Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d"
                           % (self.num_lbs, self.fps_per_lb, total)))
        print("╚" + "═" * 62 + "╝")
        print()

    # ---- public API ---------------------------------------------------------
    def block_ip(self, ip):
        self.rules.block_ip(ip)

    def block_app(self, app):
        self.rules.block_app(app)

    def block_domain(self, dom):
        self.rules.block_domain(dom)

    def process(self, input_file, output_file):
        reader = PcapReader()
        if not reader.open(input_file):
            return False
        try:
            out = open(output_file, "wb")
        except OSError:
            print("Cannot open output file", file=sys.stderr)
            reader.close()
            return False

        start = time.time()
        with out:
            out.write(reader.global_header)
            if self.simple:
                self._run_simple(reader, out)
            else:
                self._run_multi(reader, out)
        reader.close()
        self.elapsed = time.time() - start
        self._print_report()
        return True

    # ---- reader side (shared) -----------------------------------------------
    def _read_packets(self, reader):
        print("[Reader] Processing packets...")
        pkt_id = 0
        for raw_hdr, data in reader.packets():
            pkt = parse_packet(pkt_id, raw_hdr, data)
            if pkt is None:
                continue
            pkt_id += 1
            self.total_packets += 1
            self.total_bytes += len(data)
            if pkt.protocol == 6:
                self.tcp_packets += 1
            else:
                self.udp_packets += 1
            yield pkt
        print("[Reader] Done reading %d packets" % pkt_id)

    # ---- single-threaded ----------------------------------------------------
    def _run_simple(self, reader, out):
        proc = PacketProcessor(self.rules)
        self.procs = [proc]
        for pkt in self._read_packets(reader):
            if proc.handle(pkt):
                out.write(pkt.raw_hdr)
                out.write(pkt.data)

    # ---- multi-threaded -----------------------------------------------------
    def _run_multi(self, reader, out):
        out_q = queue.Queue(QUEUE_SIZE)
        total_fps = self.num_lbs * self.fps_per_lb
        self.fps = [FastPath(i, self.rules, out_q) for i in range(total_fps)]
        self.lbs = [
            LoadBalancer(i, self.fps[i * self.fps_per_lb:(i + 1) * self.fps_per_lb],
                         self.num_lbs)
            for i in range(self.num_lbs)
        ]
        writer = OutputWriter(out_q, out, total_fps)

        writer.start()
        for fp in self.fps:
            fp.start()
        for lb in self.lbs:
            lb.start()

        for pkt in self._read_packets(reader):
            self.lbs[pkt.hash % self.num_lbs].queue.put(pkt)

        # Graceful shutdown: sentinel flows Reader -> LB -> FP -> Writer
        for lb in self.lbs:
            lb.queue.put(None)
        for lb in self.lbs:
            lb.join()
        for fp in self.fps:
            fp.join()
        writer.join()
        self.procs = [fp.proc for fp in self.fps]

    # ---- report -------------------------------------------------------------
    def _print_report(self):
        forwarded = sum(p.forwarded for p in self.procs)
        dropped = sum(p.dropped for p in self.procs)
        app_counts = Counter()
        snis = {}
        for p in self.procs:
            app_counts.update(p.app_counts)
            snis.update(p.detected_snis)

        print()
        print("╔" + "═" * 62 + "╗")
        print(box_line("                      PROCESSING REPORT"))
        print("╠" + "═" * 62 + "╣")
        print(box_line(" Total Packets:      %12d" % self.total_packets))
        print(box_line(" Total Bytes:        %12d" % self.total_bytes))
        print(box_line(" TCP Packets:        %12d" % self.tcp_packets))
        print(box_line(" UDP Packets:        %12d" % self.udp_packets))
        print("╠" + "═" * 62 + "╣")
        print(box_line(" Forwarded:          %12d" % forwarded))
        print(box_line(" Dropped:            %12d" % dropped))

        if not self.simple:
            print("╠" + "═" * 62 + "╣")
            print(box_line(" THREAD STATISTICS"))
            for i, lb in enumerate(self.lbs):
                print(box_line("   LB%d dispatched:   %12d" % (i, lb.dispatched)))
            for i, fp in enumerate(self.fps):
                print(box_line("   FP%d processed:    %12d" % (i, fp.processed)))

        print("╠" + "═" * 62 + "╣")
        print(box_line("                   APPLICATION BREAKDOWN"))
        print("╠" + "═" * 62 + "╣")
        total = self.total_packets
        for app, count in sorted(app_counts.items(), key=lambda kv: -kv[1]):
            pct = 100.0 * count / total if total else 0.0
            bar = "#" * int(pct / 5)
            tag = " (BLOCKED)" if app in self.rules.blocked_apps else ""
            print(box_line(" %-15s%8d %5.1f%% %-20s" % (app.value, count, pct, bar + tag)))
        print("╚" + "═" * 62 + "╝")

        if snis:
            print("\n[Detected Domains/SNIs]")
            for sni, app in snis.items():
                print("  - %s -> %s" % (sni, app.value))
        print("\nProcessed in %.3f s" % self.elapsed)


# =============================================================================
# CLI
# =============================================================================
def main():
    ap = argparse.ArgumentParser(
        description="DPI Engine - Deep Packet Inspection (Python)")
    ap.add_argument("input", help="input .pcap")
    ap.add_argument("output", help="filtered output .pcap")
    ap.add_argument("--block-ip", action="append", default=[], metavar="IP")
    ap.add_argument("--block-app", action="append", default=[], metavar="APP")
    ap.add_argument("--block-domain", action="append", default=[], metavar="DOM")
    ap.add_argument("--lbs", type=int, default=2, help="load balancer threads")
    ap.add_argument("--fps", type=int, default=2, help="fast-path threads per LB")
    ap.add_argument("--simple", action="store_true", help="single-threaded mode")
    args = ap.parse_args()

    if args.lbs < 1 or args.fps < 1:
        ap.error("--lbs and --fps must be >= 1")

    engine = DPIEngine(args.lbs, args.fps, args.simple)
    for ip in args.block_ip:
        engine.block_ip(ip)
    for app in args.block_app:
        engine.block_app(app)
    for dom in args.block_domain:
        engine.block_domain(dom)

    if not engine.process(args.input, args.output):
        return 1
    print("\nOutput written to:", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
