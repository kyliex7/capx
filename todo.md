## 🏗️ Layer 1 — Raw Capture (Week 1)

- [x] Open a network device with `pcap_open_live()`
- [x] List all available interfaces with `pcap_findalldevs()`
- [x] Set up a packet capture loop with `pcap_loop()` or `pcap_next()`
- [x] Write a callback function that prints: timestamp, packet length


## 🔍 Layer 2 — Protocol Parsing (Week 1-2)

- [x] Parse **TCP header** — get source port, dest port, flags (SYN, ACK, FIN)
- [x] Parse **UDP header** — get source port, dest port, length
- [x] Parse **ICMP** — get type and code
- [x] Print a clean one-liner per packet: `[TCP] 192.168.1.1:443 → 192.168.1.5:54321 [SYN]`

## 🌐 Layer 3 — HTTP Extraction (Week 2-3)

- [x] Filter for TCP packets on port 80 (HTTP) (BPF Filter)
- [ ] Extract the TCP payload (data after the TCP header)
- [ ] Check if payload starts with HTTP method: `GET`, `POST`, `HTTP/1.1`, etc.
- [ ] Print the full HTTP request line and headers
- [ ] Try to extract: `Host`, `Cookie`, `Authorization` headers
- [ ] Test on HTTP traffic (use a local server or `http://` site with a VPN off)

## 🛠️ Layer 4 — Make It Useful (Week 3-4)

> **Why?** A tool nobody can use is a toy. Real tools have filters, output options, and a clean interface.

- [ ] Add CLI arguments with `getopt()`:
  - `-i <interface>` — specify network interface
  - `-p <port>` — filter by port
  - `-n <count>` — capture N packets then stop
  - `-v` — verbose mode
- [ ] Add BPF filter support via `pcap_compile()` + `pcap_setfilter()` — e.g. `"tcp port 80"`
- [ ] Save captured packets to a `.pcap` file with `pcap_dump_open()` / `pcap_dump()`
- [ ] Open your `.pcap` in Wireshark — if it works, you're building compatible tooling 🔥
- [ ] Add signal handling (`SIGINT`) to gracefully stop capture on Ctrl+C

---

## 🎯 Stretch Goals (optional but impressive)

- [ ] Detect and reconstruct TCP streams (reassemble fragmented HTTP requests)
- [ ] Add ARP poisoning detection (compare ARP replies for same IP with different MACs)
- [ ] Add a simple stats summary on exit: total packets, protocol breakdown, top IPs
- [ ] Port it to work on a raw socket instead of libpcap (no external dependency)

---

## 📚 Resources

| Resource | What it's for |
|---|---|
| `man pcap` | Primary reference, read it |
| Beej's Guide to Network Programming | Sockets + network fundamentals in C |
| `man 7 ip` / `man 7 tcp` | Linux IP/TCP internals |
| Wireshark | Validate your `.pcap` output |
| RFC 791 (IP), RFC 793 (TCP) | The actual protocol specs if you go deep |

---

## 📁 Suggested File Structure

```
packet-sniffer/
├── main.c          # Entry point, CLI args
├── capture.c       # pcap setup and loop
├── capture.h
├── parsers.c       # Ethernet, IP, TCP, UDP, ICMP parsing
├── parsers.h
├── http.c          # HTTP payload extraction
├── http.h
├── utils.c         # Helper functions (print IP, MAC, etc.)
├── utils.h
└── Makefile
```

```makefile
CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lpcap

sniffer: main.c capture.c parsers.c http.c utils.c
	$(CC) $(CFLAGS) -o sniffer $^ $(LIBS)

clean:
	rm -f sniffer
```
