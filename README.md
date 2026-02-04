# gpu-packet-project
# GPU-Based IPv4 Packet Authentication

This project implements IPv4 packet authentication using GPU acceleration (CUDA).
It expands IPv4 headers, computes SHA-256 hashes, recalculates checksums, and writes
authenticated packets back to a PCAP file.

## Project Contents
- `code/` – CUDA and Python source files
- `report/` – Full project report (PDF)

## Technologies
- CUDA
- C++
- Python
- libpcap
- SLURM

## Highlights
- Processes over 10 million packets
- Microsecond-level GPU kernel latency
- File I/O identified as the main bottleneck

