# Vortex: High-Performance Network Analyzer

Vortex is a hybrid C++ and Python network traffic analysis tool designed for real-time packet sniffing and data visualization. 

This project demonstrates low-level system interactions, memory management, and high-speed data handling by bridging a compiled C++ packet capture engine with a Python-based analytical frontend.

## Architecture

* **The Engine (Backend):** Written in C++ utilizing the `libpcap` (Npcap on Windows) library to interface directly with the network interface controller (NIC) and capture raw network packets with minimal latency.
* **The Visualizer (Frontend - Planned):** A Python GUI using `PyQt6` and `PyQtGraph` to process the byte stream and visualize network metrics, protocol distribution, and statistical anomalies in real-time.

## Tech Stack

* **Language:** C++17, Python 3
* **Libraries:** Npcap/libpcap (Packet Capture)
* **OS Compatibility:** Windows (Currently configured for MinGW/GCC)

## Current Status

* [x] Environment and Npcap SDK configuration.
* [x] Network interface enumeration and selection.
* [x] Raw packet capture loop initialization.
* [x] Packet header parsing (Extracting IPs, Ports, Protocols).
* [x] Inter-process communication (IPC) between C++ and Python.
* [ ] GUI implementation.

## Build and Run Instructions (Windows)

### Prerequisites
1. Install [Npcap](https://npcap.com/) (Check "Install in WinPcap API-compatible Mode" during installation).
2. Download the Npcap SDK and extract the `Include` and `Lib` folders into a `lib/` directory in the project root.
3. Install MinGW-w64 (for the `g++` compiler).

### Compilation
Run the following command in the terminal from the project root:

```powershell
g++ src/main.cpp -o vortex.exe -I"./lib/Include" -L"./lib/Lib/x64" -lwpcap -lPacket
