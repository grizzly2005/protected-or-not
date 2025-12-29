<p align="center">
  <img src="assets/image.png" alt="Blindspot C2 - WebSocket Server for Detection Research" width="100%">
</p>

<h1 align="center">Protected-or-not</h1>

**WebSocket C2 Server for Security Research & Windows Detection Studies**

Companion server for the *"Defender looks, but does it see?"* research series. This tool emulates a minimal command & control infrastructure to study payload delivery, network behavior, and endpoint detection mechanisms.

-------------------------------------------------------------------------------------------------------------------------------------

#  Overview

This is a **research-grade C2 server** designed to work with the Windows implant in the main repository. It demonstrates:

- **WebSocket-based implant communication** (RFC 6455)
- **Chunked payload delivery** with rotating XOR encryption
- **Multi-session management** for parallel implant instances
- **Payload type detection** (shellcode vs reflective DLL)
- **Trigger-based execution** with timing validation

**⚠️ This is NOT a weapon.** It's a learning tool to understand detection boundaries between consumer AV and enterprise EDR.

-------------------------------------------------------------------------------------------------------------------------------------


                 ┌────────────────────────┐
                 │        OPERATOR        │
                 │   Interactive CLI      │
                 └───────────┬────────────┘
                             │
                Commands (run / send / trigger)
                             │
                 ┌───────────▼────────────┐
                 │      C2 SERVER         │
                 │  WebSocket (RFC 6455)  │
                 │                        │
                 │  - Session Manager     │
                 │  - Payload Manager     │
                 │  - XOR Encoder         │
                 └───────────┬────────────┘
                             │
                  WebSocket Frames (Custom)
                             │
        ┌────────────────────▼────────────────────┐
        │                IMPLANT                  │
        │          Windows Userland               │
        │                                         │
        │  - Payload Receiver                     │
        │  - Integrity Check (SHA256)             │
        │  - Triggered Execution                  │
        └─────────────────────────────────────────┘



-------------------------------------------------------------------------------------------------------------------------------------

# 🚀Quick Start

# c2.py---------------------------------------------------------------

### Prerequisites

#### Python 3.7+
python3 --version

## Basic Usage

#### 1. Start the C2 server
python3 c2.py --listen IP:PORT


#### 2. Load a payload
C2> upload implant.exe          # From file
C2> upload --base64 <string>    # From base64
C2> upload --hex <string>       # From hex


#### 3. List connected implants
C2> sessions


#### 4. Send payload to implant
C2> run SESSION_NUMBER


#### 5. Send trigger signal (execute)
C2> trigger SESSION_NUMBER


## Command	Description

```
upload <file>	Load payload from file (supports .bin, .dll, shellcode)

upload --base64 <string>	Load base64-encoded payload

upload --hex <string>	Load hex-encoded payload (format: \x90\x90 or 9090)

type [shellcode	reflective

sessions	List all active implant sessions

run <session_id>	Send payload + trigger to session

send <session_id>	Send payload only (no trigger)

trigger <session_id>	Send execution trigger only

info	Display loaded payload details

clear	Unload current payload

generate [shellcode	reflective]`

help	Show this help

exit	Quit CLI and stop server
```

##  Troubleshooting

**Agent not connecting?**
```
- Check Windows Firewall on the port
- Make sure the XOR-encoded IP in `node.c` is correct
```
# node.c---------------------------------------------------------------

### Prerequisites
```
MinGW-w64 cross-compiler (or native Windows toolchain)
Windows SDK (10.0.22621+) for headers and libraries
Visual Studio Command Prompt or MSYS2 environment
```

### compile:

x86_64-w64-mingw32-gcc -O2 -o IMPLANT_NAME.exe node.c -lws2_32 -liphlpapi -lbcrypt -lntdll

### notes:
```
Use -mwindows flag to hide console window in GUI builds
Adjust IMPLANT_NAME.exe to your desired output filename
Recommended: add -D_WIN64 for x64 targets or -D_WIN32 for x86 targets
```
##  Troubleshooting

**Compilation failing?**
```
- Use MinGW-w64, not standard MinGW
- Add `-D_WIN64` if targeting x64
```

-------------------------------------------------------------------------------------------------------------------------------------


##  Protocol Details
```
WebSocket Opcodes (Custom)

Opcode	Name	Purpose
0x04	INIT	Send size + xor_key + type
0x03	DATA	Send encrypted chunk
0x05	FINAL	Send SHA256 hash for integrity check
0x02	TRIGGER	72-byte execution signal (magic + timestamp + HMAC)
```
```
Operator              C2 Server                    Implant
   │                      │                          │
   │   upload payload     │                          │
   │─────────────────────►│                          │
   │                      │                          │
   │   run <session>      │                          │
   │─────────────────────►│                          │
   │                      │ INIT (0x04)              │
   │                      ├─────────────────────────►│
   │                      │ DATA (0x03) [chunks]     │
   │                      ├─────────────────────────►│
   │                      │ FINAL (0x05)             │
   │                      ├─────────────────────────►│
   │                      │                          │
   │   trigger <session>  │                          │
   │─────────────────────►│ TRIGGER (0x02)           │
   │                      ├─────────────────────────►│
   │                      │                          │
```



Message Flow:
```
INIT (0x04)
    └─► magic: 0xCAFEBABE
    └─► size: payload length (uint64)
    └─► xor_key: 1-byte base key
    └─► type: 0x01 (shellcode) or 0x02 (reflective)

DATA (0x03) [repeated]
    └─► magic: 0xDEADC0DE
    └─► encrypted_data: XOR-rotated chunk

FINAL (0x05)
    └─► magic: 0xBAADF00D
    └─► hash: SHA256 of original payload

TRIGGER (0x02) [when ready]
    └─► magic: 32-byte constant
    └─► timestamp: uint64 (anti-replay)
    └─► HMAC: SHA256 of magic+timestamp
```




    
XOR Rotating Algorithm
```
Payload (raw bytes)
┌──────────────────────────────────────┐
│ 90 90 90 CC C3 ...                   │
└───────────────┬──────────────────────┘
                │  chunking (8192 bytes)
                ▼
        ┌─────────────────┐
        │   DATA CHUNK    │
        │ magic: DEADC0DE │
        │ xor(data, key)  │
        └────────┬────────┘
                 │ rotate_xor_key()
                 ▼
        key = (base * 7 + state) % 251
```
-------------------------------------------------------------------------------------------------------------------------------------



 Payload Detection
The server auto-detects payload type:
```
SHELLCODE: Pure code, no PE header
REFLECTIVE: Contains MZ + PE\0\0 signature (DLL)
Use type command to override detection if needed.
```



-------------------------------------------------------------------------------------------------------------------------------------


```
## ⚠️ Legal & Ethical Notice

This project is provided strictly for **educational and authorized security research purposes**.

- Use only on systems you own or have explicit written authorization to test
- Designed for studying detection mechanisms, not evasion in the wild
- No responsibility is assumed for misuse or illegal deployment
- The implementation is intentionally simplified for learning and analysis

By using this code, you agree to comply with all applicable laws and regulations.
```

-------------------------------------------------------------------------------------------------------------------------------------


## 📖 Article Series (LinkedIn)

This repository implements the research detailed in my 3-part LinkedIn series (currently French, English version coming soon):

1. Série Partie 1/3 :[Defender grand public vs EDR entreprise, où commence la vraie protection ?](https://www.linkedin.com/pulse/s%C3%A9rie-partie-13-youre-protected-defender-grand-public-massetti-io14e)
🇫🇷 French | 🌐 English translation in progress




2. Série Partie 2/3 : [L'architecture d’un implant en C](https://www.linkedin.com/pulse/s%C3%A9rie-partie-23-built-evade-larchitecture-dun-implant-massetti-yutwe)
🇫🇷 French | 🌐 English translation in progress




3. Série Partie 3/3 : [C2 Protocol & Detection Boundaries](https://www.linkedin.com/pulse/s%C3%A9rie-partie-33-built-evade-larchitecture-dun-implant-massetti-o79ge)
🇫🇷 French | 🌐 English translation in progress



Each article explains the **why** behind the code — perfect if you want to understand the research methodology rather than just the implementation.

🔗 [**Follow the series**](https://www.linkedin.com/in/massimo-massetti-462346326/)
