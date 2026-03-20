# TFTP Requirements

**Protocol:** Trivial File Transfer Protocol  
**Primary RFC:** RFC 1350 — The TFTP Protocol (Revision 2)  
**Supporting:** RFC 2348 — TFTP Blocksize Option, RFC 2349 — TFTP Timeout Interval and Transfer Size Options, RFC 7440 — TFTP Windowsize Option  
**Scope:** V1 (IPv4), V2 (IPv6)  
**Last updated:** 2026-03-19

## Overview

TFTP is a simple file transfer protocol over UDP. It uses a lock-step (stop-and-wait) acknowledgment model, making it ideal for small devices. The primary use case is bootloader firmware downloads. This stack implements a TFTP client (not server).

## Packet Types

| Opcode | Name | Direction |
|---|---|---|
| 1 | RRQ (Read Request) | Client → Server |
| 2 | WRQ (Write Request) | Client → Server |
| 3 | DATA | Server → Client (for RRQ) |
| 4 | ACK | Client → Server (for RRQ) |
| 5 | ERROR | Either direction |
| 6 | OACK (Option Acknowledgment) | Server → Client |

## Packet Formats

```
RRQ/WRQ:
  2 bytes: Opcode (1 or 2)
  string:  Filename (null-terminated)
  string:  Mode ("octet", null-terminated)
  [option negotiations...]

DATA:
  2 bytes: Opcode (3)
  2 bytes: Block Number (1-65535)
  0-512:   Data (0-blksize bytes)

ACK:
  2 bytes: Opcode (4)
  2 bytes: Block Number

ERROR:
  2 bytes: Opcode (5)
  2 bytes: Error Code
  string:  Error Message (null-terminated)

OACK:
  2 bytes: Opcode (6)
  [option pairs: name\0value\0...]
```

## Requirements

### Read Request (RRQ) — File Download

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-001 | MUST | Send RRQ (opcode 1) with filename and mode "octet" | RFC 1350 §2 | TEST-TFTP-001 |
| REQ-TFTP-002 | MUST | RRQ sent to server IP:port 69 | RFC 1350 §2 | TEST-TFTP-002 |
| REQ-TFTP-003 | MUST | Use "octet" (binary) transfer mode | RFC 1350 §2 | TEST-TFTP-003 |
| REQ-TFTP-004 | MAY | Support "netascii" transfer mode | RFC 1350 §2 | TEST-TFTP-004 |
| REQ-TFTP-005 | MUST | After RRQ, expect DATA or OACK from server on a new TID (ephemeral port) | RFC 1350 §2 | TEST-TFTP-005 |
| REQ-TFTP-006 | MUST | Record server's TID (source port of first response) and use it for all subsequent packets | RFC 1350 §2 | TEST-TFTP-006 |

### DATA Reception

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-007 | MUST | Verify opcode = 3 (DATA) | RFC 1350 §2 | TEST-TFTP-007 |
| REQ-TFTP-008 | MUST | Verify block number = expected next block | RFC 1350 §2 | TEST-TFTP-008 |
| REQ-TFTP-009 | MUST | If block number matches, send ACK with that block number | RFC 1350 §2 | TEST-TFTP-009 |
| REQ-TFTP-010 | MUST | If DATA block is less than blksize bytes, transfer is complete (last block) | RFC 1350 §2 | TEST-TFTP-010 |
| REQ-TFTP-011 | MUST | Default block size = 512 bytes (without option negotiation) | RFC 1350 §2 | TEST-TFTP-011 |
| REQ-TFTP-012 | MUST | Deliver received data to application callback | Architecture | TEST-TFTP-012 |
| REQ-TFTP-013 | SHOULD | If duplicate block received (retransmit from server), re-send ACK but don't deliver data again | RFC 1350 §2 | TEST-TFTP-013 |

### ACK Transmission

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-014 | MUST | ACK contains opcode 4 + block number being acknowledged | RFC 1350 §2 | TEST-TFTP-014 |
| REQ-TFTP-015 | MUST | Send ACK to server's TID (not port 69) | RFC 1350 §2 | TEST-TFTP-015 |

### Error Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-016 | MUST | Process ERROR packets (opcode 5) and abort transfer | RFC 1350 §2 | TEST-TFTP-016 |
| REQ-TFTP-017 | MUST | Report error code and message to application | RFC 1350 §2 | TEST-TFTP-017 |
| REQ-TFTP-018 | MUST | Send ERROR if packet received from wrong TID | RFC 1350 §2 | TEST-TFTP-018 |
| REQ-TFTP-019 | MUST | Support error codes: 0 (not defined), 1 (file not found), 2 (access violation), 3 (disk full), 4 (illegal op), 5 (unknown TID), 6 (file exists), 7 (no such user) | RFC 1350 §5 | TEST-TFTP-019 |

### Timeout and Retransmission

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-020 | MUST | Retransmit last ACK if no DATA received within timeout | RFC 1350 §2 | TEST-TFTP-020 |
| REQ-TFTP-021 | MUST | Retransmit RRQ if no response within timeout | RFC 1350 §2 | TEST-TFTP-021 |
| REQ-TFTP-022 | SHOULD | Default timeout = 1-5 seconds | RFC 2349 §2 | TEST-TFTP-022 |
| REQ-TFTP-023 | MUST | Limit retransmissions; abort after maximum retries (typically 5) | Architecture | TEST-TFTP-023 |
| REQ-TFTP-024 | MUST | Report timeout failure to application | Architecture | TEST-TFTP-024 |

### Option Negotiation (RFC 2348, RFC 2349)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-025 | MAY | Include "blksize" option in RRQ to negotiate block size | RFC 2348 §2 | TEST-TFTP-025 |
| REQ-TFTP-026 | MUST | Requested blksize MUST fit in application buffer: blksize ≤ buffer - ETH - IP - UDP - TFTP header | Architecture, RFC 2348 | TEST-TFTP-026 |
| REQ-TFTP-027 | MUST | If server responds with OACK, acknowledge with ACK block 0 | RFC 2347 §4 | TEST-TFTP-027 |
| REQ-TFTP-028 | MUST | Parse OACK to extract negotiated blksize (server may reduce it) | RFC 2348 §2 | TEST-TFTP-028 |
| REQ-TFTP-029 | MAY | Include "tsize" option in RRQ to request transfer size | RFC 2349 §3 | TEST-TFTP-029 |
| REQ-TFTP-030 | MAY | Include "timeout" option in RRQ to negotiate timeout interval | RFC 2349 §2 | TEST-TFTP-030 |
| REQ-TFTP-031 | MUST | If server does not understand options (sends DATA block 1 instead of OACK), fall back to defaults | RFC 2347 §4 | TEST-TFTP-031 |
| REQ-TFTP-032 | MAY | Include "windowsize" option in RRQ for multi-block windows (RFC 7440) | RFC 7440 | TEST-TFTP-032 |

### Write Request (WRQ) — File Upload (Optional)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-033 | MAY | Support WRQ (opcode 2) for file upload | RFC 1350 §2 | TEST-TFTP-033 |
| REQ-TFTP-034 | MAY | If WRQ supported: send DATA blocks after receiving ACK 0 from server | RFC 1350 §2 | TEST-TFTP-034 |

### Address Resolution

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-035 | MUST | Resolve TFTP server MAC before sending RRQ | Architecture | TEST-TFTP-035 |
| REQ-TFTP-036 | MUST | Server TID (ephemeral port) response comes from server's IP — reuse resolved MAC | Architecture | TEST-TFTP-036 |

### Buffer Adaptation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-037 | MUST | Adapt block size to buffer capacity (negotiate smaller blksize if buffer is small) | Architecture | TEST-TFTP-037 |
| REQ-TFTP-038 | MUST | Minimum useful blksize: 8 bytes (RFC 2348 allows 8-65464) | RFC 2348 §2 | TEST-TFTP-038 |

## Notes

- **TFTP is UDP-based:** No TCP connection required. This makes TFTP ideal for bootloaders.
- **Lock-step protocol:** One DATA block outstanding at a time (default). RFC 7440 windowsize option allows multiple blocks in flight.
- **Block number wraps at 65535:** For large files (> 32 MB at 512-byte blocks), block numbers wrap to 0. Both sides must handle this correctly.
- **Bootloader use case:** TFTP client downloads firmware. The application callback writes data to flash. Block size adapts to available RAM.
- **Port 69 is initial only:** The server picks an ephemeral TID for the data transfer. The client must track this and send ACKs to it.
