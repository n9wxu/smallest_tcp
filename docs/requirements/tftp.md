# TFTP Requirements

**Protocol:** Trivial File Transfer Protocol
**Primary RFC:** RFC 1350 — The TFTP Protocol (Revision 2)
**Supporting:** RFC 1123 §4.2 — Requirements for Internet Hosts (TFTP), RFC 2347 — TFTP Option Extension, RFC 2348 — TFTP Blocksize Option, RFC 2349 — TFTP Timeout Interval and Transfer Size Options, RFC 7440 — TFTP Windowsize Option
**Scope:** a client that reads files (RRQ), over IPv4

## Overview

TFTP is a simple file transfer protocol over UDP. It uses a lock-step (stop-and-wait) acknowledgment model, making it ideal for small devices. The primary use case is bootloader firmware downloads. This stack implements a TFTP client that reads files; it has no server and does not write files (WRQ).

RFC 1350 and the option RFCs do not use requirement keywords; the levels below are those of RFC 1123 §4.2 where it speaks, and otherwise say what the protocol needs to work (MUST) or recommends (SHOULD). RFC 2347, 2348 and 2349 have no section numbers and are cited by section title.

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
  string:  Mode ("octet" or "netascii", null-terminated)
  [option negotiations...]

DATA:
  2 bytes: Opcode (3)
  2 bytes: Block Number (1-65535)
  0-blksize bytes of data (blksize is 512 unless negotiated)

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
| REQ-TFTP-001 | MUST | Send RRQ (opcode 1) with the filename and the mode, each NUL-terminated; an RRQ that does not fit the TX frame buffer is not sent (`NET_ERR_BUF_TOO_SMALL`) | RFC 1350 §5 | itest_tftp_001_rrq, itest_tftp_001_one_transfer_at_a_time, itest_tftp_001_rrq_too_long_for_tx_buffer |
| REQ-TFTP-002 | MUST | RRQ sent to server IP:port 69 | RFC 1350 §4 | itest_tftp_001_rrq |
| REQ-TFTP-003 | MUST | Use "octet" (binary) transfer mode unless the application chooses another | RFC 1350 §1 | itest_tftp_001_rrq, itest_tftp_004_octet_untouched |
| REQ-TFTP-004 | MUST | Support "netascii" transfer mode (`tftp_client_set_mode()`): CR LF arrives as the local newline, CR NUL as CR | RFC 1350 §1, RFC 1123 §4.2.4 | itest_tftp_004_netascii, itest_tftp_004_netascii_bare_cr, itest_tftp_004_netascii_cr_across_blocks, itest_tftp_004_octet_untouched |
| REQ-TFTP-005 | MUST | After RRQ, expect DATA or OACK from server on a new TID (ephemeral port) | RFC 1350 §4 | itest_tftp_005_data_acked_to_the_servers_port, itest_tftp_018_stray_before_the_first_answer |
| REQ-TFTP-006 | MUST | Record server's TID (source port of first response) and use it for all subsequent packets; port 0 is no TID, and a datagram from it is dropped | RFC 1350 §4 | itest_tftp_005_data_acked_to_the_servers_port, itest_tftp_006_port_0_is_no_transfer_id |
| REQ-TFTP-042 | SHOULD | Choose the local TID (source port) at random for each transfer — **deviation:** the application gives one local port to `tftp_client_init()` and every transfer uses it, so the port's handler can be a constant table entry; a late datagram of an earlier transfer can be taken for the next one's first answer | RFC 1350 §4 | — |

### DATA Reception

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-007 | MUST | Verify opcode = 3 (DATA); a DATA packet of fewer than 4 bytes is dropped | RFC 1350 §5 | itest_tftp_005_data_acked_to_the_servers_port, itest_tftp_008_only_the_next_block_is_taken, itest_tftp_017_truncated_packets_dropped |
| REQ-TFTP-008 | MUST | Verify block number = expected next block (after 65535 the next is 0) | RFC 1350 §2 | itest_tftp_008_only_the_next_block_is_taken, itest_tftp_008_block_number_wraps |
| REQ-TFTP-009 | MUST | If block number matches, send ACK with that block number | RFC 1350 §2 | itest_tftp_005_data_acked_to_the_servers_port |
| REQ-TFTP-010 | MUST | If DATA block is less than blksize bytes, transfer is complete (last block) | RFC 1350 §6 | itest_tftp_010_short_block_ends_the_transfer, itest_tftp_010_empty_block_ends_the_transfer, itest_tftp_010_nothing_after_the_end |
| REQ-TFTP-011 | MUST | Default block size = 512 bytes (without option negotiation) | RFC 1350 §2 | itest_tftp_010_short_block_ends_the_transfer, itest_tftp_025_default_size_not_asked_for |
| REQ-TFTP-012 | MUST | Deliver received data to application callback | Architecture | itest_tftp_005_data_acked_to_the_servers_port |
| REQ-TFTP-013 | SHOULD | If duplicate block received (retransmit from server), re-send ACK but don't deliver data again | RFC 1350 §2 | itest_tftp_013_duplicate_block_acked_not_delivered |
| REQ-TFTP-041 | MUST | A DATA packet carrying more than the block size in force (512, or the OACK's) is dropped: not delivered, not acknowledged | RFC 1350 §5, RFC 2348 (Blocksize Option Specification) | itest_tftp_041_oversize_data_dropped, itest_tftp_041_data_above_the_negotiated_size_dropped |
| REQ-TFTP-043 | SHOULD | Dally after the final ACK: acknowledge the last DATA again if the server repeats it — **deviation:** the transfer ends with the final ACK and nothing after it is answered; the file is complete either way, and a server that missed the ACK repeats the block until it gives up | RFC 1350 §6 | — |

### ACK Transmission

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-014 | MUST | ACK contains opcode 4 + block number being acknowledged | RFC 1350 §5 | itest_tftp_005_data_acked_to_the_servers_port |
| REQ-TFTP-015 | MUST | Send ACK to server's TID (not port 69) | RFC 1350 §4 | itest_tftp_005_data_acked_to_the_servers_port |

### Error Handling

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-016 | MUST | Process ERROR packets (opcode 5) and abort transfer; an ERROR of fewer than 4 bytes is dropped | RFC 1350 §5, §7 | itest_tftp_016_error_ends_the_transfer, itest_tftp_016_error_while_receiving, itest_tftp_017_truncated_packets_dropped |
| REQ-TFTP-017 | MUST | Report error code and message to application; a message not NUL-terminated within the packet is reported as empty | RFC 1350 §5 | itest_tftp_016_error_ends_the_transfer, itest_tftp_017_unterminated_message_reported_empty, itest_tftp_017_truncated_packets_dropped |
| REQ-TFTP-018 | MUST | Answer a packet from a wrong TID (IP or port) with ERROR 5 to its source, and continue the transfer; an ERROR from a wrong TID is dropped unanswered | RFC 1350 §4 | itest_tftp_018_wrong_port_gets_error_5, itest_tftp_018_wrong_host_gets_error_5, itest_tftp_018_stray_before_the_first_answer, itest_tftp_018_stray_error_not_answered |
| REQ-TFTP-019 | MUST | Support error codes: 0 (not defined), 1 (file not found), 2 (access violation), 3 (disk full), 4 (illegal op), 5 (unknown TID), 6 (file exists), 7 (no such user) | RFC 1350 Appendix | itest_tftp_019_every_error_code_reported |

### Timeout and Retransmission

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-020 | MUST | Retransmit last ACK if no DATA received within timeout; only the block expected (or an OACK taken) restarts the timer | RFC 1350 §2 | itest_tftp_020_last_ack_retransmitted, itest_tftp_020_timer_restarted_only_by_progress, itest_tftp_039_timeout_shrinks_for_a_fast_server, itest_tftp_027_ack_0_retransmitted |
| REQ-TFTP-021 | MUST | Retransmit RRQ if no response within timeout | RFC 1350 §2 | itest_tftp_039_retransmission_backs_off, itest_tftp_023_gives_up_after_5_retransmissions |
| REQ-TFTP-022 | SHOULD | First timeout of 1-5 seconds: 3 s (`TFTP_TIMEOUT_MS`) | Architecture | itest_tftp_039_retransmission_backs_off |
| REQ-TFTP-023 | MUST | Limit retransmissions: give up after 5 (`TFTP_MAX_RETRIES`) without progress | Architecture | itest_tftp_023_gives_up_after_5_retransmissions, itest_tftp_023_gives_up_on_a_server_that_only_repeats |
| REQ-TFTP-024 | MUST | Report timeout failure to application | Architecture | itest_tftp_023_gives_up_after_5_retransmissions, itest_tftp_023_gives_up_on_a_server_that_only_repeats |
| REQ-TFTP-039 | MUST | Adaptive retransmission timeout: exponential backoff on each retransmission, and a timeout that follows the measured round-trip time | RFC 1123 §4.2.3.2 | itest_tftp_039_retransmission_backs_off, itest_tftp_039_timeout_shrinks_for_a_fast_server, itest_tftp_039_timeout_grows_for_a_slow_server, itest_tftp_039_backoff_stops_at_the_ceiling |

### Option Negotiation (RFC 2348, RFC 2349)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-025 | MAY | Include "blksize" option in RRQ to negotiate block size (only a size other than 512 is asked for) | RFC 2348 (Blocksize Option Specification) | itest_tftp_026_blksize_fits_the_rx_buffer, itest_tftp_025_default_size_not_asked_for |
| REQ-TFTP-026 | MUST | The blksize asked for fits the RX frame buffer: blksize ≤ its size − Ethernet, IPv4, UDP and TFTP DATA headers (46 bytes), and ≤ 1468, the largest DATA in one Ethernet frame | Architecture, RFC 2348 | itest_tftp_026_blksize_fits_the_rx_buffer |
| REQ-TFTP-027 | MUST | If server responds with OACK, acknowledge with ACK block 0; acknowledge a repeated OACK again until DATA block 1 arrives | RFC 2347 (Negotiation Protocol) | itest_tftp_027_oack_acked_with_block_0, itest_tftp_027_repeated_oack_acked_again, itest_tftp_027_ack_0_retransmitted |
| REQ-TFTP-028 | MUST | Parse OACK to extract negotiated blksize (server may reduce it; an OACK without it means 512; the name in any case); refuse a larger one, one below 8, one not all digits, one not requested, or any option not requested, with ERROR 8 and end the transfer; drop an OACK whose last name or value is not NUL-terminated | RFC 2348 (Blocksize Option Specification), RFC 2347 (Negotiation Protocol) | itest_tftp_027_oack_acked_with_block_0, itest_tftp_028_oack_name_in_any_case, itest_tftp_028_larger_blksize_refused, itest_tftp_028_blksize_not_a_number_refused, itest_tftp_028_unrequested_blksize_refused, itest_tftp_028_unrequested_option_refused, itest_tftp_028_oack_without_blksize_means_512, itest_tftp_028_malformed_oack_dropped |
| REQ-TFTP-029 | MAY | Include "tsize" option in RRQ to request transfer size | RFC 2349 (Transfer Size Option Specification) | — (not implemented) |
| REQ-TFTP-030 | MAY | Include "timeout" option in RRQ to negotiate timeout interval | RFC 2349 (Timeout Interval Option Specification) | — (not implemented) |
| REQ-TFTP-031 | MUST | If server does not understand options (sends DATA block 1 instead of OACK), fall back to defaults | RFC 2347 (Negotiation Protocol) | itest_tftp_031_data_instead_of_oack_means_512 |
| REQ-TFTP-032 | MAY | Include "windowsize" option in RRQ for multi-block windows (RFC 7440) | RFC 7440 | — (not implemented) |

### Write Request (WRQ) — File Upload (Optional)

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-033 | MAY | Support WRQ (opcode 2) for file upload | RFC 1350 §5 | — (not implemented) |
| REQ-TFTP-034 | MAY | If WRQ supported: send DATA blocks after receiving ACK 0 from server | RFC 1350 §4 | — (not implemented) |
| REQ-TFTP-040 | MUST | The side sending DATA never resends the current DATA on a duplicate ACK (the Sorcerer's Apprentice fix); the client only reads, sends no DATA, and answers an ACK with nothing | RFC 1123 §4.2.3.1 | itest_tftp_040_duplicate_ack_draws_no_data |

### Address Resolution

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-035 | MUST | The server's MAC is resolved before the RRQ is sent: the application passes it to `tftp_client_get()`, and the RRQ goes to it | Architecture | itest_tftp_001_rrq |
| REQ-TFTP-036 | MUST | Server TID (ephemeral port) response comes from server's IP — reuse resolved MAC | Architecture | itest_tftp_005_data_acked_to_the_servers_port |

### Buffer Adaptation

| ID | Level | Requirement | RFC | Test ID |
|---|---|---|---|---|
| REQ-TFTP-037 | MUST | Adapt block size to buffer capacity (ask for a smaller blksize if the RX frame buffer is small) | Architecture | itest_tftp_026_blksize_fits_the_rx_buffer |
| REQ-TFTP-038 | MUST | Minimum blksize: 8 bytes (RFC 2348 allows 8-65464); a smaller one in an OACK is refused | RFC 2348 (Blocksize Option Specification) | itest_tftp_038_blksize_below_8_refused |

## Notes

- **TFTP is UDP-based:** No TCP connection required. This makes TFTP ideal for bootloaders.
- **Lock-step protocol:** One DATA block outstanding at a time (default). RFC 7440 windowsize option allows multiple blocks in flight.
- **Block number wraps at 65535:** For large files (> 32 MB at 512-byte blocks), block numbers wrap to 0 (REQ-TFTP-008). RFC 1350 does not define the wrap; a server that wraps to 1 stalls such a transfer.
- **Bootloader use case:** TFTP client downloads firmware. The application callback writes data to flash. Block size adapts to available RAM.
- **Port 69 is initial only:** The server picks an ephemeral TID for the data transfer. The client must track this and send ACKs to it.
