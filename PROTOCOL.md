# TrustTunnel Protocol Specification

**Version 1.0**

## Abstract

TrustTunnel is a VPN protocol designed to tunnel network traffic through
standard HTTP/2 and HTTP/3 (QUIC) connections. By leveraging widely-used web
protocols, TrustTunnel traffic closely resembles regular HTTPS traffic, making
it resistant to detection and blocking by network intermediaries.

This document provides a complete specification of the TrustTunnel protocol,
enabling independent implementations that are interoperable with existing
TrustTunnel clients and endpoints.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Protocol Overview](#2-protocol-overview)
3. [Transport Layer](#3-transport-layer)
4. [Session Establishment](#4-session-establishment)
5. [TCP Connection Tunneling](#5-tcp-connection-tunneling)
6. [UDP Multiplexing](#6-udp-multiplexing)
7. [ICMP Multiplexing](#7-icmp-multiplexing)
8. [Health Checks](#8-health-checks)
9. [Authentication](#9-authentication)
10. [Error Handling](#10-error-handling)
11. [Wire Formats](#11-wire-formats)
12. [Security Considerations](#12-security-considerations)
13. [Implementation Notes](#13-implementation-notes)
14. [Appendix A: Reserved Pseudo-Hosts](#appendix-a-reserved-pseudo-hosts)
15. [Appendix B: Example Message Flows](#appendix-b-example-message-flows)
16. [Appendix C: Version History](#appendix-c-version-history)
17. [References](#references)

---

## 1. Introduction

### 1.1 Purpose

TrustTunnel provides a mechanism for tunneling arbitrary network traffic (TCP,
UDP, and ICMP) through encrypted HTTP/2 or HTTP/3 connections. The protocol is
designed with the following goals:

- **Stealth**: Traffic appears as standard HTTPS, making it difficult to
distinguish from regular web browsing
- **Performance**: Efficient multiplexing of multiple connections over a single
transport session
- **Reliability**: Built-in session recovery and health checking mechanisms
- **Flexibility**: Support for both HTTP/2 (over TLS) and HTTP/3 (over QUIC) transports

### 1.2 Terminology

| Term           | Definition                                                           |
|----------------|----------------------------------------------------------------------|
| **Client**     | The TrustTunnel client application that initiates connections        |
| **Endpoint**   | The TrustTunnel server that terminates tunneled connections          |
| **Session**    | An HTTP/2 or HTTP/3 connection between client and endpoint           |
| **Stream**     | An individual HTTP stream within a session                           |
| **Connection** | A tunneled TCP, UDP, or ICMP flow                                    |

### 1.3 Conventions

- All multi-byte integers are transmitted in **network byte order** (big-endian)
- IP addresses are transmitted in their binary form (4 bytes for IPv4, 16 bytes for IPv6)
- IPv4 addresses are zero-padded to 16 bytes when transmitted in padded format

---

## 2. Protocol Overview

### 2.1 Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                        TrustTunnel Client                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────-┐  ┌─────────────────────────┐ │
│  │ TCP Streams │  │ UDP Stream   │  │ ICMP Stream             │ │
│  │ (per-conn)  │  │ (multiplexed)│  │ (multiplexed)           │ │
│  └──────┬──────┘  └──────┬──────-┘  └───────────┬─────────────┘ │
│         │                │                      │               │
│         └────────────────┼─────────────────────-┘               │
│                          │                                      │
│                ┌─────────▼─────────┐                            │
│                │  HTTP/2 or HTTP/3 │                            │
│                │     Session       │                            │
│                └─────────┬─────────┘                            │
│                          │                                      │
│                ┌─────────▼─────────┐                            │
│                │   TLS or QUIC     │                            │
│                └─────────┬─────────┘                            │
└──────────────────────────┼──────────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │   Internet  │
                    └──────┬──────┘
                           │
┌──────────────────────────┼──────────────────────────────────────┐
│                ┌─────────▼─────────┐                            │
│                │   TLS or QUIC     │                            │
│                └─────────┬─────────┘                            │
│                ┌─────────▼─────────┐                            │
│                │  HTTP/2 or HTTP/3 │                            │
│                │     Session       │                            │
│                └─────────┬─────────┘                            │
│         ┌────────────────┼─────────────────────┐                │
│         │                │                     │                │
│  ┌──────▼──────┐  ┌──────▼──────-┐  ┌───────────▼─────────────┐ │
│  │ TCP Streams │  │ UDP Stream   │  │ ICMP Stream             │ │
│  │ (per-conn)  │  │ (multiplexed)│  │ (multiplexed)           │ │
│  └─────────────┘  └─────────────-┘  └─────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                       TrustTunnel Endpoint                      │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Connection Model

TrustTunnel uses different strategies for different protocols:

- **TCP**: Each TCP connection uses a dedicated HTTP stream via the CONNECT
  method
- **UDP**: All UDP datagrams are multiplexed over a single HTTP stream
- **ICMP**: All ICMP echo requests/replies are multiplexed over a single HTTP
  stream

---

## 3. Transport Layer

### 3.1 HTTP/2 Transport

When using HTTP/2:

- The client establishes a TLS 1.2+ connection to the endpoint
- ALPN negotiation MUST select `h2`
- The initial stream window size is set to **131072 bytes** (Chrome's default)
- Standard HTTP/2 flow control applies

**TLS Requirements:**

- TLS 1.2 or higher
- Server certificate verification is REQUIRED
- SNI (Server Name Indication) MUST be sent

### 3.2 HTTP/3 Transport

When using HTTP/3:

- The client establishes a QUIC connection to the endpoint
- ALPN negotiation MUST select `h3`
- QUIC version negotiation follows standard QUIC procedures
- Default QUIC version: `0x00000001` (RFC 9000)

**QUIC Configuration:**

- Max idle timeout: `2 × (connection_timeout + health_check_timeout)`
- Standard QUIC flow control applies

### 3.3 Protocol Selection

Clients MAY support automatic protocol selection:

1. Attempt HTTP/3 connection
2. Fall back to HTTP/2 after a configurable delay (default: 1000ms)
3. Use whichever protocol establishes first

---

## 4. Session Establishment

### 4.1 Connection Flow

1. Client initiates TLS/QUIC handshake with the endpoint
2. Client verifies endpoint certificate
3. HTTP/2: Client sends HTTP/2 SETTINGS frame
4. HTTP/3: Client initiates HTTP/3 session after QUIC handshake
5. Session is considered established when the first stream can be opened

### 4.2 Endpoint Discovery

Endpoints are identified by:

- **Address**: IP address and port (e.g., `192.0.2.1:443`)
- **Hostname**: Used for TLS SNI and certificate verification
- **Remote ID** (optional): Alternative identifier for certificate verification

---

## 5. TCP Connection Tunneling

### 5.1 Opening a TCP Tunnel

To tunnel a TCP connection, the client sends an HTTP CONNECT request:

```http
CONNECT example.com:443 HTTP/2
:method: CONNECT
:authority: example.com:443
user-agent: <platform> <app_name>
proxy-authorization: Basic <base64(username:password)>
```

**Headers:**

| Header                | Required | Description                               |
|-----------------------|----------|-------------------------------------------|
| `:method`             | Yes      | Must be `CONNECT`                         |
| `:authority`          | Yes      | Target host and port in format `host:port`|
| `user-agent`          | Yes      | Platform identifier and application name  |
| `proxy-authorization` | Yes      | Basic authentication credentials          |

**Authority Format:**

- IPv4: `192.0.2.1:443`
- IPv6: `[2001:db8::1]:443`
- Hostname: `example.com:443`

### 5.2 Endpoint Response

**Success (200 OK):**

```http
HTTP/2 200
```

After receiving a 200 response, the stream becomes a bidirectional byte stream.
All data sent on the stream is forwarded to the target host, and all data
received from the target host is sent back on the stream.

**Authentication Required (407):**

```http
HTTP/2 407
```

The client MUST close the session and re-authenticate.

**Other Errors:**
The endpoint MAY return other HTTP status codes to indicate errors. The client
SHOULD treat any non-200 response as a connection failure.

### 5.3 Data Transfer

After successful CONNECT:

- Client sends data → Endpoint forwards to target
- Target sends data → Endpoint forwards to client
- Standard HTTP/2 or HTTP/3 flow control applies
- Stream closure indicates connection termination

### 5.4 Optional Padding

TCP CONNECT streams MAY negotiate padding to obscure the sizes of their initial
payload exchanges. Padding is not supported for the `_udp2`, `_icmp`, or
`_check` pseudo-hosts.

The client opts in by adding a `padding` header to the CONNECT request. Its
value SHOULD contain 16 to 32 characters whose HPACK or QPACK Huffman
representation does not compress their length. A capable endpoint adds a
`padding` header containing 30 to 62 characters to a successful response. The
first 16 response characters are selected independently from
``!#$()+<>?@[]^`{}``, and the remaining characters are `~`. Padding is enabled
only when the header is present in both messages; the header values themselves
do not carry protocol data.

The client MUST wait for the response before sending a padded payload when the
endpoint's capability is not already known.

When enabled, each direction independently frames its first eight payload
records:

```text
+----------------+--------------+----------------------+------------------+
| Payload Length | Padding Size | Payload              | Zero Padding     |
| 2 bytes        | 1 byte       | Payload Length bytes | Padding Size bytes |
+----------------+--------------+----------------------+------------------+
```

The payload length is an unsigned 16-bit integer in network byte order. The
padding size is selected uniformly from 0 through 255. Payloads larger than
65,535 bytes are split across records. After eight complete records in one
direction, all subsequent bytes in that direction are transmitted without
framing.

Graceful stream-closing HTTP/2 DATA frames are not padded.

### 5.5 Connection Closure

- **Graceful**: Send HTTP/2 `END_STREAM` flag or HTTP/3 `FIN`
- **Abrupt**: Send HTTP/2 `RST_STREAM` or HTTP/3 `STOP_SENDING`/`RESET_STREAM`

---

## 6. UDP Multiplexing

### 6.1 Overview

All UDP traffic is multiplexed over a single HTTP stream to reduce overhead.
The stream is established using a CONNECT request to a special pseudo-host.

### 6.2 Stream Establishment

```http
CONNECT _udp2 HTTP/2
:method: CONNECT
:authority: _udp2
user-agent: <platform> _udp2
proxy-authorization: Basic <base64(username:password)>
```

The authority `_udp2` is a reserved identifier for the UDP multiplexer stream.

### 6.3 Outgoing Packet Format (Client → Endpoint)

```text
+----------+----------------+-------------+---------------------+------------------+------------------+----------+---------+
|  Length  | Source Address | Source Port | Destination Address | Destination Port | App Name Len (L) | App Name | Payload |
| 4 bytes  |    16 bytes    |   2 bytes   |      16 bytes       |     2 bytes      |      1 byte      | L bytes  | N bytes |
+----------+----------------+-------------+---------------------+------------------+------------------+----------+---------+
```

**Field Descriptions:**

| Field               | Size     | Description                                      |
|---------------------|----------|--------------------------------------------------|
| Length              | 4 bytes  | Total packet length excluding this field         |
| Source Address      | 16 bytes | Source IP (IPv4 zero-padded to 16 bytes)         |
| Source Port         | 2 bytes  | Source UDP port                                  |
| Destination Address | 16 bytes | Destination IP (IPv4 zero-padded to 16 bytes)    |
| Destination Port    | 2 bytes  | Destination UDP port                             |
| App Name Length     | 1 byte   | Length of application name (0-255)               |
| App Name            | L bytes  | Application name string                          |
| Payload             | N bytes  | UDP payload data                                 |

**IPv4 Padding:**
IPv4 addresses are transmitted as 16 bytes with 12 leading zero bytes:

```text
00 00 00 00 00 00 00 00 00 00 00 00 XX XX XX XX
```

### 6.4 Incoming Packet Format (Endpoint → Client)

```text
+----------+----------------+-------------+---------------------+------------------+---------+
|  Length  | Source Address | Source Port | Destination Address | Destination Port | Payload |
| 4 bytes  |    16 bytes    |   2 bytes   |      16 bytes       |     2 bytes      | N bytes |
+----------+----------------+-------------+---------------------+------------------+---------+
```

Note: Incoming packets do not include the application name field.

### 6.5 Connection Tracking

The endpoint tracks UDP "connections" by the 4-tuple:

- Source Address
- Source Port
- Destination Address
- Destination Port

UDP connections have a default timeout of **120 seconds** of inactivity.

---

## 7. ICMP Multiplexing

### 7.1 Overview

ICMP echo requests (ping) are multiplexed over a single HTTP stream, similar to UDP.

### 7.2 Stream Establishment

```http
CONNECT _icmp HTTP/2
:method: CONNECT
:authority: _icmp
user-agent: <platform> _icmp
proxy-authorization: Basic <base64(username:password)>
```

### 7.3 Echo Request Format (Client → Endpoint)

```text
+----------+---------------------+-----------------+---------------+-----------+
|    ID    | Destination Address | Sequence Number | TTL/Hop Limit | Data Size |
| 2 bytes  |      16 bytes       |     2 bytes     |    1 byte     |  2 bytes  |
+----------+---------------------+-----------------+---------------+-----------+
```

**Field Descriptions:**

| Field               | Size     | Description                         |
|---------------------|----------|-------------------------------------|
| ID                  | 2 bytes  | ICMP identifier                     |
| Destination Address | 16 bytes | Target IP (IPv4 zero-padded)        |
| Sequence Number     | 2 bytes  | ICMP sequence number                |
| TTL/Hop Limit       | 1 byte   | IP TTL or IPv6 hop limit            |
| Data Size           | 2 bytes  | Size of echo data (not transmitted) |

### 7.4 Echo Reply Format (Endpoint → Client)

```text
+----------+----------------+--------+--------+-----------------+
|    ID    | Source Address |  Type  |  Code  | Sequence Number |
| 2 bytes  |    16 bytes    | 1 byte | 1 byte |     2 bytes     |
+----------+----------------+--------+--------+-----------------+
```

**Field Descriptions:**

| Field             | Size    | Description                                       |
|-------------------|---------|---------------------------------------------------|
| ID                | 2 bytes | ICMP identifier (matches request)                 |
| Source Address    | 16 bytes| Responding host IP                                |
| Type              | 1 byte  | ICMP type (0 = echo reply, 3 = unreachable, etc.) |
| Code              | 1 byte  | ICMP code                                         |
| Sequence Number   | 2 bytes | ICMP sequence number (matches request)            |

---

## 8. Health Checks

### 8.1 Purpose

Health checks verify that the session is still functional and can process requests.

### 8.2 Health Check Request

The client sends a CONNECT request to a special pseudo-host:

```http
CONNECT _check HTTP/2
:method: CONNECT
:authority: _check
user-agent: <platform>
proxy-authorization: Basic <base64(username:password)>
```

### 8.3 Health Check Response

- **200 OK**: Session is healthy
- **407**: Authentication failure
- **Other**: Session may be unhealthy

### 8.4 Health Check Timing

- Default health check timeout: **7000ms**
- Health checks are triggered when:
    - No data has been received for `timeout_ms` duration
    - The client explicitly requests a health check
- Receiving any data from the endpoint cancels pending health checks

---

## 9. Authentication

### 9.1 Basic Authentication

TrustTunnel uses HTTP Basic Authentication:

```text
proxy-authorization: Basic <credentials>
```

Where `<credentials>` is:

```text
base64(username + ":" + password)
```

### 9.2 Authentication Errors

| HTTP Status | Error Code      | Description                          |
|-------------|-----------------|--------------------------------------|
| 407         | `AUTH_REQUIRED` | Invalid or expired credentials       |

When receiving a 407 response or a GOAWAY frame with error code indicating authentication failure, the client MUST:

1. Close the current session
2. Obtain new credentials (if possible)
3. Establish a new session

---

## 10. Error Handling

### 10.1 HTTP/2 Error Codes

| Error Code       | Meaning                    |
|------------------|----------------------------|
| `NO_ERROR` (0x0) | Graceful shutdown          |
| `CANCEL` (0x8)   | Stream cancelled by client |
| Custom: `0x1F`   | Authentication required    |

### 10.2 HTTP/3 Error Codes

| Error Code                     | Meaning                          |
|--------------------------------|----------------------------------|
| `H3_NO_ERROR` (0x100)          | Graceful shutdown                |
| `H3_REQUEST_CANCELLED` (0x10c) | Stream cancelled                 |
| Custom: `0x1F`                 | Authentication required          |

### 10.3 Session Recovery

When a session is lost:

1. Client enters recovery mode
2. Exponential backoff between reconnection attempts:
   - Initial interval: **1000ms**
   - Backoff rate: **1.3×**
   - Location update period: **10000ms**
3. New connections during recovery:
   - If killswitch enabled: Queue or reject
   - If killswitch disabled: Route directly (bypass)

---

## 11. Wire Formats

### 11.1 Integer Encoding

All integers are encoded in **network byte order** (big-endian):

```text
uint16: [MSB][LSB]
uint32: [MSB][...][...][LSB]
```

### 11.2 IP Address Encoding

**IPv4 (padded to 16 bytes):**

```text
00 00 00 00 00 00 00 00 00 00 00 00 [4 bytes IPv4]
```

**IPv6 (16 bytes):**

```text
[16 bytes IPv6]
```

**Detection:**
An address is IPv4 if the first 12 bytes are zero AND it's not `::1`
(IPv6 loopback).

### 11.3 Authority String Format

The `:authority` header uses these formats:

| Type     | Format           | Example             |
|----------|------------------|---------------------|
| IPv4     | `address:port`   | `192.0.2.1:443`     |
| IPv6     | `[address]:port` | `[2001:db8::1]:443` |
| Hostname | `hostname:port`  | `example.com:443`   |

---

## 12. Security Considerations

### 12.1 Transport Security

- All traffic MUST be encrypted using TLS 1.2+ or QUIC
- Certificate verification MUST be performed
- Clients SHOULD support certificate pinning

### 12.2 Credential Security

- Credentials are transmitted in every CONNECT request
- Base64 encoding provides no security; TLS provides confidentiality
- Implementations SHOULD support credential rotation

### 12.3 Traffic Analysis Resistance

TrustTunnel provides some resistance to traffic analysis:

- Traffic appears as standard HTTPS
- Multiple connections are multiplexed
- However, traffic patterns may still be distinguishable

### 12.4 Endpoint Trust

- The endpoint can see all tunneled traffic (decrypted at endpoint)
- End-to-end encryption (e.g., HTTPS within tunnel) provides additional protection
- Users should only connect to trusted endpoints

---

## 13. Implementation Notes

### 13.1 Flow Control

**HTTP/2:**

- Respect stream and connection window sizes
- Initial stream window: 131072 bytes
- Send WINDOW_UPDATE frames appropriately

**HTTP/3:**

- Use QUIC flow control mechanisms
- Monitor stream capacity before sending

### 13.2 Connection Buffering

Implementations SHOULD buffer data when:

- Flow control prevents immediate sending
- The client is temporarily unable to receive

Buffer limits:

- Memory buffer threshold: Configurable (default varies)
- File-based buffering for large buffers

### 13.3 Timeouts

| Timeout              | Default | Description                           |
|----------------------|---------|---------------------------------------|
| Connection timeout   | 30s     | Time to establish endpoint connection |
| Health check timeout | 7s      | Time to receive health check response |
| TCP timeout          | 7200s   | Idle timeout for TCP connections      |
| UDP timeout          | 120s    | Idle timeout for UDP "connections"    |

### 13.4 Split Tunneling

Clients MAY implement split tunneling:

- **General mode**: Route all traffic except exclusions through endpoint
- **Selective mode**: Route only specified traffic through endpoint

Exclusions can be specified as:

- Domain names (with wildcard support: `*.example.com`)
- IP addresses
- CIDR ranges

### 13.5 DNS Handling

Clients MAY intercept DNS queries and:

- Route them through the tunnel
- Use custom DNS upstreams (DoH, DoT, DoQ)
- Perform local resolution for excluded domains

---

## Appendix A: Reserved Pseudo-Hosts

| Host     | Port | Purpose                           |
|----------|------|-----------------------------------|
| `_udp2`  | 0    | UDP multiplexer stream            |
| `_icmp`  | 0    | ICMP multiplexer stream           |
| `_check` | 0    | Health check stream               |

---

## Appendix B: Example Message Flows

### B.1 TCP Connection

```text
Client                                    Endpoint                              Target
   |                                          |                                    |
   |----CONNECT example.com:443-------------->|                                    |
   |                                          |----TCP SYN------------------------>|
   |                                          |<---TCP SYN-ACK---------------------|
   |                                          |----TCP ACK------------------------>|
   |<---HTTP 200 OK---------------------------|                                    |
   |                                          |                                    |
   |----DATA (TLS ClientHello)--------------->|----DATA (TLS ClientHello)--------->|
   |<---DATA (TLS ServerHello)----------------|<---DATA (TLS ServerHello)----------|
   |    ...                                   |    ...                             |
```

### B.2 UDP Datagram

```text
Client                                    Endpoint                              Target
   |                                          |                                    |
   |----CONNECT _udp2------------------------>|                                    |
   |<---HTTP 200 OK---------------------------|                                    |
   |                                          |                                    |
   |----[UDP Packet: src→dst, payload]------->|----UDP datagram------------------->|
   |<---[UDP Packet: dst→src, response]-------|<---UDP datagram--------------------|
```

---

## Appendix C: Version History

| Version | Date          | Changes                           |
|---------|---------------|-----------------------------------|
| 1.0     | Dec 24, 2025  | Initial public specification      |

---

## References

- [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000) - QUIC: A UDP-Based Multiplexed and Secure Transport
- [RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114) - HTTP/3
- [RFC 9113](https://datatracker.ietf.org/doc/html/rfc9113) - HTTP/2
- [RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231) - HTTP/1.1 Semantics and Content
- [RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235) - HTTP/1.1 Authentication
