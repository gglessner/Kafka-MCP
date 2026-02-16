# Kafka-MCP

A Model Context Protocol (MCP) server that provides direct Apache Kafka broker interaction through 30 tools spanning raw wire protocol operations and high-level client capabilities. Built for AI-driven security testing, administration, and operational monitoring.

## Author

**Garland Glessner** — [gglessner@gmail.com](mailto:gglessner@gmail.com)

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE)

## Features

- **Pure-Python Kafka wire protocol** — no external Kafka client library required for core functionality
- **30 MCP tools** across two families:
  - **20 raw protocol tools** (`kafka_*`) — byte-level broker interaction via custom wire protocol codec
  - **10 high-level tools** (`kafka_hl_*`) — operational features via `confluent-kafka` (consumer groups, SCRAM, etc.)
- **Full authentication support:**
  - PLAINTEXT, SSL, SASL_PLAINTEXT, SASL_SSL
  - SASL mechanisms: PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, OAUTHBEARER
  - Mutual TLS (mTLS) with client certificates
  - Password-protected keys, CRL, cipher suite, TLS version pinning
- **Security testing tools:**
  - `kafka_security_audit` — comprehensive broker security assessment
  - `kafka_compression_bomb` — DoS vulnerability testing
  - `kafka_raw_request` — arbitrary protocol-level requests
  - `kafka_hl_test_permissions` — permission enumeration

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/gglessner/kafka-mcp.git
cd kafka-mcp
pip install -r requirements.txt
```

### 2. Open in Cursor

Open the `kafka-mcp` directory as your project in Cursor. Everything is pre-configured:

- **`.cursor/mcp.json`** — auto-registers the MCP server (30 tools)
- **`.cursor/skills/kafka-mcp/SKILL.md`** — teaches the AI assistant all tools and auth options

No manual setup needed. See [MCP_SETUP.md](MCP_SETUP.md) for VS Code and advanced configurations.

### 3. Start using

Once the project is open, the 30 Kafka tools are immediately available. Connect to a broker:

```
kafka_connect(host="localhost", port=9092)
```

Or with authentication:

```
kafka_connect(host="broker.example.com", port=9093,
              security_protocol="SASL_SSL",
              sasl_mechanism="SCRAM-SHA-256",
              username="admin", password="secret")
```

## Tool Reference

### Raw Protocol Tools (kafka_*)

| Tool | Description |
|------|-------------|
| `kafka_connect` | Connect to a broker with full auth support |
| `kafka_disconnect` | Close a connection |
| `kafka_connections` | List all active connections |
| `kafka_api_versions` | Query supported API versions |
| `kafka_metadata` | Get cluster metadata (brokers, topics, partitions) |
| `kafka_describe_configs` | Read broker or topic configuration |
| `kafka_alter_configs` | Dynamically modify broker/topic configuration |
| `kafka_create_topics` | Create topics |
| `kafka_delete_topics` | Delete topics |
| `kafka_produce` | Produce a single message |
| `kafka_produce_batch` | Produce multiple messages in one batch |
| `kafka_fetch` | Fetch messages from a partition |
| `kafka_list_offsets` | Get offset info for a partition |
| `kafka_describe_acls` | List ACL bindings |
| `kafka_create_acls` | Create ACL bindings |
| `kafka_list_groups` | List consumer groups |
| `kafka_describe_groups` | Get consumer group details |
| `kafka_raw_request` | Send arbitrary Kafka protocol requests |
| `kafka_compression_bomb` | Test for compression bomb DoS vulnerability |
| `kafka_security_audit` | Run comprehensive security audit |

### High-Level Tools (kafka_hl_*)

| Tool | Description |
|------|-------------|
| `kafka_hl_connect` | Connect using confluent-kafka library |
| `kafka_hl_disconnect` | Disconnect high-level client |
| `kafka_hl_connections` | List high-level connections |
| `kafka_hl_produce` | Produce with delivery confirmation and headers |
| `kafka_hl_consume` | Consume from topics with consumer group |
| `kafka_hl_list_groups` | List consumer groups with state info |
| `kafka_hl_describe_group` | Detailed group info with member assignments |
| `kafka_hl_consumer_lag` | Get committed offsets per partition |
| `kafka_hl_scram_credentials` | Manage SCRAM user credentials |
| `kafka_hl_test_permissions` | Test what operations are permitted |

## Architecture

```
kafka-mcp/
  .cursor/
    mcp.json                # Auto-registers MCP server in Cursor
    skills/
      kafka-mcp/
        SKILL.md            # Skill — AI knows all 30 tools on project open
  kafka_mcp/
    __init__.py             # Package metadata
    protocol.py             # Kafka binary wire protocol codec (pure Python)
    connection.py           # TCP/TLS/SASL connection manager
    highlevel.py            # confluent-kafka wrapper for advanced operations
    server.py               # FastMCP server with 30 registered tools
  run_kafka_mcp.py          # Entry point
  requirements.txt          # Dependencies
```

### Wire Protocol Codec (`protocol.py`)

Implements encoding/decoding for 17 Kafka request types and 15 response types:
- CRC-32C checksums for RecordBatch v2
- Zigzag varint encoding for compact records
- Full RecordBatch framing with gzip compression support
- Non-flexible header v0 format

### Connection Manager (`connection.py`)

Thread-safe persistent connection management:
- SCRAM-SHA-256/512 client (RFC 5802 compliant with PBKDF2, HMAC, SASLprep)
- OAUTHBEARER token formatting
- Full TLS configuration (mTLS, CRL, cipher suites, version pinning)
- Automatic API version negotiation on connect

### High-Level Client (`highlevel.py`)

Optional `confluent-kafka` integration for features requiring a full client:
- Consumer group management with proper rebalancing
- SCRAM credential administration
- Delivery-confirmed produce with headers
- Permission testing

## Authentication Quick Reference

| Protocol | Encryption | Auth | Example |
|----------|-----------|------|---------|
| `PLAINTEXT` | No | No | Dev/test environments |
| `SSL` | TLS | mTLS certificates | `ssl_certfile`, `ssl_keyfile` |
| `SASL_PLAINTEXT` | No | SASL | Username/password over plaintext |
| `SASL_SSL` | TLS | SASL | Production with encryption + auth |

| SASL Mechanism | Description | Parameters |
|----------------|-------------|------------|
| `PLAIN` | Username/password | `username`, `password` |
| `SCRAM-SHA-256` | Challenge-response (SHA-256) | `username`, `password` |
| `SCRAM-SHA-512` | Challenge-response (SHA-512) | `username`, `password` |
| `OAUTHBEARER` | OAuth 2.0 bearer token | `oauth_token` |

## Requirements

- Python 3.9+
- `mcp[cli]` >= 1.0.0 (MCP framework)
- `confluent-kafka` >= 2.6.0 (optional, for `kafka_hl_*` tools)

## Tested Against

- Apache Kafka 4.0.0 (KRaft mode)
- Apache Kafka 4.1.1
- All 30 tools verified operational
