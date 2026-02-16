---
name: kafka-mcp
description: Interact with Apache Kafka brokers via the Kafka-MCP server. Provides two modes -- raw wire protocol for penetration testing and confluent-kafka for operational testing. Use when the user asks about Kafka operations, security auditing, producing/consuming, managing topics/ACLs/SCRAM credentials, or penetration testing Kafka.
---

# Kafka-MCP: Dual-Mode Kafka Broker Interaction

Two tool families for different purposes:

- **`kafka_*`** (20 tools) -- Raw wire protocol. Byte-level control, malformed requests, compression bombs, protocol manipulation. For pen testing and security research.
- **`kafka_hl_*`** (10 tools) -- confluent-kafka library. Consumer groups, rebalancing, SCRAM credentials, delivery guarantees. For operational testing.

Both share the same auth options. Use them together on the same broker.

## Quick Start

```
# Raw protocol (pen testing)
kafka_connect(host="broker", port=9092)
kafka_security_audit(conn_id="conn-1")

# High-level (operational testing)
kafka_hl_connect(host="broker", port=9092)
kafka_hl_test_permissions(conn_id="hl-broker:9092")
kafka_hl_consume(conn_id="hl-broker:9092", topics="my-topic", group_id="test")
```

## Authentication (all modes)

| Method | Protocol | Key Params |
|--------|----------|------------|
| None | `PLAINTEXT` | (defaults) |
| SASL/PLAIN | `SASL_PLAINTEXT` | `username`, `password` |
| SCRAM-SHA-256 | `SASL_PLAINTEXT` or `SASL_SSL` | `sasl_mechanism="SCRAM-SHA-256"`, `username`, `password` |
| SCRAM-SHA-512 | `SASL_SSL` | `sasl_mechanism="SCRAM-SHA-512"`, `username`, `password` |
| OAuth | `SASL_SSL` | `sasl_mechanism="OAUTHBEARER"`, `oauth_token` |
| TLS | `SSL` | `ssl_cafile` |
| mTLS | `SSL` | `ssl_cafile`, `ssl_certfile`, `ssl_keyfile` |
| mTLS + encrypted key | `SSL` | + `ssl_keypassword` |
| SASL + mTLS | `SASL_SSL` | combine SASL + SSL params |

Advanced TLS: `ssl_capath`, `ssl_crlfile`, `ssl_ciphers`, `tls_version`, `ssl_check_hostname`

## Raw Protocol Tools (kafka_*)

| Tool | Purpose |
|------|---------|
| `kafka_connect` | Connect (PLAINTEXT/SASL/SSL/mTLS) |
| `kafka_disconnect` | Close connection |
| `kafka_connections` | List connections |
| `kafka_api_versions` | API version negotiation |
| `kafka_metadata` | Brokers, topics, partitions |
| `kafka_describe_configs` | Read broker/topic configs |
| `kafka_alter_configs` | Modify dynamic configs (IncrementalAlterConfigs) |
| `kafka_create_topics` | Create topics |
| `kafka_delete_topics` | Delete topics |
| `kafka_produce` | Send single message |
| `kafka_produce_batch` | Send batch messages |
| `kafka_fetch` | Read from partition |
| `kafka_list_offsets` | Get earliest/latest offsets |
| `kafka_describe_acls` | List ACLs |
| `kafka_create_acls` | Create ACLs |
| `kafka_list_groups` | List consumer groups |
| `kafka_describe_groups` | Group details |
| `kafka_security_audit` | Full security assessment |
| `kafka_compression_bomb` | Test decompression DoS |
| `kafka_raw_request` | Send arbitrary hex bytes |

## High-Level Tools (kafka_hl_*)

| Tool | Purpose |
|------|---------|
| `kafka_hl_connect` | Connect via confluent-kafka |
| `kafka_hl_disconnect` | Close client |
| `kafka_hl_connections` | List high-level clients |
| `kafka_hl_consume` | Subscribe + consume with consumer group |
| `kafka_hl_produce` | Produce with delivery confirmation |
| `kafka_hl_list_groups` | List groups with state info |
| `kafka_hl_describe_group` | Group members + assignments |
| `kafka_hl_consumer_lag` | Committed offsets per partition |
| `kafka_hl_scram_credentials` | Create/delete/list SCRAM users |
| `kafka_hl_test_permissions` | Probe allowed operations |

## When to Use Which

| Task | Use |
|------|-----|
| Security audit | `kafka_security_audit` |
| Compression bomb test | `kafka_compression_bomb` |
| Malformed request fuzzing | `kafka_raw_request` |
| Dynamic config injection | `kafka_alter_configs` |
| Config reconnaissance | `kafka_describe_configs` |
| Consume with rebalancing | `kafka_hl_consume` |
| SCRAM user management | `kafka_hl_scram_credentials` |
| Permission enumeration | `kafka_hl_test_permissions` |
| Consumer lag monitoring | `kafka_hl_consumer_lag` |
| Produce with confirmation | `kafka_hl_produce` |

## JSON Argument Formats

- `kafka_create_topics`: `[{"name":"t","partitions":3,"replication":1}]`
- `kafka_alter_configs`: `[{"name":"key","value":"val","op":0}]` (0=SET, 1=DELETE)
- `kafka_create_acls`: `[{"resource_type":2,"resource_name":"t","principal":"User:x","host":"*","operation":3,"permission_type":3}]`
- `kafka_produce_batch`: `[{"key":"k","value":"v"}]`
