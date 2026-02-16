"""
Kafka-MCP Server

MCP server providing AI-driven Kafka broker interaction via pure-Python
wire protocol implementation. Supports PLAINTEXT, SASL/PLAIN, SSL, and
SASL_SSL security protocols with zero external dependencies.

Tools cover: connection management, cluster discovery, topic admin,
produce/consume, config management, ACL management, and security testing.
"""

import atexit
import json
import os
import sys
import time

from mcp.server.fastmcp import FastMCP

# Ensure package is importable
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_pkg_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from kafka_mcp.connection import ConnectionManager, KafkaConnection
from kafka_mcp.protocol import (
    RequestBuilder, ResponseParser, RESOURCE_BROKER, RESOURCE_TOPIC,
    API_NAMES, CONFIG_SOURCE, error_name,
)

# =====================================================================
#  Initialize
# =====================================================================

conn_mgr = ConnectionManager()
atexit.register(conn_mgr.shutdown_all)

mcp = FastMCP(
    "Kafka-MCP",
    instructions=(
        "Kafka-MCP provides direct interaction with Apache Kafka brokers via "
        "the binary wire protocol. No external Kafka client library needed. "
        "Workflow: kafka_connect -> explore with kafka_metadata/kafka_describe_configs "
        "-> admin ops (kafka_create_topics, kafka_alter_configs, kafka_produce, etc.) "
        "-> kafka_disconnect when done. "
        "Supports PLAINTEXT, SASL/PLAIN, SSL, and SASL_SSL connections. "
        "All operations use raw Kafka protocol encoding."
    ),
)

# =====================================================================
#  Helper
# =====================================================================

def _get_conn(conn_id: str) -> KafkaConnection:
    """Get a connected connection or raise helpful error."""
    conn = conn_mgr.get(conn_id)
    if not conn.connected:
        raise ConnectionError(
            f"Connection '{conn_id}' exists but is not connected. "
            f"Call kafka_connect again."
        )
    return conn


def _fmt_json(obj, indent=2) -> str:
    """Format object as JSON string."""
    return json.dumps(obj, indent=indent, default=str)


# =====================================================================
#  CONNECTION MANAGEMENT
# =====================================================================

@mcp.tool()
def kafka_connect(
    host: str,
    port: int = 9092,
    name: str = "",
    security_protocol: str = "PLAINTEXT",
    sasl_mechanism: str = "PLAIN",
    username: str = "",
    password: str = "",
    oauth_token: str = "",
    oauth_principal: str = "",
    ssl_cafile: str = "",
    ssl_capath: str = "",
    ssl_certfile: str = "",
    ssl_keyfile: str = "",
    ssl_keypassword: str = "",
    ssl_crlfile: str = "",
    ssl_ciphers: str = "",
    ssl_no_verify: bool = False,
    ssl_check_hostname: bool = True,
    tls_version: str = "",
    client_id: str = "kafka-mcp",
) -> str:
    """Connect to a Kafka broker with full auth support.

    Supports all Kafka security protocols and SASL mechanisms.
    The connection persists across tool calls until kafka_disconnect.

    Security Protocols:
      - PLAINTEXT:      No auth, no encryption
      - SSL:            TLS encryption, optional mTLS client certs
      - SASL_PLAINTEXT: SASL auth over plaintext
      - SASL_SSL:       SASL auth over TLS

    SASL Mechanisms (for SASL_PLAINTEXT / SASL_SSL):
      - PLAIN:          Username/password
      - SCRAM-SHA-256:  Challenge-response (SHA-256)
      - SCRAM-SHA-512:  Challenge-response (SHA-512)
      - OAUTHBEARER:    OAuth 2.0 bearer token

    Args:
        host: Broker hostname or IP address
        port: Broker port (default: 9092)
        name: Optional connection name (auto-generated if empty)
        security_protocol: PLAINTEXT, SASL_PLAINTEXT, SSL, or SASL_SSL
        sasl_mechanism: PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, or OAUTHBEARER
        username: SASL username (for PLAIN, SCRAM)
        password: SASL password (for PLAIN, SCRAM)
        oauth_token: OAuth bearer token (for OAUTHBEARER)
        oauth_principal: OAuth principal/authzid (for OAUTHBEARER, optional)
        ssl_cafile: Path to CA certificate file (PEM) for server verification
        ssl_capath: Path to directory of CA certificates
        ssl_certfile: Path to client certificate (PEM) for mutual TLS (mTLS)
        ssl_keyfile: Path to client private key (PEM) for mTLS
        ssl_keypassword: Password for encrypted private key
        ssl_crlfile: Path to Certificate Revocation List (PEM)
        ssl_ciphers: Colon-separated cipher suite string (e.g. "ECDHE+AESGCM")
        ssl_no_verify: Skip all SSL certificate verification
        ssl_check_hostname: Verify server certificate hostname (default: true)
        tls_version: Pin TLS version: "TLSv1.2" or "TLSv1.3" (empty = auto)
        client_id: Kafka client ID sent in requests
    """
    conn_id, conn = conn_mgr.create(
        host=host, port=port, name=name,
        security_protocol=security_protocol,
        sasl_mechanism=sasl_mechanism,
        username=username or None, password=password or None,
        oauth_token=oauth_token or None,
        oauth_principal=oauth_principal or None,
        ssl_cafile=ssl_cafile or None, ssl_capath=ssl_capath or None,
        ssl_certfile=ssl_certfile or None, ssl_keyfile=ssl_keyfile or None,
        ssl_keypassword=ssl_keypassword or None,
        ssl_crlfile=ssl_crlfile or None, ssl_ciphers=ssl_ciphers or None,
        ssl_no_verify=ssl_no_verify,
        ssl_check_hostname=ssl_check_hostname,
        tls_version=tls_version or None,
        client_id=client_id,
    )
    try:
        result = conn.connect()
        lines = [
            f"Connected to Kafka broker.\n",
            f"  Connection ID : {conn_id}",
            f"  Host          : {host}:{port}",
            f"  Protocol      : {security_protocol}",
            f"  Authenticated : {result.get('authenticated', False)}",
            f"  API count     : {result.get('api_count', 'N/A')}",
        ]
        if result.get("sasl_mechanism"):
            lines.append(f"  SASL mechanism : {result['sasl_mechanism']}")
        if result.get("auth_method"):
            lines.append(f"  Auth method    : {result['auth_method']}")
        if result.get("tls_version"):
            lines.append(f"  TLS version    : {result['tls_version']}")
        if result.get("tls_cipher"):
            lines.append(f"  TLS cipher     : {result['tls_cipher']}")
        if result.get("server_cert_subject"):
            lines.append(f"  Server cert    : {result['server_cert_subject']}")
        lines.append(f"\nUse connection ID '{conn_id}' for subsequent operations.")
        return '\n'.join(lines)
    except Exception as e:
        conn_mgr.remove(conn_id)
        return f"Connection failed: {e}"


@mcp.tool()
def kafka_disconnect(conn_id: str) -> str:
    """Disconnect from a Kafka broker.

    Args:
        conn_id: Connection ID from kafka_connect
    """
    result = conn_mgr.remove(conn_id)
    return (
        f"Disconnected.\n"
        f"  Requests sent   : {result.get('requests_sent', 0)}\n"
        f"  Uptime          : {result.get('uptime_seconds', 0)}s"
    )


@mcp.tool()
def kafka_connections() -> str:
    """List all active Kafka connections with status."""
    conns = conn_mgr.list_all()
    if not conns:
        return "No active connections. Use kafka_connect to establish one."
    lines = ["Active Kafka Connections:\n"]
    for c in conns:
        status = "CONNECTED" if c["connected"] else "DISCONNECTED"
        auth = "auth" if c["authenticated"] else "no-auth"
        lines.append(
            f"  {c['conn_id']}: {c['host']}:{c['port']} "
            f"[{c['protocol']}] {status} ({auth}) "
            f"| {c['requests_sent']} requests | {c['uptime_seconds']}s uptime"
        )
    return '\n'.join(lines)


# =====================================================================
#  CLUSTER DISCOVERY
# =====================================================================

@mcp.tool()
def kafka_api_versions(conn_id: str) -> str:
    """Get supported API versions from the broker.

    Returns the complete list of Kafka protocol APIs the broker supports,
    with minimum and maximum version numbers for each.

    Args:
        conn_id: Connection ID from kafka_connect
    """
    conn = _get_conn(conn_id)
    req, _ = conn.builder.api_versions()
    resp = conn.send_recv(req)
    result = conn.parser.parse_api_versions(resp)
    if result["error_code"] != 0:
        return f"Error: {result['error']}"

    lines = [f"Supported APIs ({len(result['apis'])} total):\n"]
    for key in sorted(result["apis"]):
        api = result["apis"][key]
        lines.append(f"  {key:3d}: {api['name']:<35s} v{api['min_version']}-v{api['max_version']}")
    return '\n'.join(lines)


@mcp.tool()
def kafka_metadata(conn_id: str, topics: str = "") -> str:
    """Get cluster metadata: brokers, topics, partitions.

    Args:
        conn_id: Connection ID from kafka_connect
        topics: Comma-separated topic names (empty = all topics)
    """
    conn = _get_conn(conn_id)
    topic_list = [t.strip() for t in topics.split(',') if t.strip()] if topics else None
    req, _ = conn.builder.metadata(topic_list)
    resp = conn.send_recv(req)
    result = conn.parser.parse_metadata(resp)

    lines = [f"Cluster Metadata:\n"]
    lines.append(f"  Controller: broker {result['controller_id']}")
    lines.append(f"\n  Brokers ({len(result['brokers'])}):")
    for b in result["brokers"]:
        lines.append(f"    {b['node_id']}: {b['host']}:{b['port']}"
                     + (f" (rack={b['rack']})" if b['rack'] else ""))

    lines.append(f"\n  Topics ({len(result['topics'])}):")
    for t in result["topics"]:
        err = f" [ERROR: {error_name(t['error_code'])}]" if t["error_code"] != 0 else ""
        internal = " (internal)" if t["is_internal"] else ""
        lines.append(f"    {t['name']}{internal}{err}")
        for p in t["partitions"]:
            p_err = f" [ERROR: {error_name(p['error_code'])}]" if p["error_code"] != 0 else ""
            lines.append(
                f"      partition {p['partition_id']}: leader={p['leader']} "
                f"replicas={p['replicas']} isr={p['isr']}{p_err}"
            )
    return '\n'.join(lines)


# =====================================================================
#  CONFIGURATION MANAGEMENT
# =====================================================================

@mcp.tool()
def kafka_describe_configs(
    conn_id: str,
    resource_type: str = "broker",
    resource_name: str = "1",
    config_names: str = "",
    filter_text: str = "",
) -> str:
    """Read configuration for a broker or topic.

    Args:
        conn_id: Connection ID from kafka_connect
        resource_type: "broker" (type 4) or "topic" (type 2)
        resource_name: Broker ID (e.g. "1") or topic name
        config_names: Comma-separated config names (empty = all)
        filter_text: Only show configs whose name contains this text
    """
    conn = _get_conn(conn_id)
    rtype = RESOURCE_BROKER if resource_type.lower() == "broker" else RESOURCE_TOPIC
    names = [n.strip() for n in config_names.split(',') if n.strip()] if config_names else None

    req, _ = conn.builder.describe_configs(rtype, resource_name, names)
    resp = conn.send_recv(req)
    result = conn.parser.parse_describe_configs(resp)

    lines = []
    for res in result["resources"]:
        if res["error_code"] != 0:
            lines.append(f"Error: {error_name(res['error_code'])}: {res['error_message']}")
            continue

        configs = res["configs"]
        if filter_text:
            configs = [c for c in configs if filter_text.lower() in c["name"].lower()]

        lines.append(f"Configs for {resource_type} '{resource_name}' ({len(configs)} shown):\n")
        for c in configs:
            val = "(sensitive)" if c["is_sensitive"] else (c["value"] or "(null)")
            src = c["source"]
            ro = " [read-only]" if c["read_only"] else ""
            lines.append(f"  {c['name']:<55s} = {val[:80]:<80s} [{src}]{ro}")
    return '\n'.join(lines) if lines else "No configs returned."


@mcp.tool()
def kafka_alter_configs(
    conn_id: str,
    resource_type: str = "broker",
    resource_name: str = "1",
    configs: str = "",
    validate_only: bool = False,
) -> str:
    """Dynamically modify broker or topic configuration.

    Uses IncrementalAlterConfigs API (key 44). Changes take effect
    immediately for most configs and persist across broker restarts.

    Args:
        conn_id: Connection ID from kafka_connect
        resource_type: "broker" (type 4) or "topic" (type 2)
        resource_name: Broker ID or topic name
        configs: JSON array of config operations, e.g.:
                 [{"name":"log.retention.ms","value":"86400000"}]
                 Each entry: name (required), value (string or null),
                 op (0=SET, 1=DELETE, default 0)
        validate_only: If true, validate but don't apply
    """
    conn = _get_conn(conn_id)
    rtype = RESOURCE_BROKER if resource_type.lower() == "broker" else RESOURCE_TOPIC

    try:
        cfg_list = json.loads(configs)
    except json.JSONDecodeError as e:
        return f"Invalid JSON for configs: {e}\nExpected: [{{'name':'key','value':'val'}}]"

    req, _ = conn.builder.incremental_alter_configs(rtype, resource_name, cfg_list, validate_only)
    resp = conn.send_recv(req)
    result = conn.parser.parse_incremental_alter_configs(resp)

    lines = [f"IncrementalAlterConfigs {'(validate_only)' if validate_only else ''}:\n"]
    for res in result["resources"]:
        status = "OK" if res["error_code"] == 0 else f"ERROR: {res['error']} - {res['error_message']}"
        lines.append(f"  {resource_type} '{res['resource_name']}': {status}")
    return '\n'.join(lines)


# =====================================================================
#  TOPIC MANAGEMENT
# =====================================================================

@mcp.tool()
def kafka_create_topics(
    conn_id: str,
    topics: str = "",
    timeout_ms: int = 30000,
    validate_only: bool = False,
) -> str:
    """Create one or more Kafka topics.

    Args:
        conn_id: Connection ID from kafka_connect
        topics: JSON array of topic specs, e.g.:
                [{"name":"my-topic","partitions":3,"replication":1}]
                Optional per-topic: configs dict (e.g. {"retention.ms":"86400000"})
        timeout_ms: Timeout for topic creation
        validate_only: If true, validate but don't create
    """
    conn = _get_conn(conn_id)
    try:
        topic_list = json.loads(topics)
    except json.JSONDecodeError as e:
        return f"Invalid JSON for topics: {e}\nExpected: [{{'name':'topic','partitions':1,'replication':1}}]"

    req, _ = conn.builder.create_topics(topic_list, timeout_ms, validate_only)
    resp = conn.send_recv(req)
    result = conn.parser.parse_create_topics(resp)

    lines = [f"CreateTopics {'(validate_only)' if validate_only else ''}:\n"]
    for t in result["topics"]:
        status = "OK" if t["error_code"] == 0 else f"{t['error']}: {t['error_message']}"
        lines.append(f"  {t['name']}: {status}")
    return '\n'.join(lines)


@mcp.tool()
def kafka_delete_topics(conn_id: str, topics: str = "") -> str:
    """Delete one or more Kafka topics.

    Args:
        conn_id: Connection ID from kafka_connect
        topics: Comma-separated topic names to delete
    """
    conn = _get_conn(conn_id)
    topic_list = [t.strip() for t in topics.split(',') if t.strip()]
    if not topic_list:
        return "No topics specified. Provide comma-separated topic names."

    req, _ = conn.builder.delete_topics(topic_list)
    resp = conn.send_recv(req)
    result = conn.parser.parse_delete_topics(resp)

    lines = ["DeleteTopics:\n"]
    for t in result["topics"]:
        status = "OK" if t["error_code"] == 0 else t["error"]
        lines.append(f"  {t['name']}: {status}")
    return '\n'.join(lines)


# =====================================================================
#  PRODUCE & CONSUME
# =====================================================================

@mcp.tool()
def kafka_produce(
    conn_id: str,
    topic: str,
    value: str = "",
    key: str = "",
    partition: int = 0,
    compression: str = "none",
    acks: int = 1,
) -> str:
    """Produce a message to a Kafka topic.

    Args:
        conn_id: Connection ID from kafka_connect
        topic: Topic name to produce to
        value: Message value (string)
        key: Message key (string, empty = null key)
        partition: Target partition (default: 0)
        compression: "none" or "gzip"
        acks: 0, 1, or -1 (all)
    """
    conn = _get_conn(conn_id)
    records = [{"key": key or None, "value": value}]
    req, _ = conn.builder.produce(topic, partition, records, acks=acks, compression=compression)
    resp = conn.send_recv(req, timeout=60.0)
    result = conn.parser.parse_produce(resp)

    lines = ["Produce result:\n"]
    for r in result["results"]:
        for p in r["partitions"]:
            if p["error_code"] == 0:
                lines.append(f"  {r['topic']}-{p['partition']}: offset={p['base_offset']} (success)")
            else:
                lines.append(f"  {r['topic']}-{p['partition']}: {p['error']}")
    return '\n'.join(lines)


@mcp.tool()
def kafka_produce_batch(
    conn_id: str,
    topic: str,
    messages: str = "",
    partition: int = 0,
    compression: str = "none",
) -> str:
    """Produce multiple messages to a Kafka topic in one batch.

    Args:
        conn_id: Connection ID from kafka_connect
        topic: Topic name
        messages: JSON array of messages, e.g.:
                  [{"key":"k1","value":"v1"},{"value":"v2"}]
        partition: Target partition
        compression: "none" or "gzip"
    """
    conn = _get_conn(conn_id)
    try:
        msg_list = json.loads(messages)
    except json.JSONDecodeError as e:
        return f"Invalid JSON: {e}"

    req, _ = conn.builder.produce(topic, partition, msg_list, compression=compression)
    resp = conn.send_recv(req, timeout=60.0)
    result = conn.parser.parse_produce(resp)

    lines = [f"Batch produce ({len(msg_list)} messages):\n"]
    for r in result["results"]:
        for p in r["partitions"]:
            if p["error_code"] == 0:
                lines.append(f"  {r['topic']}-{p['partition']}: base_offset={p['base_offset']}")
            else:
                lines.append(f"  {r['topic']}-{p['partition']}: {p['error']}")
    return '\n'.join(lines)


@mcp.tool()
def kafka_fetch(
    conn_id: str,
    topic: str,
    partition: int = 0,
    offset: int = 0,
    max_bytes: int = 65536,
    max_wait_ms: int = 5000,
) -> str:
    """Fetch messages from a Kafka topic partition.

    Returns raw record batch data. For human-readable output, the response
    is decoded as best-effort UTF-8.

    Args:
        conn_id: Connection ID from kafka_connect
        topic: Topic name
        partition: Partition to fetch from
        offset: Starting offset (0 = beginning)
        max_bytes: Maximum bytes to fetch
        max_wait_ms: Maximum wait time for data
    """
    conn = _get_conn(conn_id)
    req, _ = conn.builder.fetch(topic, partition, offset, max_bytes, max_wait_ms)
    resp = conn.send_recv(req, timeout=max_wait_ms / 1000 + 10)

    # Parse Fetch v4 response (simplified)
    lines = [f"Fetch {topic}-{partition} from offset {offset}:\n"]
    try:
        off = 0
        throttle = int.from_bytes(resp[off:off+4], 'big'); off += 4
        topic_count = int.from_bytes(resp[off:off+4], 'big'); off += 4
        for _ in range(topic_count):
            tname_len = int.from_bytes(resp[off:off+2], 'big'); off += 2
            tname = resp[off:off+tname_len].decode('utf-8', errors='replace'); off += tname_len
            part_count = int.from_bytes(resp[off:off+4], 'big'); off += 4
            for _ in range(part_count):
                pid = int.from_bytes(resp[off:off+4], 'big'); off += 4
                ec = int.from_bytes(resp[off:off+2], 'big', signed=True); off += 2
                hw_offset = int.from_bytes(resp[off:off+8], 'big', signed=True); off += 8
                last_stable = int.from_bytes(resp[off:off+8], 'big', signed=True); off += 8
                # aborted txn array (v4+)
                abort_count = int.from_bytes(resp[off:off+4], 'big', signed=True); off += 4
                if abort_count > 0:
                    off += abort_count * 16  # producer_id(8) + first_offset(8)
                record_set_size = int.from_bytes(resp[off:off+4], 'big', signed=True); off += 4

                lines.append(f"  Partition {pid}: error={error_name(ec)}, hw_offset={hw_offset}")

                if record_set_size > 0 and ec == 0:
                    record_data = resp[off:off+record_set_size]
                    off += record_set_size
                    lines.append(f"  Record set: {record_set_size} bytes")
                    # Show hex preview
                    preview = record_data[:200].hex()
                    lines.append(f"  Hex preview: {preview[:100]}...")
                    # Try to extract readable strings
                    readable = record_data.decode('utf-8', errors='replace')
                    # Find printable segments
                    segments = []
                    current = []
                    for ch in readable:
                        if ch.isprintable() or ch in '\n\r\t':
                            current.append(ch)
                        else:
                            if len(current) > 4:
                                segments.append(''.join(current))
                            current = []
                    if len(current) > 4:
                        segments.append(''.join(current))
                    if segments:
                        lines.append(f"  Readable strings: {'; '.join(s[:100] for s in segments[:10])}")
                elif record_set_size <= 0:
                    lines.append(f"  No records at this offset.")
    except Exception as e:
        lines.append(f"  Parse error: {e}")
        lines.append(f"  Raw response ({len(resp)} bytes): {resp[:200].hex()}")

    return '\n'.join(lines)


@mcp.tool()
def kafka_list_offsets(
    conn_id: str,
    topic: str,
    partition: int = 0,
    timestamp: int = -1,
) -> str:
    """Get offset information for a topic partition.

    Args:
        conn_id: Connection ID from kafka_connect
        topic: Topic name
        partition: Partition number
        timestamp: -1 = latest offset, -2 = earliest offset, or epoch ms
    """
    conn = _get_conn(conn_id)
    req, _ = conn.builder.list_offsets(topic, partition, timestamp)
    resp = conn.send_recv(req)
    result = conn.parser.parse_list_offsets(resp)

    ts_desc = {-1: "latest", -2: "earliest"}.get(timestamp, f"at_time={timestamp}")
    lines = [f"ListOffsets ({ts_desc}):\n"]
    for t in result["topics"]:
        for p in t["partitions"]:
            if p["error_code"] == 0:
                lines.append(f"  {t['topic']}-{p['partition']}: offset={p['offset']} timestamp={p['timestamp']}")
            else:
                lines.append(f"  {t['topic']}-{p['partition']}: {p['error']}")
    return '\n'.join(lines)


# =====================================================================
#  ACL MANAGEMENT
# =====================================================================

@mcp.tool()
def kafka_describe_acls(
    conn_id: str,
    resource_type: int = 1,
    resource_name: str = "",
    principal: str = "",
) -> str:
    """List ACL bindings on the cluster.

    Args:
        conn_id: Connection ID from kafka_connect
        resource_type: 1=ANY, 2=TOPIC, 3=GROUP, 4=CLUSTER, 5=TRANSACTIONAL_ID
        resource_name: Filter by resource name (empty = any)
        principal: Filter by principal (e.g. "User:admin", empty = any)
    """
    conn = _get_conn(conn_id)
    req, _ = conn.builder.describe_acls(
        resource_type=resource_type,
        resource_name=resource_name or None,
        principal=principal or None,
    )
    resp = conn.send_recv(req)
    result = conn.parser.parse_describe_acls(resp)

    if result["error_code"] != 0:
        return f"Error: {result['error']}: {result['error_message']}"

    OPS = {0: "UNKNOWN", 1: "ANY", 2: "ALL", 3: "READ", 4: "WRITE",
           5: "CREATE", 6: "DELETE", 7: "ALTER", 8: "DESCRIBE",
           9: "CLUSTER_ACTION", 10: "DESCRIBE_CONFIGS", 11: "ALTER_CONFIGS",
           12: "IDEMPOTENT_WRITE"}
    PERMS = {0: "UNKNOWN", 1: "ANY", 2: "DENY", 3: "ALLOW"}
    RTYPES = {0: "UNKNOWN", 1: "ANY", 2: "TOPIC", 3: "GROUP",
              4: "CLUSTER", 5: "TRANSACTIONAL_ID", 6: "DELEGATION_TOKEN"}

    acls = result["acls"]
    if not acls:
        return "No ACLs found (authorization may not be configured)."

    lines = [f"ACLs ({len(acls)} bindings):\n"]
    for a in acls:
        lines.append(
            f"  {PERMS.get(a['permission_type'], '?'):5s} | "
            f"{a['principal']:<30s} | "
            f"{OPS.get(a['operation'], '?'):<18s} | "
            f"{RTYPES.get(a['resource_type'], '?'):<12s} | "
            f"{a['resource_name']:<20s} | "
            f"host={a['host']}"
        )
    return '\n'.join(lines)


@mcp.tool()
def kafka_create_acls(conn_id: str, acls: str = "") -> str:
    """Create ACL bindings.

    Args:
        conn_id: Connection ID from kafka_connect
        acls: JSON array of ACL specs, e.g.:
              [{"resource_type":2,"resource_name":"my-topic",
                "principal":"User:alice","host":"*",
                "operation":3,"permission_type":3}]
              resource_type: 2=TOPIC,3=GROUP,4=CLUSTER
              operation: 2=ALL,3=READ,4=WRITE,5=CREATE,6=DELETE,
                        7=ALTER,8=DESCRIBE,10=DESCRIBE_CONFIGS,11=ALTER_CONFIGS
              permission_type: 2=DENY,3=ALLOW
    """
    conn = _get_conn(conn_id)
    try:
        acl_list = json.loads(acls)
    except json.JSONDecodeError as e:
        return f"Invalid JSON: {e}"

    req, _ = conn.builder.create_acls(acl_list)
    resp = conn.send_recv(req)
    result = conn.parser.parse_create_acls(resp)

    lines = [f"CreateAcls ({len(result['results'])} bindings):\n"]
    for i, r in enumerate(result["results"]):
        status = "OK" if r["error_code"] == 0 else f"{r['error']}: {r['error_message']}"
        lines.append(f"  ACL {i}: {status}")
    return '\n'.join(lines)


# =====================================================================
#  CONSUMER GROUPS
# =====================================================================

@mcp.tool()
def kafka_list_groups(conn_id: str) -> str:
    """List all consumer groups on the broker.

    Args:
        conn_id: Connection ID from kafka_connect
    """
    conn = _get_conn(conn_id)
    req, _ = conn.builder.list_groups()
    resp = conn.send_recv(req)
    result = conn.parser.parse_list_groups(resp)

    if result["error_code"] != 0:
        return f"Error: {result['error']}"

    groups = result["groups"]
    if not groups:
        return "No consumer groups found."

    lines = [f"Consumer Groups ({len(groups)}):\n"]
    for g in groups:
        lines.append(f"  {g['group_id']:<40s} protocol={g['protocol_type']}")
    return '\n'.join(lines)


@mcp.tool()
def kafka_describe_groups(conn_id: str, group_ids: str = "") -> str:
    """Get detailed information about consumer groups.

    Args:
        conn_id: Connection ID from kafka_connect
        group_ids: Comma-separated group IDs to describe
    """
    conn = _get_conn(conn_id)
    gids = [g.strip() for g in group_ids.split(',') if g.strip()]
    if not gids:
        return "No group IDs specified."

    req, _ = conn.builder.describe_groups(gids)
    resp = conn.send_recv(req)
    result = conn.parser.parse_describe_groups(resp)

    lines = []
    for g in result["groups"]:
        if g["error_code"] != 0:
            lines.append(f"Group '{g['group_id']}': {g['error']}")
            continue
        lines.append(f"Group: {g['group_id']}")
        lines.append(f"  State: {g['state']}")
        lines.append(f"  Protocol: {g['protocol_type']} / {g['protocol']}")
        lines.append(f"  Members ({len(g['members'])}):")
        for m in g["members"]:
            lines.append(f"    {m['member_id'][:40]}... client={m['client_id']} host={m['client_host']}")
    return '\n'.join(lines) if lines else "No group information returned."


# =====================================================================
#  SECURITY TESTING
# =====================================================================

@mcp.tool()
def kafka_compression_bomb(
    conn_id: str,
    topic: str = "poc-bomb-test",
    decompressed_mb: int = 100,
) -> str:
    """Send a compression bomb to test for CVE: unbounded decompression.

    Crafts a gzip-compressed Produce request that is small on the wire
    but decompresses to a much larger payload. Tests whether the broker
    enforces a decompressed size limit.

    WARNING: This is a destructive DoS test. Only use on test brokers.

    Args:
        conn_id: Connection ID from kafka_connect
        topic: Topic to produce to (will be created if needed)
        decompressed_mb: Target decompressed size in MB (default: 100)
    """
    conn = _get_conn(conn_id)

    # Create topic first
    req, _ = conn.builder.create_topics([{"name": topic, "partitions": 1, "replication": 1}])
    resp = conn.send_recv(req)
    create_result = conn.parser.parse_create_topics(resp)
    topic_status = create_result["topics"][0] if create_result["topics"] else {}
    if topic_status.get("error_code", 0) not in (0, 36):  # 0=OK, 36=ALREADY_EXISTS
        return f"Failed to create topic: {topic_status}"

    time.sleep(2)  # Wait for partition leader

    # Build and send bomb
    req, _, info = conn.builder.produce_compression_bomb(topic, 0, decompressed_mb)
    t0 = time.time()

    try:
        resp = conn.send_recv(req, timeout=120.0)
    except Exception as e:
        elapsed = time.time() - t0
        return (
            f"Compression Bomb Test:\n"
            f"  Compressed    : {info['compressed_bytes']:,} bytes ({info['compressed_bytes']/1024:.1f} KB)\n"
            f"  Decompressed  : {info['decompressed_bytes']:,} bytes ({info['decompressed_bytes']/(1024*1024):.1f} MB)\n"
            f"  Ratio         : {info['ratio']:.0f}:1\n"
            f"  Batch on wire : {info['batch_bytes']:,} bytes\n\n"
            f"  Result: Connection error after {elapsed:.1f}s: {e}\n"
            f"  (Broker may have crashed or timed out processing the bomb)"
        )

    elapsed = time.time() - t0
    result = conn.parser.parse_produce(resp)

    ec = -1
    base_offset = -1
    for r in result["results"]:
        for p in r["partitions"]:
            ec = p["error_code"]
            base_offset = p["base_offset"]

    lines = [
        f"Compression Bomb Test:\n",
        f"  Compressed    : {info['compressed_bytes']:>12,} bytes ({info['compressed_bytes']/1024:.1f} KB)",
        f"  Decompressed  : {info['decompressed_bytes']:>12,} bytes ({info['decompressed_bytes']/(1024*1024):.1f} MB)",
        f"  Ratio         : {info['ratio']:>12,.0f}:1",
        f"  Batch on wire : {info['batch_bytes']:>12,} bytes",
        f"  Processing    : {elapsed:>12.2f} s",
        f"  Error code    : {error_name(ec)}",
        f"  Base offset   : {base_offset}",
        "",
    ]
    if ec == 0:
        lines.append("  >>> VULNERABILITY CONFIRMED <<<")
        lines.append(f"  Broker accepted {info['compressed_bytes']/1024:.0f} KB that decompresses to "
                     f"{info['decompressed_bytes']/(1024*1024):.0f} MB ({info['ratio']:.0f}x amplification)")
    else:
        lines.append(f"  Broker rejected the request: {error_name(ec)}")

    return '\n'.join(lines)


@mcp.tool()
def kafka_security_audit(conn_id: str) -> str:
    """Run a comprehensive security audit of the connected Kafka broker.

    Checks: authorization config, listener security, SASL mechanisms,
    SSL/TLS status, sensitive config exposure, dynamic config permissions,
    and default security posture.

    Args:
        conn_id: Connection ID from kafka_connect
    """
    conn = _get_conn(conn_id)

    lines = ["=" * 60, "  Kafka Security Audit", "=" * 60, ""]

    # 1. Read broker configs
    req, _ = conn.builder.describe_configs(RESOURCE_BROKER, "1")
    try:
        resp = conn.send_recv(req)
        result = conn.parser.parse_describe_configs(resp)
    except Exception as e:
        return f"Failed to read broker configs: {e}"

    configs = {}
    sensitive_names = []
    dynamic_configs = []
    for res in result["resources"]:
        for c in res.get("configs", []):
            configs[c["name"]] = c
            if c["is_sensitive"]:
                sensitive_names.append(c["name"])
            if c["source"] in ("DYNAMIC_BROKER", "DYNAMIC_DEFAULT_BROKER"):
                dynamic_configs.append(c["name"])

    # 2. Authorization
    lines.append("[1] Authorization")
    auth_class = configs.get("authorizer.class.name", {}).get("value", "")
    if auth_class:
        lines.append(f"  [+] Authorizer configured: {auth_class}")
    else:
        lines.append(f"  [!] CRITICAL: No authorizer configured (all operations permitted)")

    super_users = configs.get("super.users", {}).get("value", "")
    lines.append(f"  super.users: {super_users or '(empty)'}")

    allow_all = configs.get("allow.everyone.if.no.acl.found", {}).get("value", "")
    if allow_all and allow_all.lower() == "true":
        lines.append(f"  [!] WARNING: allow.everyone.if.no.acl.found=true (ACL bypass)")
    lines.append("")

    # 3. Listeners & Security Protocol
    lines.append("[2] Listeners & Protocol")
    listeners = configs.get("listeners", {}).get("value", "")
    lines.append(f"  listeners: {listeners}")
    adv = configs.get("advertised.listeners", {}).get("value", "")
    lines.append(f"  advertised.listeners: {adv}")
    if "PLAINTEXT" in listeners:
        lines.append(f"  [!] WARNING: PLAINTEXT listener (no encryption, no auth)")
    if "SASL" in listeners:
        mechs = configs.get("sasl.enabled.mechanisms", {}).get("value", "")
        lines.append(f"  SASL mechanisms: {mechs}")
    if "SSL" in listeners:
        lines.append(f"  [+] SSL/TLS enabled")
    lines.append("")

    # 4. Sensitive Config Names
    lines.append(f"[3] Sensitive Configs ({len(sensitive_names)} found)")
    for sn in sensitive_names[:15]:
        lines.append(f"  {sn}")
    if len(sensitive_names) > 15:
        lines.append(f"  ... and {len(sensitive_names) - 15} more")
    lines.append("")

    # 5. Dynamic overrides
    lines.append(f"[4] Dynamic Config Overrides ({len(dynamic_configs)} found)")
    if dynamic_configs:
        for dc in dynamic_configs:
            val = configs[dc].get("value", "")
            lines.append(f"  [!] {dc} = {val[:60]}")
    else:
        lines.append(f"  No dynamic overrides detected.")
    lines.append("")

    # 6. Test dynamic config write
    lines.append("[5] Dynamic Config Write Test")
    try:
        test_cfg = [{"name": "attacker.mcp.test", "value": "audit-probe", "op": 0}]
        req, _ = conn.builder.incremental_alter_configs(RESOURCE_BROKER, "1", test_cfg, validate_only=True)
        resp = conn.send_recv(req)
        alter_result = conn.parser.parse_incremental_alter_configs(resp)
        ec = alter_result["resources"][0]["error_code"] if alter_result["resources"] else -1
        if ec == 0:
            lines.append(f"  [!] CRITICAL: Arbitrary config keys ACCEPTED (customPropsAllowed=true)")
        elif ec == 31:
            lines.append(f"  [+] Config write requires authorization (CLUSTER_AUTHORIZATION_FAILED)")
        else:
            lines.append(f"  Config write test: {error_name(ec)}")
    except Exception as e:
        lines.append(f"  Config write test error: {e}")
    lines.append("")

    # 7. Summary
    lines.append("[6] Summary")
    total_configs = len(configs)
    lines.append(f"  Total broker configs: {total_configs}")
    lines.append(f"  Sensitive config names exposed: {len(sensitive_names)}")
    lines.append(f"  Dynamic overrides: {len(dynamic_configs)}")

    issues = []
    if not auth_class:
        issues.append("No authorizer (full unauthenticated access)")
    if "PLAINTEXT" in listeners:
        issues.append("PLAINTEXT listener (no encryption)")
    if allow_all and allow_all.lower() == "true":
        issues.append("allow.everyone.if.no.acl.found=true")
    if ec == 0:
        issues.append("Arbitrary dynamic config keys accepted")

    if issues:
        lines.append(f"\n  SECURITY ISSUES ({len(issues)}):")
        for issue in issues:
            lines.append(f"    [!] {issue}")
    else:
        lines.append(f"\n  No critical issues detected.")

    return '\n'.join(lines)


@mcp.tool()
def kafka_raw_request(
    conn_id: str,
    api_key: int,
    api_version: int,
    body_hex: str = "",
) -> str:
    """Send a raw Kafka protocol request (advanced/debug).

    Builds a request with the given API key and version, using the
    body provided as hex bytes. Returns the response as hex.

    Args:
        conn_id: Connection ID from kafka_connect
        api_key: Kafka API key number
        api_version: API version number
        body_hex: Request body as hex string (e.g. "00000001")
    """
    conn = _get_conn(conn_id)
    body = bytes.fromhex(body_hex) if body_hex else b''

    hdr, corr = conn.builder._header_v0(api_key, api_version)
    data = conn.builder._frame(hdr, body)

    resp = conn.send_recv(data)

    api_name = API_NAMES.get(api_key, f"API_{api_key}")
    lines = [
        f"Raw request: {api_name} v{api_version}",
        f"  Sent: {len(data)} bytes",
        f"  Response: {len(resp)} bytes",
        f"  Hex: {resp[:200].hex()}",
    ]
    # Try UTF-8 decode
    try:
        readable = resp.decode('utf-8', errors='replace')
        segments = [s for s in readable.split('\x00') if len(s) > 2 and s.isprintable()]
        if segments:
            lines.append(f"  Strings: {'; '.join(s[:80] for s in segments[:10])}")
    except Exception:
        pass

    return '\n'.join(lines)


# =====================================================================
#  HIGH-LEVEL TOOLS (confluent-kafka powered)
# =====================================================================

try:
    from kafka_mcp.highlevel import (
        HighLevelManager, build_config,
        get_cluster_metadata, describe_broker_configs,
        consume_messages, get_consumer_lag,
        manage_scram_credentials, test_permissions,
    )
    hl_mgr = HighLevelManager()
    atexit.register(hl_mgr.shutdown_all)
    _HL_AVAILABLE = True
except ImportError:
    _HL_AVAILABLE = False
    hl_mgr = None


def _hl_check():
    if not _HL_AVAILABLE:
        raise RuntimeError(
            "High-level tools require confluent-kafka. "
            "Install with: pip install confluent-kafka"
        )


@mcp.tool()
def kafka_hl_connect(
    host: str,
    port: int = 9092,
    name: str = "",
    security_protocol: str = "PLAINTEXT",
    sasl_mechanism: str = "PLAIN",
    username: str = "",
    password: str = "",
    oauth_token: str = "",
    ssl_cafile: str = "",
    ssl_certfile: str = "",
    ssl_keyfile: str = "",
    ssl_keypassword: str = "",
    ssl_no_verify: bool = False,
    client_id: str = "kafka-mcp-hl",
) -> str:
    """Connect using confluent-kafka (high-level client).

    Creates an AdminClient, Producer, and on-demand Consumers using
    the full confluent-kafka library. Use for operational features
    like consumer groups, SCRAM credentials, and proper rebalancing.

    Works alongside the raw protocol tools -- use raw for pen testing,
    high-level for operational testing.

    Args:
        host: Broker hostname or IP
        port: Broker port (default: 9092)
        name: Connection name (auto-generated if empty)
        security_protocol: PLAINTEXT, SASL_PLAINTEXT, SSL, or SASL_SSL
        sasl_mechanism: PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, or OAUTHBEARER
        username: SASL username
        password: SASL password
        oauth_token: OAuth bearer token
        ssl_cafile: CA certificate path
        ssl_certfile: Client certificate path (mTLS)
        ssl_keyfile: Client key path (mTLS)
        ssl_keypassword: Password for encrypted key
        ssl_no_verify: Skip certificate verification
        client_id: Kafka client ID
    """
    _hl_check()
    config = build_config(
        host=host, port=port,
        security_protocol=security_protocol,
        sasl_mechanism=sasl_mechanism,
        username=username or None, password=password or None,
        oauth_token=oauth_token or None,
        ssl_cafile=ssl_cafile or None,
        ssl_certfile=ssl_certfile or None,
        ssl_keyfile=ssl_keyfile or None,
        ssl_keypassword=ssl_keypassword or None,
        ssl_no_verify=ssl_no_verify,
        client_id=client_id,
    )
    conn_id = name or f"hl-{host}:{port}"
    client = hl_mgr.create(conn_id, config)

    # Test connection by fetching metadata
    try:
        md = get_cluster_metadata(client.admin())
        return (
            f"High-level client connected.\n\n"
            f"  Connection ID : {conn_id}\n"
            f"  Bootstrap     : {host}:{port}\n"
            f"  Protocol      : {security_protocol}\n"
            f"  SASL          : {sasl_mechanism if 'SASL' in security_protocol else 'N/A'}\n"
            f"  Brokers       : {len(md['brokers'])}\n"
            f"  Topics        : {md['topic_count']}\n"
            f"  Controller    : {md['controller_id']}\n\n"
            f"Use '{conn_id}' with kafka_hl_* tools."
        )
    except Exception as e:
        hl_mgr.remove(conn_id)
        return f"High-level connection failed: {e}"


@mcp.tool()
def kafka_hl_disconnect(conn_id: str) -> str:
    """Disconnect high-level client.

    Args:
        conn_id: High-level connection ID from kafka_hl_connect
    """
    _hl_check()
    hl_mgr.remove(conn_id)
    return f"High-level client '{conn_id}' disconnected."


@mcp.tool()
def kafka_hl_consume(
    conn_id: str,
    topics: str,
    group_id: str = "kafka-mcp-consumer",
    max_messages: int = 10,
    timeout: float = 10.0,
    auto_offset_reset: str = "earliest",
) -> str:
    """Consume messages from topics using a consumer group.

    Properly handles partition assignment, rebalancing, and offset
    tracking -- features only available with the full Kafka client.

    Args:
        conn_id: High-level connection ID
        topics: Comma-separated topic names to subscribe to
        group_id: Consumer group ID
        max_messages: Maximum messages to consume
        timeout: Maximum time to wait (seconds)
        auto_offset_reset: "earliest" or "latest"
    """
    _hl_check()
    client = hl_mgr.get(conn_id)
    topic_list = [t.strip() for t in topics.split(',') if t.strip()]
    consumer = client.consumer(group_id, auto_offset_reset)

    msgs = consume_messages(consumer, topic_list, max_messages, timeout)
    if not msgs:
        return f"No messages received from {', '.join(topic_list)} within {timeout}s."

    lines = [f"Consumed {len(msgs)} messages from group '{group_id}':\n"]
    for i, m in enumerate(msgs):
        if "error" in m:
            lines.append(f"  [{i}] ERROR: {m['error']}")
        else:
            key_str = m['key'] or '(null)'
            val_preview = (m['value'] or '(null)')[:200]
            lines.append(
                f"  [{i}] {m['topic']}-{m['partition']} @{m['offset']} "
                f"key={key_str} value={val_preview}"
            )
    return '\n'.join(lines)


@mcp.tool()
def kafka_hl_produce(
    conn_id: str,
    topic: str,
    value: str = "",
    key: str = "",
    headers: str = "",
) -> str:
    """Produce a message using confluent-kafka producer.

    Supports delivery confirmation, serialization, and proper
    partitioning logic.

    Args:
        conn_id: High-level connection ID
        topic: Topic name
        value: Message value
        key: Message key (empty = null)
        headers: JSON object of headers, e.g. {"h1":"v1"}
    """
    _hl_check()
    client = hl_mgr.get(conn_id)
    producer = client.producer()

    kwargs = {"topic": topic, "value": value.encode('utf-8')}
    if key:
        kwargs["key"] = key.encode('utf-8')
    if headers:
        try:
            hdr_dict = json.loads(headers)
            kwargs["headers"] = {k: v.encode('utf-8') if isinstance(v, str) else v
                                 for k, v in hdr_dict.items()}
        except json.JSONDecodeError:
            pass

    delivery_result = {"status": "pending"}

    def on_delivery(err, msg):
        if err:
            delivery_result["status"] = f"FAILED: {err}"
        else:
            delivery_result["status"] = "delivered"
            delivery_result["partition"] = msg.partition()
            delivery_result["offset"] = msg.offset()

    producer.produce(callback=on_delivery, **kwargs)
    producer.flush(10)

    if delivery_result["status"] == "delivered":
        return (
            f"Message delivered.\n"
            f"  Topic     : {topic}\n"
            f"  Partition : {delivery_result.get('partition')}\n"
            f"  Offset    : {delivery_result.get('offset')}"
        )
    return f"Produce result: {delivery_result['status']}"


@mcp.tool()
def kafka_hl_scram_credentials(
    conn_id: str,
    operation: str = "describe",
    username: str = "",
    mechanism: str = "SCRAM-SHA-256",
    password: str = "",
    iterations: int = 4096,
) -> str:
    """Manage SCRAM user credentials on the broker.

    Can create, update, delete, and list SCRAM credentials for
    SASL/SCRAM authentication.

    Args:
        conn_id: High-level connection ID
        operation: "describe" (list creds), "upsert" (create/update), or "delete"
        username: Target username (empty = all users for describe)
        mechanism: SCRAM-SHA-256 or SCRAM-SHA-512
        password: New password (for upsert)
        iterations: PBKDF2 iterations (for upsert, default: 4096)
    """
    _hl_check()
    client = hl_mgr.get(conn_id)
    result = manage_scram_credentials(
        client.admin(), operation, username, mechanism, password, iterations
    )
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def kafka_hl_consumer_lag(conn_id: str, group_id: str) -> str:
    """Get consumer lag for a consumer group.

    Shows committed offsets per partition. Useful for monitoring
    consumer health and identifying stalled consumers.

    Args:
        conn_id: High-level connection ID
        group_id: Consumer group ID to check
    """
    _hl_check()
    client = hl_mgr.get(conn_id)
    lag = get_consumer_lag(client.admin(), group_id)

    if not lag:
        return f"No lag information for group '{group_id}'."

    lines = [f"Consumer Lag for '{group_id}':\n"]
    for entry in lag:
        if "error" in entry:
            lines.append(f"  ERROR: {entry['error']}")
        else:
            lines.append(
                f"  {entry['topic']}-{entry['partition']}: "
                f"committed={entry['committed_offset']}"
                + (f" error={entry['error']}" if entry.get('error') else "")
            )
    return '\n'.join(lines)


@mcp.tool()
def kafka_hl_test_permissions(conn_id: str) -> str:
    """Test what operations are permitted with current credentials.

    Attempts: topic create/delete, describe configs, describe ACLs,
    produce, and list consumer groups. Reports ALLOWED/DENIED for each.

    Args:
        conn_id: High-level connection ID
    """
    _hl_check()
    client = hl_mgr.get(conn_id)
    results = test_permissions(client.admin(), client.config)

    lines = ["Permission Test Results:\n"]
    allowed = 0
    for r in results:
        status_marker = "[+]" if r["status"] == "ALLOWED" else "[-]"
        line = f"  {status_marker} {r['test']:<25s} {r['status']}"
        if r.get("error"):
            line += f" ({r['error'][:60]})"
        lines.append(line)
        if r["status"] == "ALLOWED":
            allowed += 1

    lines.append(f"\n  {allowed}/{len(results)} operations permitted.")
    return '\n'.join(lines)


@mcp.tool()
def kafka_hl_list_groups(conn_id: str) -> str:
    """List all consumer groups with state information.

    Uses the confluent-kafka AdminClient for richer group metadata
    than the raw protocol tool.

    Args:
        conn_id: High-level connection ID
    """
    _hl_check()
    client = hl_mgr.get(conn_id)
    try:
        future = client.admin().list_consumer_groups()
        result = future.result()
        groups = result.valid
        errors = result.errors

        if not groups and not errors:
            return "No consumer groups found."

        lines = [f"Consumer Groups ({len(groups)}):\n"]
        for g in groups:
            lines.append(
                f"  {g.group_id:<40s} state={g.state:<15s} "
                f"type={g.type if hasattr(g, 'type') else 'N/A'}"
            )
        if errors:
            lines.append(f"\nErrors ({len(errors)}):")
            for e in errors:
                lines.append(f"  {e}")
        return '\n'.join(lines)
    except Exception as e:
        return f"Error listing groups: {e}"


@mcp.tool()
def kafka_hl_describe_group(conn_id: str, group_id: str) -> str:
    """Get detailed consumer group information including members.

    Args:
        conn_id: High-level connection ID
        group_id: Consumer group ID
    """
    _hl_check()
    client = hl_mgr.get(conn_id)
    try:
        result = client.admin().describe_consumer_groups([group_id])
        lines = []
        for gid, future in result.items():
            group = future.result()
            lines.append(f"Group: {group.group_id}")
            lines.append(f"  State       : {group.state}")
            lines.append(f"  Coordinator : {group.coordinator}")
            if hasattr(group, 'protocol_type'):
                lines.append(f"  Protocol    : {group.protocol_type}")
            members = group.members if hasattr(group, 'members') else []
            lines.append(f"  Members ({len(members)}):")
            for m in members:
                lines.append(
                    f"    {m.member_id[:40]}... "
                    f"client={m.client_id} host={m.host}"
                )
                if hasattr(m, 'assignment') and m.assignment:
                    tps = m.assignment.topic_partitions if hasattr(m.assignment, 'topic_partitions') else []
                    for tp in tps:
                        lines.append(f"      -> {tp.topic}-{tp.partition}")
        return '\n'.join(lines) if lines else f"No details for group '{group_id}'."
    except Exception as e:
        return f"Error describing group '{group_id}': {e}"


@mcp.tool()
def kafka_hl_connections() -> str:
    """List all active high-level (confluent-kafka) connections."""
    if not _HL_AVAILABLE:
        return "High-level tools not available (confluent-kafka not installed)."
    clients = hl_mgr.list_all()
    if not clients:
        return "No active high-level connections. Use kafka_hl_connect to create one."
    lines = ["High-Level Connections:\n"]
    for c in clients:
        lines.append(
            f"  {c['conn_id']}: {c['bootstrap']} [{c['protocol']}] "
            f"admin={'yes' if c['has_admin'] else 'no'} "
            f"producer={'yes' if c['has_producer'] else 'no'} "
            f"consumers={c['consumer_groups']}"
        )
    return '\n'.join(lines)


# =====================================================================
#  ENTRY POINT
# =====================================================================

def main():
    """Start the Kafka-MCP server with stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
