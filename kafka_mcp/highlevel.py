"""
High-Level Kafka Operations via confluent-kafka

Provides operational Kafka capabilities that complement the raw wire
protocol tools: consumer group management, transactional produce,
SCRAM credential management, schema operations, etc.

Uses the confluent-kafka Python library (librdkafka wrapper).
"""

import json
import time
import threading
from typing import Optional, Dict, Any, List, Tuple

from confluent_kafka import (
    Consumer, Producer, KafkaError, KafkaException,
    TopicPartition, OFFSET_BEGINNING, OFFSET_END,
)
from confluent_kafka.admin import (
    AdminClient, ConfigResource, ResourceType, NewTopic, NewPartitions,
    AclBinding, AclBindingFilter, AclOperation, AclPermissionType,
    ResourcePatternType, AlterConfigOpType, OffsetSpec,
    UserScramCredentialUpsertion, UserScramCredentialDeletion,
    ScramMechanism,
    _ConsumerGroupTopicPartitions,
)


# =========================================================================
#  Config Builder
# =========================================================================

def build_config(
    host: str,
    port: int = 9092,
    security_protocol: str = "PLAINTEXT",
    sasl_mechanism: str = "PLAIN",
    username: Optional[str] = None,
    password: Optional[str] = None,
    oauth_token: Optional[str] = None,
    ssl_cafile: Optional[str] = None,
    ssl_certfile: Optional[str] = None,
    ssl_keyfile: Optional[str] = None,
    ssl_keypassword: Optional[str] = None,
    ssl_no_verify: bool = False,
    client_id: str = "kafka-mcp-hl",
    extra_config: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Build a confluent-kafka configuration dict from connection parameters."""
    conf = {
        "bootstrap.servers": f"{host}:{port}",
        "client.id": client_id,
        "security.protocol": security_protocol,
    }

    # SASL
    if security_protocol in ("SASL_PLAINTEXT", "SASL_SSL"):
        conf["sasl.mechanism"] = sasl_mechanism
        if sasl_mechanism in ("PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"):
            if username:
                conf["sasl.username"] = username
            if password:
                conf["sasl.password"] = password
        elif sasl_mechanism == "OAUTHBEARER":
            if oauth_token:
                conf["sasl.oauthbearer.config"] = oauth_token

    # SSL/TLS
    if security_protocol in ("SSL", "SASL_SSL"):
        if ssl_cafile:
            conf["ssl.ca.location"] = ssl_cafile
        if ssl_certfile:
            conf["ssl.certificate.location"] = ssl_certfile
        if ssl_keyfile:
            conf["ssl.key.location"] = ssl_keyfile
        if ssl_keypassword:
            conf["ssl.key.password"] = ssl_keypassword
        if ssl_no_verify:
            conf["enable.ssl.certificate.verification"] = "false"

    if extra_config:
        conf.update(extra_config)

    return conf


# =========================================================================
#  Client Manager
# =========================================================================

class HighLevelClient:
    """Manages confluent-kafka AdminClient, Producer, and Consumer instances."""

    def __init__(self, conn_id: str, config: Dict[str, str]):
        self.conn_id = conn_id
        self.config = config
        self._admin: Optional[AdminClient] = None
        self._producer: Optional[Producer] = None
        self._consumers: Dict[str, Consumer] = {}
        self._lock = threading.Lock()

    def admin(self) -> AdminClient:
        """Get or create AdminClient."""
        if not self._admin:
            self._admin = AdminClient(self.config)
        return self._admin

    def producer(self) -> Producer:
        """Get or create Producer."""
        if not self._producer:
            self._producer = Producer(self.config)
        return self._producer

    def consumer(self, group_id: str, auto_offset_reset: str = "earliest") -> Consumer:
        """Get or create Consumer for a group."""
        key = group_id
        if key not in self._consumers:
            conf = dict(self.config)
            conf["group.id"] = group_id
            conf["auto.offset.reset"] = auto_offset_reset
            conf["enable.auto.commit"] = "false"
            self._consumers[key] = Consumer(conf)
        return self._consumers[key]

    def close(self):
        """Close all clients."""
        if self._producer:
            try:
                self._producer.flush(5)
            except Exception:
                pass
            self._producer = None
        for c in self._consumers.values():
            try:
                c.close()
            except Exception:
                pass
        self._consumers.clear()
        self._admin = None

    def status(self) -> Dict[str, Any]:
        return {
            "conn_id": self.conn_id,
            "bootstrap": self.config.get("bootstrap.servers", ""),
            "protocol": self.config.get("security.protocol", ""),
            "has_admin": self._admin is not None,
            "has_producer": self._producer is not None,
            "consumer_groups": list(self._consumers.keys()),
        }


class HighLevelManager:
    """Manages multiple high-level client instances."""

    def __init__(self):
        self._clients: Dict[str, HighLevelClient] = {}

    def create(self, conn_id: str, config: Dict[str, str]) -> HighLevelClient:
        if conn_id in self._clients:
            self._clients[conn_id].close()
        client = HighLevelClient(conn_id, config)
        self._clients[conn_id] = client
        return client

    def get(self, conn_id: str) -> HighLevelClient:
        client = self._clients.get(conn_id)
        if not client:
            available = list(self._clients.keys())
            raise KeyError(
                f"High-level client '{conn_id}' not found. "
                f"Use kafka_hl_connect first. Available: {available}"
            )
        return client

    def remove(self, conn_id: str):
        client = self._clients.pop(conn_id, None)
        if client:
            client.close()

    def list_all(self) -> list:
        return [c.status() for c in self._clients.values()]

    def shutdown_all(self):
        for c in self._clients.values():
            try:
                c.close()
            except Exception:
                pass
        self._clients.clear()


# =========================================================================
#  Operations
# =========================================================================

def get_cluster_metadata(admin: AdminClient, timeout: float = 10.0) -> Dict[str, Any]:
    """Get full cluster metadata."""
    md = admin.list_topics(timeout=timeout)
    brokers = []
    for bid, broker in md.brokers.items():
        brokers.append({"id": bid, "host": broker.host, "port": broker.port})

    topics = []
    for tname, topic_md in md.topics.items():
        partitions = []
        for pid, part_md in topic_md.partitions.items():
            partitions.append({
                "id": pid,
                "leader": part_md.leader,
                "replicas": list(part_md.replicas),
                "isrs": list(part_md.isrs),
            })
        topics.append({
            "name": tname,
            "partitions": partitions,
            "error": str(topic_md.error) if topic_md.error else None,
        })
    return {
        "brokers": brokers,
        "controller_id": md.controller_id,
        "topics": topics,
        "topic_count": len(topics),
    }


def describe_broker_configs(admin: AdminClient, broker_id: int = 1) -> List[Dict[str, Any]]:
    """Read all broker configs."""
    resource = ConfigResource(ResourceType.BROKER, str(broker_id))
    futures = admin.describe_configs([resource])
    configs = []
    for res, future in futures.items():
        try:
            result = future.result()
            for name, entry in result.items():
                configs.append({
                    "name": name,
                    "value": entry.value,
                    "source": str(entry.source),
                    "is_read_only": entry.is_read_only,
                    "is_sensitive": entry.is_sensitive,
                    "is_synonym": entry.is_synonym,
                })
        except Exception as e:
            configs.append({"error": str(e)})
    return configs


def consume_messages(consumer: Consumer, topics: List[str],
                     max_messages: int = 10, timeout: float = 10.0) -> List[Dict[str, Any]]:
    """Subscribe and consume messages."""
    consumer.subscribe(topics)
    messages = []
    deadline = time.time() + timeout
    while len(messages) < max_messages and time.time() < deadline:
        msg = consumer.poll(min(1.0, deadline - time.time()))
        if msg is None:
            continue
        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                continue
            messages.append({"error": str(msg.error())})
            continue
        # Decode key/value
        key = None
        if msg.key():
            try:
                key = msg.key().decode('utf-8')
            except (UnicodeDecodeError, AttributeError):
                key = repr(msg.key())
        value = None
        if msg.value():
            try:
                value = msg.value().decode('utf-8')
            except (UnicodeDecodeError, AttributeError):
                value = repr(msg.value())
        messages.append({
            "topic": msg.topic(),
            "partition": msg.partition(),
            "offset": msg.offset(),
            "key": key,
            "value": value,
            "timestamp": msg.timestamp(),
            "headers": dict(msg.headers()) if msg.headers() else None,
        })
    return messages


def get_consumer_lag(admin: AdminClient, group_id: str) -> List[Dict[str, Any]]:
    """Get consumer lag for a group."""
    try:
        req = _ConsumerGroupTopicPartitions(group_id)
        offsets_future = admin.list_consumer_group_offsets([req])
        lag_info = []
        for group, future in offsets_future.items():
            result = future.result()
            for tp in result.topic_partitions:
                lag_info.append({
                    "topic": tp.topic,
                    "partition": tp.partition,
                    "committed_offset": tp.offset,
                    "error": str(tp.error) if tp.error else None,
                })
        return lag_info
    except Exception as e:
        return [{"error": str(e)}]


def manage_scram_credentials(
    admin: AdminClient,
    operation: str,  # "upsert", "delete", "describe"
    username: str = "",
    mechanism: str = "SCRAM-SHA-256",
    password: str = "",
    iterations: int = 4096,
) -> Dict[str, Any]:
    """Manage SCRAM credentials."""
    mech_map = {
        "SCRAM-SHA-256": ScramMechanism.SCRAM_SHA_256,
        "SCRAM-SHA-512": ScramMechanism.SCRAM_SHA_512,
    }
    scram_mech = mech_map.get(mechanism, ScramMechanism.SCRAM_SHA_256)

    if operation == "describe":
        try:
            future = admin.describe_user_scram_credentials(
                [username] if username else None
            )
            # Returns a Future whose result() is a dict of {username: UserScramCredentialsDescription}
            user_map = future.result()
            results = {}
            for user, desc in user_map.items():
                try:
                    creds = desc.scram_credential_infos if hasattr(desc, 'scram_credential_infos') else desc
                    if hasattr(creds, '__iter__'):
                        results[user] = [
                            {"mechanism": str(c.mechanism), "iterations": c.iterations}
                            for c in creds
                        ]
                    else:
                        results[user] = str(creds)
                except Exception as e:
                    results[user] = {"error": str(e)}
            return {"operation": "describe", "users": results}
        except Exception as e:
            return {"operation": "describe", "error": str(e)}

    elif operation == "upsert":
        if not username or not password:
            return {"error": "upsert requires username and password"}
        try:
            upsertion = UserScramCredentialUpsertion(
                username, scram_mech, iterations, password.encode('utf-8')
            )
            futures = admin.alter_user_scram_credentials([upsertion])
            for user, future in futures.items():
                future.result()
            return {"operation": "upsert", "username": username,
                    "mechanism": mechanism, "status": "success"}
        except Exception as e:
            return {"operation": "upsert", "error": str(e)}

    elif operation == "delete":
        if not username:
            return {"error": "delete requires username"}
        try:
            deletion = UserScramCredentialDeletion(username, scram_mech)
            futures = admin.alter_user_scram_credentials([deletion])
            for user, future in futures.items():
                future.result()
            return {"operation": "delete", "username": username,
                    "mechanism": mechanism, "status": "success"}
        except Exception as e:
            return {"operation": "delete", "error": str(e)}

    return {"error": f"Unknown operation: {operation}"}


def test_permissions(admin: AdminClient, config: Dict[str, str]) -> List[Dict[str, str]]:
    """Test what operations are permitted."""
    results = []
    test_topic = f"mcp-perm-test-{int(time.time())}"

    # 1. Topic creation
    try:
        fs = admin.create_topics([NewTopic(test_topic, 1, 1)])
        for t, f in fs.items():
            f.result()
        results.append({"test": "create_topic", "status": "ALLOWED"})
    except Exception as e:
        results.append({"test": "create_topic", "status": "DENIED", "error": str(e)[:100]})

    # 2. Topic deletion
    try:
        fs = admin.delete_topics([test_topic])
        for t, f in fs.items():
            f.result()
        results.append({"test": "delete_topic", "status": "ALLOWED"})
    except Exception as e:
        results.append({"test": "delete_topic", "status": "DENIED", "error": str(e)[:100]})

    # 3. Describe configs
    try:
        resource = ConfigResource(ResourceType.BROKER, "1")
        fs = admin.describe_configs([resource])
        for r, f in fs.items():
            f.result()
        results.append({"test": "describe_configs", "status": "ALLOWED"})
    except Exception as e:
        results.append({"test": "describe_configs", "status": "DENIED", "error": str(e)[:100]})

    # 4. Describe ACLs
    try:
        filt = AclBindingFilter(
            ResourceType.ANY, None, ResourcePatternType.ANY, None,
            None, AclOperation.ANY, AclPermissionType.ANY
        )
        result = admin.describe_acls(filt)
        if hasattr(result, 'result'):
            result.result()
        results.append({"test": "describe_acls", "status": "ALLOWED"})
    except Exception as e:
        results.append({"test": "describe_acls", "status": "DENIED", "error": str(e)[:100]})

    # 5. Produce
    try:
        producer = Producer(config)
        producer.produce(test_topic, value=b"test")
        producer.flush(5)
        results.append({"test": "produce", "status": "ALLOWED"})
    except Exception as e:
        results.append({"test": "produce", "status": "DENIED", "error": str(e)[:100]})

    # 6. List consumer groups
    try:
        admin.list_consumer_groups()
        results.append({"test": "list_groups", "status": "ALLOWED"})
    except Exception as e:
        results.append({"test": "list_groups", "status": "DENIED", "error": str(e)[:100]})

    # Cleanup
    try:
        admin.delete_topics([test_topic])
    except Exception:
        pass

    return results
