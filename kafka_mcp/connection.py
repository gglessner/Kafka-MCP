"""
Kafka Connection Manager

Manages persistent TCP connections to Kafka brokers with full support for
all Kafka security protocols and SASL mechanisms:

  Security Protocols:
    - PLAINTEXT          (no auth, no encryption)
    - SSL                (TLS encryption, optional mTLS client certs)
    - SASL_PLAINTEXT     (SASL auth over plaintext)
    - SASL_SSL           (SASL auth over TLS)

  SASL Mechanisms:
    - PLAIN              (username/password)
    - SCRAM-SHA-256      (challenge-response, SHA-256)
    - SCRAM-SHA-512      (challenge-response, SHA-512)
    - OAUTHBEARER        (OAuth 2.0 bearer token)

  SSL/TLS Options:
    - CA certificate(s) for server verification
    - Client certificate + key for mutual TLS (mTLS)
    - Password-protected private keys
    - Hostname verification toggle
    - CRL (Certificate Revocation List) support
    - Custom cipher suites
    - TLS version pinning
"""

import base64
import hashlib
import hmac
import os
import secrets
import socket
import ssl
import struct
import threading
import time
from typing import Optional, Dict, Tuple, Any, List

from kafka_mcp.protocol import RequestBuilder, ResponseParser


# =========================================================================
#  SCRAM Authentication (SHA-256 / SHA-512)
# =========================================================================

class ScramClient:
    """SCRAM-SHA-256 / SCRAM-SHA-512 SASL client.

    Implements RFC 5802 (SCRAM) as used by Kafka:
      1. client-first-message: n,,n=<user>,r=<client_nonce>
      2. server-first-message: r=<combined_nonce>,s=<salt>,i=<iterations>
      3. client-final-message: c=biws,r=<combined_nonce>,p=<proof>
      4. server-final-message: v=<server_signature>
    """

    def __init__(self, username: str, password: str, mechanism: str = "SCRAM-SHA-256"):
        self.username = username
        self.password = password
        if mechanism == "SCRAM-SHA-256":
            self._hash_name = "sha256"
            self._hash_func = hashlib.sha256
            self._digest_size = 32
        elif mechanism == "SCRAM-SHA-512":
            self._hash_name = "sha512"
            self._hash_func = hashlib.sha512
            self._digest_size = 64
        else:
            raise ValueError(f"Unsupported SCRAM mechanism: {mechanism}")

        self._client_nonce = base64.b64encode(secrets.token_bytes(24)).decode('ascii')
        self._client_first_bare = f"n={self._saslprep(username)},r={self._client_nonce}"
        self._server_first: Optional[str] = None
        self._auth_message: Optional[str] = None
        self._salted_password: Optional[bytes] = None

    @staticmethod
    def _saslprep(s: str) -> str:
        """Minimal SASLprep: escape '=' as '=3D' and ',' as '=2C'."""
        return s.replace('=', '=3D').replace(',', '=2C')

    def client_first_message(self) -> bytes:
        """Generate the client-first-message."""
        # gs2-header is "n,," (no channel binding, no authzid)
        msg = f"n,,{self._client_first_bare}"
        return msg.encode('utf-8')

    def process_server_first(self, server_first_bytes: bytes) -> bytes:
        """Process server-first-message and generate client-final-message."""
        self._server_first = server_first_bytes.decode('utf-8')
        parts = {}
        for part in self._server_first.split(','):
            if '=' in part:
                k = part[0]
                v = part[2:]
                parts[k] = v

        server_nonce = parts.get('r', '')
        salt_b64 = parts.get('s', '')
        iterations = int(parts.get('i', '4096'))

        # Verify server nonce starts with our client nonce
        if not server_nonce.startswith(self._client_nonce):
            raise ValueError("Server nonce does not start with client nonce")

        salt = base64.b64decode(salt_b64)

        # SaltedPassword = Hi(password, salt, iterations) using PBKDF2
        self._salted_password = hashlib.pbkdf2_hmac(
            self._hash_name,
            self.password.encode('utf-8'),
            salt,
            iterations,
            dklen=self._digest_size,
        )

        # ClientKey = HMAC(SaltedPassword, "Client Key")
        client_key = hmac.new(self._salted_password, b"Client Key", self._hash_func).digest()

        # StoredKey = Hash(ClientKey)
        stored_key = self._hash_func(client_key).digest()

        # client-final-without-proof
        channel_binding = base64.b64encode(b"n,,").decode('ascii')  # "biws"
        client_final_without_proof = f"c={channel_binding},r={server_nonce}"

        # AuthMessage = client-first-bare + "," + server-first + "," + client-final-without-proof
        self._auth_message = f"{self._client_first_bare},{self._server_first},{client_final_without_proof}"

        # ClientSignature = HMAC(StoredKey, AuthMessage)
        client_signature = hmac.new(
            stored_key, self._auth_message.encode('utf-8'), self._hash_func
        ).digest()

        # ClientProof = ClientKey XOR ClientSignature
        client_proof = bytes(a ^ b for a, b in zip(client_key, client_signature))
        proof_b64 = base64.b64encode(client_proof).decode('ascii')

        # client-final-message
        client_final = f"{client_final_without_proof},p={proof_b64}"
        return client_final.encode('utf-8')

    def verify_server_final(self, server_final_bytes: bytes) -> bool:
        """Verify the server-final-message (optional but recommended)."""
        server_final = server_final_bytes.decode('utf-8')
        parts = {}
        for part in server_final.split(','):
            if '=' in part:
                k = part[0]
                v = part[2:]
                parts[k] = v

        verifier_b64 = parts.get('v', '')
        if not verifier_b64 or not self._salted_password or not self._auth_message:
            return False

        # ServerKey = HMAC(SaltedPassword, "Server Key")
        server_key = hmac.new(self._salted_password, b"Server Key", self._hash_func).digest()

        # ServerSignature = HMAC(ServerKey, AuthMessage)
        expected_sig = hmac.new(
            server_key, self._auth_message.encode('utf-8'), self._hash_func
        ).digest()
        expected_b64 = base64.b64encode(expected_sig).decode('ascii')

        return hmac.compare_digest(verifier_b64, expected_b64)


# =========================================================================
#  OAUTHBEARER Token Building
# =========================================================================

def _build_oauthbearer_client_initial(token: str, principal: str = "") -> bytes:
    """Build the OAUTHBEARER initial client response per RFC 7628.

    Format: "n,,\x01auth=Bearer <token>\x01\x01"
    """
    extensions = ""
    if principal:
        extensions = f"authzid={principal}"
    # gs2-header + kvpairs + final \x01
    msg = f"n,,\x01auth=Bearer {token}\x01{extensions}\x01"
    return msg.encode('utf-8')


# =========================================================================
#  Kafka Connection
# =========================================================================

class KafkaConnection:
    """A single managed connection to a Kafka broker.

    Supports all Kafka security protocol and SASL mechanism combinations.
    """

    VALID_PROTOCOLS = {"PLAINTEXT", "SSL", "SASL_PLAINTEXT", "SASL_SSL"}
    VALID_MECHANISMS = {"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512", "OAUTHBEARER"}

    def __init__(self, conn_id: str, host: str, port: int,
                 security_protocol: str = "PLAINTEXT",
                 sasl_mechanism: str = "PLAIN",
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 oauth_token: Optional[str] = None,
                 oauth_principal: Optional[str] = None,
                 ssl_cafile: Optional[str] = None,
                 ssl_capath: Optional[str] = None,
                 ssl_certfile: Optional[str] = None,
                 ssl_keyfile: Optional[str] = None,
                 ssl_keypassword: Optional[str] = None,
                 ssl_crlfile: Optional[str] = None,
                 ssl_ciphers: Optional[str] = None,
                 ssl_no_verify: bool = False,
                 ssl_check_hostname: bool = True,
                 tls_version: Optional[str] = None,
                 client_id: str = "kafka-mcp"):
        self.conn_id = conn_id
        self.host = host
        self.port = port
        self.security_protocol = security_protocol.upper()
        self.sasl_mechanism = sasl_mechanism.upper()
        self.username = username
        self.password = password
        self.oauth_token = oauth_token
        self.oauth_principal = oauth_principal
        self.ssl_cafile = ssl_cafile
        self.ssl_capath = ssl_capath
        self.ssl_certfile = ssl_certfile
        self.ssl_keyfile = ssl_keyfile
        self.ssl_keypassword = ssl_keypassword
        self.ssl_crlfile = ssl_crlfile
        self.ssl_ciphers = ssl_ciphers
        self.ssl_no_verify = ssl_no_verify
        self.ssl_check_hostname = ssl_check_hostname
        self.tls_version = tls_version
        self.client_id = client_id

        # Validate
        if self.security_protocol not in self.VALID_PROTOCOLS:
            raise ValueError(
                f"Invalid security_protocol '{security_protocol}'. "
                f"Must be one of: {', '.join(sorted(self.VALID_PROTOCOLS))}"
            )
        if self.security_protocol.startswith("SASL"):
            if self.sasl_mechanism not in self.VALID_MECHANISMS:
                raise ValueError(
                    f"Invalid sasl_mechanism '{sasl_mechanism}'. "
                    f"Must be one of: {', '.join(sorted(self.VALID_MECHANISMS))}"
                )

        self.builder = RequestBuilder(client_id)
        self.parser = ResponseParser()

        self._sock: Optional[socket.socket] = None
        self._lock = threading.RLock()
        self._connected = False
        self._authenticated = False
        self._auth_mechanism_used: Optional[str] = None
        self._connect_time: Optional[float] = None
        self._api_versions: Optional[Dict] = None
        self._request_count = 0
        self._tls_version_used: Optional[str] = None
        self._tls_cipher_used: Optional[str] = None
        self._server_cert_subject: Optional[str] = None

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def authenticated(self) -> bool:
        return self._authenticated

    def connect(self, timeout: float = 10.0) -> Dict[str, Any]:
        """Establish connection, TLS handshake, and SASL authentication."""
        with self._lock:
            if self._connected:
                return {"status": "already_connected", "host": self.host, "port": self.port}

            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)

            try:
                raw_sock.connect((self.host, self.port))
            except Exception as e:
                raw_sock.close()
                raise ConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}")

            # ---- TLS Handshake ----
            if self.security_protocol in ("SSL", "SASL_SSL"):
                self._sock = self._wrap_tls(raw_sock)
            else:
                self._sock = raw_sock

            self._connected = True
            self._connect_time = time.time()

            result = {
                "status": "connected",
                "host": self.host,
                "port": self.port,
                "protocol": self.security_protocol,
            }

            # Report TLS details
            if self._tls_version_used:
                result["tls_version"] = self._tls_version_used
            if self._tls_cipher_used:
                result["tls_cipher"] = self._tls_cipher_used
            if self._server_cert_subject:
                result["server_cert_subject"] = self._server_cert_subject

            # ---- API Versions ----
            try:
                api_resp = self._do_api_versions()
                self._api_versions = api_resp.get("apis", {})
                result["api_count"] = len(self._api_versions)
            except Exception as e:
                result["api_versions_error"] = str(e)

            # ---- SASL Authentication ----
            if self.security_protocol in ("SASL_PLAINTEXT", "SASL_SSL"):
                auth_result = self._do_sasl_auth()
                self._authenticated = auth_result.get("error_code", -1) == 0
                result["authenticated"] = self._authenticated
                result["sasl_mechanism"] = self.sasl_mechanism
                if not self._authenticated:
                    result["auth_error"] = auth_result.get("error_message", "unknown")
                    self.disconnect()
                    raise ConnectionError(
                        f"SASL/{self.sasl_mechanism} authentication failed: "
                        f"{auth_result.get('error_message')}"
                    )
            else:
                # PLAINTEXT and SSL (with mTLS) are implicitly authenticated
                self._authenticated = True
                result["authenticated"] = True
                if self.security_protocol == "SSL" and self.ssl_certfile:
                    result["auth_method"] = "mTLS_client_cert"

            return result

    def _wrap_tls(self, raw_sock: socket.socket) -> ssl.SSLSocket:
        """Configure and perform TLS handshake with full option support."""
        # Choose TLS protocol version
        if self.tls_version:
            version_map = {
                "TLSv1.2": ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else ssl.PROTOCOL_TLS,
                "TLSv1.3": ssl.PROTOCOL_TLS,  # TLS 1.3 is negotiated via PROTOCOL_TLS
            }
            proto = version_map.get(self.tls_version, ssl.PROTOCOL_TLS)
        else:
            proto = ssl.PROTOCOL_TLS_CLIENT

        ctx = ssl.SSLContext(proto)

        # --- Verification & Hostname ---
        if self.ssl_no_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.check_hostname = self.ssl_check_hostname
            ctx.verify_mode = ssl.CERT_REQUIRED
            # Load CA certificates
            if self.ssl_cafile or self.ssl_capath:
                ctx.load_verify_locations(
                    cafile=self.ssl_cafile,
                    capath=self.ssl_capath,
                )
            else:
                ctx.load_default_certs()

        # --- CRL (Certificate Revocation List) ---
        if self.ssl_crlfile:
            ctx.load_verify_locations(cafile=self.ssl_crlfile)
            ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF

        # --- Client Certificate (mTLS) ---
        if self.ssl_certfile:
            ctx.load_cert_chain(
                certfile=self.ssl_certfile,
                keyfile=self.ssl_keyfile,
                password=self.ssl_keypassword,
            )

        # --- Cipher Suites ---
        if self.ssl_ciphers:
            ctx.set_ciphers(self.ssl_ciphers)

        # --- TLS Version Constraints ---
        if self.tls_version == "TLSv1.2":
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        elif self.tls_version == "TLSv1.3":
            if hasattr(ssl.TLSVersion, 'TLSv1_3'):
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3

        # --- Handshake ---
        server_hostname = self.host if ctx.check_hostname else None
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=server_hostname)

        # Capture TLS session details
        self._tls_version_used = tls_sock.version()
        cipher_info = tls_sock.cipher()
        if cipher_info:
            self._tls_cipher_used = f"{cipher_info[0]} ({cipher_info[1]}, {cipher_info[2]} bits)"

        # Capture server certificate subject
        cert = tls_sock.getpeercert()
        if cert:
            subject = dict(x[0] for x in cert.get('subject', ()))
            self._server_cert_subject = subject.get('commonName', str(subject))

        return tls_sock

    def disconnect(self) -> Dict[str, Any]:
        """Close the connection."""
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None
            was_connected = self._connected
            self._connected = False
            self._authenticated = False
            uptime = time.time() - self._connect_time if self._connect_time else 0
            return {
                "status": "disconnected" if was_connected else "was_not_connected",
                "requests_sent": self._request_count,
                "uptime_seconds": round(uptime, 1),
            }

    def send_recv(self, data: bytes, timeout: float = 30.0) -> bytes:
        """Send a framed request and receive the response payload."""
        with self._lock:
            if not self._connected or not self._sock:
                raise ConnectionError("Not connected")
            self._sock.settimeout(timeout)
            self._sock.sendall(data)
            self._request_count += 1

            # Read 4-byte length
            buf = b''
            while len(buf) < 4:
                chunk = self._sock.recv(4 - len(buf))
                if not chunk:
                    self._connected = False
                    raise ConnectionError("Connection closed reading length")
                buf += chunk
            length = struct.unpack('>i', buf)[0]

            # Read response body
            body = b''
            while len(body) < length:
                chunk = self._sock.recv(min(length - len(body), 65536))
                if not chunk:
                    self._connected = False
                    raise ConnectionError("Connection closed reading body")
                body += chunk

            # Skip correlation_id (first 4 bytes)
            return body[4:]

    def status(self) -> Dict[str, Any]:
        """Get connection status."""
        info = {
            "conn_id": self.conn_id,
            "host": self.host,
            "port": self.port,
            "protocol": self.security_protocol,
            "connected": self._connected,
            "authenticated": self._authenticated,
            "requests_sent": self._request_count,
            "uptime_seconds": round(time.time() - self._connect_time, 1) if self._connect_time and self._connected else 0,
            "api_versions_count": len(self._api_versions) if self._api_versions else 0,
        }
        if self.security_protocol.startswith("SASL"):
            info["sasl_mechanism"] = self.sasl_mechanism
        if self._tls_version_used:
            info["tls_version"] = self._tls_version_used
        if self._tls_cipher_used:
            info["tls_cipher"] = self._tls_cipher_used
        if self._auth_mechanism_used:
            info["auth_mechanism"] = self._auth_mechanism_used
        if self.ssl_certfile:
            info["client_cert"] = os.path.basename(self.ssl_certfile)
        return info

    # =====================================================================
    #  SASL Authentication
    # =====================================================================

    def _do_api_versions(self) -> Dict:
        req, _ = self.builder.api_versions()
        resp = self.send_recv(req)
        return self.parser.parse_api_versions(resp)

    def _do_sasl_auth(self) -> Dict:
        """Perform SASL authentication using the configured mechanism."""
        mechanism = self.sasl_mechanism

        # Step 1: SaslHandshake - tell broker which mechanism we want
        req, _ = self.builder.sasl_handshake(mechanism)
        resp = self.send_recv(req)
        hs = self.parser.parse_sasl_handshake(resp)
        if hs["error_code"] != 0:
            return {
                "error_code": hs["error_code"],
                "error_message": (
                    f"SaslHandshake failed: {hs['error']}. "
                    f"Broker supports: {', '.join(hs.get('mechanisms', []))}"
                ),
            }

        # Check mechanism is in broker's supported list
        supported = hs.get("mechanisms", [])
        if mechanism not in supported:
            return {
                "error_code": -1,
                "error_message": (
                    f"Mechanism '{mechanism}' not supported by broker. "
                    f"Supported: {', '.join(supported)}"
                ),
            }

        # Step 2: Dispatch to mechanism-specific handler
        self._auth_mechanism_used = mechanism
        if mechanism == "PLAIN":
            return self._do_sasl_plain()
        elif mechanism in ("SCRAM-SHA-256", "SCRAM-SHA-512"):
            return self._do_sasl_scram(mechanism)
        elif mechanism == "OAUTHBEARER":
            return self._do_sasl_oauthbearer()
        else:
            return {"error_code": -1, "error_message": f"Unsupported mechanism: {mechanism}"}

    def _do_sasl_plain(self) -> Dict:
        """SASL/PLAIN: single-step username/password auth."""
        if not self.username or not self.password:
            return {"error_code": -1, "error_message": "PLAIN requires username and password"}
        req, _ = self.builder.sasl_authenticate(self.username, self.password)
        resp = self.send_recv(req)
        return self.parser.parse_sasl_authenticate(resp)

    def _do_sasl_scram(self, mechanism: str) -> Dict:
        """SASL/SCRAM-SHA-256 or SCRAM-SHA-512: multi-step challenge-response."""
        if not self.username or not self.password:
            return {"error_code": -1, "error_message": f"{mechanism} requires username and password"}

        scram = ScramClient(self.username, self.password, mechanism)

        # Step 1: Send client-first-message
        client_first = scram.client_first_message()
        req, _ = self.builder.sasl_authenticate_raw(client_first)
        resp = self.send_recv(req)
        result1 = self.parser.parse_sasl_authenticate(resp)
        if result1["error_code"] != 0:
            return result1

        # Step 2: Process server-first-message, send client-final-message
        server_first = result1.get("auth_bytes", "")
        if isinstance(server_first, str):
            server_first = server_first.encode('utf-8')
        try:
            client_final = scram.process_server_first(server_first)
        except Exception as e:
            return {"error_code": -1, "error_message": f"SCRAM client-final error: {e}"}

        req, _ = self.builder.sasl_authenticate_raw(client_final)
        resp = self.send_recv(req)
        result2 = self.parser.parse_sasl_authenticate(resp)
        if result2["error_code"] != 0:
            return result2

        # Step 3: Verify server-final-message (optional but good practice)
        server_final = result2.get("auth_bytes", "")
        if isinstance(server_final, str):
            server_final = server_final.encode('utf-8')
        if server_final:
            if not scram.verify_server_final(server_final):
                return {"error_code": -1, "error_message": "SCRAM server signature verification failed"}

        return result2

    def _do_sasl_oauthbearer(self) -> Dict:
        """SASL/OAUTHBEARER: OAuth 2.0 bearer token auth."""
        if not self.oauth_token:
            return {"error_code": -1, "error_message": "OAUTHBEARER requires oauth_token"}

        token_msg = _build_oauthbearer_client_initial(
            self.oauth_token, self.oauth_principal or ""
        )
        req, _ = self.builder.sasl_authenticate_raw(token_msg)
        resp = self.send_recv(req)
        result = self.parser.parse_sasl_authenticate(resp)

        # OAUTHBEARER may return an error with a JSON body for token refresh
        if result["error_code"] != 0:
            auth_bytes = result.get("auth_bytes", "")
            if auth_bytes:
                result["error_message"] = (
                    f"{result.get('error_message', '')} | "
                    f"Server response: {auth_bytes[:500]}"
                )
        return result


# =========================================================================
#  Connection Manager
# =========================================================================

class ConnectionManager:
    """Manages multiple named Kafka connections."""

    def __init__(self):
        self._connections: Dict[str, KafkaConnection] = {}
        self._counter = 0
        self._lock = threading.RLock()

    def create(self, host: str, port: int = 9092,
               name: str = "",
               security_protocol: str = "PLAINTEXT",
               sasl_mechanism: str = "PLAIN",
               username: Optional[str] = None,
               password: Optional[str] = None,
               oauth_token: Optional[str] = None,
               oauth_principal: Optional[str] = None,
               ssl_cafile: Optional[str] = None,
               ssl_capath: Optional[str] = None,
               ssl_certfile: Optional[str] = None,
               ssl_keyfile: Optional[str] = None,
               ssl_keypassword: Optional[str] = None,
               ssl_crlfile: Optional[str] = None,
               ssl_ciphers: Optional[str] = None,
               ssl_no_verify: bool = False,
               ssl_check_hostname: bool = True,
               tls_version: Optional[str] = None,
               client_id: str = "kafka-mcp") -> Tuple[str, KafkaConnection]:
        """Create a new connection (does not connect yet)."""
        with self._lock:
            self._counter += 1
            conn_id = name or f"conn-{self._counter}"
            if conn_id in self._connections:
                try:
                    self._connections[conn_id].disconnect()
                except Exception:
                    pass

            conn = KafkaConnection(
                conn_id=conn_id, host=host, port=port,
                security_protocol=security_protocol,
                sasl_mechanism=sasl_mechanism,
                username=username, password=password,
                oauth_token=oauth_token, oauth_principal=oauth_principal,
                ssl_cafile=ssl_cafile, ssl_capath=ssl_capath,
                ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile,
                ssl_keypassword=ssl_keypassword, ssl_crlfile=ssl_crlfile,
                ssl_ciphers=ssl_ciphers, ssl_no_verify=ssl_no_verify,
                ssl_check_hostname=ssl_check_hostname,
                tls_version=tls_version, client_id=client_id,
            )
            self._connections[conn_id] = conn
            return conn_id, conn

    def get(self, conn_id: str) -> KafkaConnection:
        """Get a connection by ID."""
        conn = self._connections.get(conn_id)
        if not conn:
            available = list(self._connections.keys())
            raise KeyError(
                f"Connection '{conn_id}' not found. "
                f"Available: {available if available else '(none - use kafka_connect first)'}"
            )
        return conn

    def remove(self, conn_id: str) -> Dict[str, Any]:
        """Disconnect and remove a connection."""
        conn = self._connections.pop(conn_id, None)
        if conn:
            return conn.disconnect()
        return {"status": "not_found"}

    def list_all(self) -> list:
        """List all connections with status."""
        return [conn.status() for conn in self._connections.values()]

    def shutdown_all(self):
        """Disconnect all connections."""
        for conn in self._connections.values():
            try:
                conn.disconnect()
            except Exception:
                pass
        self._connections.clear()
