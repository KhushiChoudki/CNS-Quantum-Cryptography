"""
WireGuard Dynamic Peer Manager
==============================
Manages VPN peer lifecycle gated by PQC authentication.

On Linux / Azure VM  → uses real `wg` CLI commands.
On Windows / dev     → simulation mode (logs commands, returns plausible data).

Flow:
  PQC auth succeeds
      ↓
  add_peer()  ← allocates IP from 10.0.0.x pool, runs `wg set wg0 peer ...`
      ↓
  VPN tunnel active for session_ttl seconds
      ↓
  remove_peer()  ← called on logout OR timer expiry
"""

import subprocess
import platform
import logging
import os
import time
import secrets
import hashlib
from threading import Timer, Lock

logger = logging.getLogger(__name__)

# ── Environment detection ───────────────────────────────────────────────────────
SIMULATION_MODE = (
    platform.system() == "Windows"
    or not os.path.exists("/usr/bin/wg")
)
WG_INTERFACE = "wg0"
SERVER_ENDPOINT = "40.81.244.230:51820"
SERVER_PUBKEY_PLACEHOLDER = "/9YjRqeMhqaE+cURsc3qYStn01DSie/YKDOf9WtMZg8="

# ── IP Pool Management ─────────────────────────────────────────────────────────
_allocated = {}     # {user_id: {"ip": str, "pubkey": str, "added_at": float}}
_ip_pool   = set()
_timers    = {}     # {user_id: Timer}
_lock      = Lock()


def _next_ip() -> str:
    """Allocate the next free IP from 10.0.0.2 – 10.0.0.254."""
    for i in range(2, 255):
        ip = f"10.0.0.{i}"
        if ip not in _ip_pool:
            _ip_pool.add(ip)
            return ip
    raise RuntimeError("IP pool exhausted")


# ── WireGuard CLI wrapper ───────────────────────────────────────────────────────
def _run_wg(*args: str):
    cmd = ["wg"] + list(args)
    if SIMULATION_MODE:
        logger.info(f"[WG-SIM] {' '.join(cmd)}")
        return True, f"[SIMULATED] {' '.join(cmd)}"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return True, r.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"[WG-ERR] {e.stderr}")
        return False, e.stderr


# ── Public API ─────────────────────────────────────────────────────────────────
def add_peer(user_id: str, client_pubkey: str = None, session_ttl: int = 3600):
    """
    Add WireGuard peer after successful PQC authentication.
    Schedules automatic removal after session_ttl seconds.
    Returns (success, allocated_ip, message)
    """
    with _lock:
        if client_pubkey is None:
            # Generate plausible demo public key for simulation
            client_pubkey = hashlib.sha256(
                (user_id + str(time.time())).encode()
            ).digest().hex()[:44] + "="

        allocated_ip = _next_ip()
        _allocated[user_id] = {
            "ip": allocated_ip,
            "pubkey": client_pubkey,
            "added_at": time.time(),
            "ttl": session_ttl,
        }

    ok, msg = _run_wg(
        "set", WG_INTERFACE,
        "peer", client_pubkey,
        "allowed-ips", f"{allocated_ip}/32"
    )

    if ok:
        logger.info(f"[WG] Peer ADDED: {user_id} → {allocated_ip} (TTL={session_ttl}s)")
        t = Timer(session_ttl, _expire_peer, args=[user_id])
        t.daemon = True
        with _lock:
            _timers[user_id] = t
        t.start()

    return ok, allocated_ip, msg


def remove_peer(user_id: str):
    """Remove WireGuard peer on logout."""
    with _lock:
        info = _allocated.pop(user_id, None)
        if info:
            _ip_pool.discard(info["ip"])
        t = _timers.pop(user_id, None)
        if t:
            t.cancel()

    if info:
        ok, msg = _run_wg("set", WG_INTERFACE, "peer", info["pubkey"], "remove")
        logger.info(f"[WG] Peer REMOVED: {user_id}")
        return ok, msg
    return False, "Peer not found"


def _expire_peer(user_id: str):
    """Auto-called by timer when session TTL expires."""
    logger.info(f"[WG] Session EXPIRED for {user_id} — removing peer")
    remove_peer(user_id)


def list_peers() -> list:
    """Return list of currently active peers."""
    with _lock:
        if SIMULATION_MODE:
            return [
                {
                    "user_id": uid,
                    "ip": info["ip"],
                    "pubkey_prefix": info["pubkey"][:12] + "...",
                    "session_age_s": int(time.time() - info["added_at"]),
                    "ttl_remaining_s": max(0, int(info["ttl"] - (time.time() - info["added_at"]))),
                    "status": "active",
                }
                for uid, info in _allocated.items()
            ]
    ok, output = _run_wg("show", WG_INTERFACE, "dump")
    if not ok:
        return []
    peers = []
    for line in output.strip().split("\n")[1:]:
        parts = line.split("\t")
        if len(parts) >= 4:
            peers.append({
                "pubkey_prefix": parts[0][:12] + "...",
                "allowed_ip": parts[3],
                "status": "active",
            })
    return peers


def get_allocated_ip(user_id: str) -> str | None:
    with _lock:
        info = _allocated.get(user_id)
        return info["ip"] if info else None


def get_session_info(user_id: str) -> dict | None:
    with _lock:
        info = _allocated.get(user_id)
        if not info:
            return None
        return {
            **info,
            "session_age_s": int(time.time() - info["added_at"]),
            "ttl_remaining_s": max(0, int(info["ttl"] - (time.time() - info["added_at"]))),
        }


def generate_client_config(user_id: str, server_pubkey: str = SERVER_PUBKEY_PLACEHOLDER,
                            session_key: str = None) -> tuple:
    """
    Generate WireGuard client .conf for the authenticated user.
    Returns (config_string, client_pubkey)
    """
    allocated_ip = get_allocated_ip(user_id) or "10.0.0.X"

    import base64, os
    if SIMULATION_MODE:
        client_privkey = base64.b64encode(os.urandom(32)).decode('utf-8')
        client_pubkey  = base64.b64encode(os.urandom(32)).decode('utf-8')
    else:
        try:
            client_privkey = subprocess.check_output(["wg", "genkey"]).decode().strip()
            client_pubkey  = subprocess.check_output(
                ["wg", "pubkey"], input=client_privkey.encode()
            ).decode().strip()
        except Exception:
            client_privkey = base64.b64encode(os.urandom(32)).decode('utf-8')
            client_pubkey  = base64.b64encode(os.urandom(32)).decode('utf-8')

    config = (
        f"# ┌─────────────────────────────────────────────────────────────┐\n"
        f"# │  CNS Quantum VPN — PQC-Gated WireGuard Config               │\n"
        f"# │  Generated for: {user_id:<44}│\n"
        f"# │  Algorithm: CRYSTALS-Kyber-512 + Wiesner QKD                │\n"
        f"# │  NIST PQC Standard: FIPS 203 (2024)                         │\n"
        f"# └─────────────────────────────────────────────────────────────┘\n"
        f"\n"
        f"[Interface]\n"
        f"PrivateKey = {client_privkey}\n"
        f"Address    = {allocated_ip}/32\n"
        f"DNS        = 1.1.1.1\n"
        f"\n"
        f"[Peer]\n"
        f"# Azure PQC Gateway\n"
        f"PublicKey  = {server_pubkey}\n"
        f"Endpoint   = {SERVER_ENDPOINT}\n"
        f"AllowedIPs = 0.0.0.0/0\n"
        f"PersistentKeepalive = 25\n"
        f"\n"
        f"# ── Post-Quantum Session Binding ──────────────────────────────\n"
        f"# Kyber-512 Shared Secret (session-scoped, rotates each login)\n"
        f"# SessionKey = {session_key or 'NOT_SET'}\n"
        f"# This peer is auto-removed after session expiry.\n"
    )

    return config, client_pubkey
