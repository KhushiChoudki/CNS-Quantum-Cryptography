"""
Flask PQC Security Bridge — app.py
====================================
REST API consumed by the Node.js backend.

Endpoints:
  POST /register          → generate Wiesner token + Kyber-512 keypair
  POST /authenticate      → verify token + Kyber KEM → session key
  POST /vpn-peer-add      → add WireGuard peer post-auth
  POST /vpn-peer-remove   → remove peer on logout
  GET  /vpn-peers         → list active peers
  POST /simulate-attack   → run replay/random/partial attack suite
  POST /attack-visual     → animated attack rounds for dashboard
  GET  /metrics           → auth + attack statistics
  GET  /audit-log         → recent security events
"""

from flask import Flask, request, jsonify
import logging
import time
import hashlib

from security_engine.main import (
    register_user, authenticate_user,
    run_attack_simulation, get_metrics
)
from security_engine.pqc_module import (
    benchmark_pqc_vs_classical, verify_session_claim
)
from security_engine.noise_model import generate_full_analysis
from security_engine.wireguard_manager import (
    add_peer, remove_peer, list_peers,
    generate_client_config, get_session_info
)
from security_engine.attack_simulator import (
    replay_attack, random_attack, partial_guess_attack
)
from security_engine.verifier import verify_token
from security_engine.token_generator import get_stored_token, generate_token

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger(__name__)

# ── Audit log (in-memory, last 500 events) ─────────────────────────────────────
_audit: list = []

def _log(event: str, user_id: str = None, details: dict = None):
    _audit.append({
        "event":     event,
        "user_id":   user_id,
        "timestamp": time.time(),
        "details":   details or {},
    })
    if len(_audit) > 500:
        _audit.pop(0)


# ── /register ──────────────────────────────────────────────────────────────────
@app.route("/register", methods=["POST"])
def register():
    data    = request.json or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    result  = register_user(user_id)

    # Attach token display for UI (bits + bases table)
    raw_token = get_stored_token(user_id)
    if raw_token:
        token_display = [
            {"index": i, "basis": b, "bit": v, "basis_name": "Rectilinear" if b == "+" else "Diagonal"}
            for i, (b, v) in enumerate(raw_token["token"])
        ]
        result["token_display"] = token_display
        result["token_length"]  = len(token_display)
        result["wiesner_desc"]  = "Quantum-inspired OTP — each bit/basis pair represents a quantum state"

    _log("user_registered", user_id=user_id,
         details={"pk_prefix": result.get("public_key", "")[:16]})
    return jsonify(result)


# ── /authenticate ──────────────────────────────────────────────────────────────
@app.route("/authenticate", methods=["POST"])
def authenticate():
    data      = request.json or {}
    user_id   = data.get("user_id")
    token     = data.get("token")
    if not user_id or token is None:
        return jsonify({"error": "user_id and token required"}), 400

    result = authenticate_user(user_id, token)

    if result.get("status") == "authenticated":
        # Provide the freshly-rotated token for display
        fresh = get_stored_token(user_id)
        if fresh:
            result["next_token_display"] = [
                {"index": i, "basis": b, "bit": v,
                 "basis_name": "Rectilinear" if b == "+" else "Diagonal"}
                for i, (b, v) in enumerate(fresh["token"])
            ]
        _log("auth_success", user_id=user_id,
             details={"confidence": result.get("confidence"),
                      "session_key_prefix": result.get("session_key", "")[:16]})
    else:
        _log("auth_failed", user_id=user_id,
             details={"reason": result.get("error"),
                      "confidence": result.get("confidence", 0)})

    return jsonify(result)


# ── /vpn-peer-add ──────────────────────────────────────────────────────────────
@app.route("/vpn-peer-add", methods=["POST"])
def vpn_peer_add():
    data         = request.json or {}
    user_id      = data.get("user_id")
    client_pubkey= data.get("client_pubkey")
    session_key  = data.get("session_key", "")
    session_ttl  = data.get("session_ttl", 3600)

    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    ok, allocated_ip, msg = add_peer(user_id, client_pubkey, session_ttl=session_ttl)
    config, gen_pubkey    = generate_client_config(user_id, session_key=session_key)

    _log("vpn_peer_added", user_id=user_id,
         details={"ip": allocated_ip, "ttl": session_ttl, "simulated": not ok or "SIM" in str(msg)})

    return jsonify({
        "success":      True,
        "allocated_ip": allocated_ip,
        "vpn_config":   config,
        "client_pubkey": gen_pubkey,
        "session_ttl":  session_ttl,
        "message":      f"Peer dynamically added → {allocated_ip} (TTL={session_ttl}s)",
    })


# ── /vpn-peer-remove ───────────────────────────────────────────────────────────
@app.route("/vpn-peer-remove", methods=["POST"])
def vpn_peer_remove():
    data    = request.json or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    ok, msg = remove_peer(user_id)
    _log("vpn_peer_removed", user_id=user_id)
    return jsonify({"success": ok, "message": str(msg)})


# ── /vpn-peers ─────────────────────────────────────────────────────────────────
@app.route("/vpn-peers", methods=["GET"])
def vpn_peers():
    return jsonify({"peers": list_peers()})


# ── /vpn-session ───────────────────────────────────────────────────────────────
@app.route("/vpn-session", methods=["GET"])
def vpn_session():
    user_id = request.args.get("user_id")
    info    = get_session_info(user_id) if user_id else None
    return jsonify(info or {"active": False})


# ── /simulate-attack ───────────────────────────────────────────────────────────
@app.route("/simulate-attack", methods=["POST"])
def simulate_attack():
    data    = request.json or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    run_attack_simulation(user_id)
    _log("attack_simulation", user_id=user_id)
    return jsonify({"status": "simulation_complete", **get_metrics()})


# ── /attack-visual ─────────────────────────────────────────────────────────────
@app.route("/attack-visual", methods=["POST"])
def attack_visual():
    data        = request.json or {}
    user_id     = data.get("user_id")
    attack_type = data.get("attack_type", "random")
    rounds      = min(int(data.get("rounds", 8)), 20)

    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    # Ensure user has a token for attack simulation
    tok = get_stored_token(user_id)
    if not tok:
        generate_token(user_id)

    results = []
    for i in range(rounds):
        if attack_type == "replay":
            tok_data = get_stored_token(user_id)
            if tok_data:
                intercepted = list(tok_data["token"])
                # First use — mark consumed
                verify_token(user_id, intercepted)
                # Replay attempt
                result = verify_token(user_id, intercepted)
                results.append({
                    "round":      i + 1,
                    "attack":     "replay",
                    "confidence": result["confidence"],
                    "blocked":    result["status"] != "valid",
                    "reason":     result.get("error", "OK"),
                    "steps": [
                        {"label": "Attacker captures token",  "status": "captured"},
                        {"label": "Token used legitimately",  "status": "consumed"},
                        {"label": "Replay attempt submitted", "status": "replayed"},
                        {"label": "Global replay registry checked", "status": "blocked" if result["status"] != "valid" else "passed"},
                    ]
                })
                # Regenerate for next round
                generate_token(user_id)

        elif attack_type == "partial":
            guess = partial_guess_attack(user_id, known_fraction=0.5)
            result = verify_token(user_id, guess) if guess else {"status": "failed", "confidence": 0.0}
            results.append({
                "round":      i + 1,
                "attack":     "partial_guess_50pct",
                "confidence": result.get("confidence", 0.0),
                "blocked":    result.get("status") != "valid",
                "reason":     result.get("error", ""),
            })
            generate_token(user_id)

        else:  # random
            rand_tok = random_attack()
            result   = verify_token(user_id, rand_tok)
            results.append({
                "round":      i + 1,
                "attack":     "random_impersonation",
                "confidence": result.get("confidence", 0.0),
                "blocked":    result.get("status") != "valid",
                "reason":     result.get("error", ""),
            })

    blocked_count = sum(1 for r in results if r["blocked"])
    _log("attack_visual", user_id=user_id,
         details={"type": attack_type, "rounds": rounds, "blocked": blocked_count})

    return jsonify({
        "results":       results,
        "total_rounds":  rounds,
        "blocked":       blocked_count,
        "block_rate":    round(blocked_count / rounds, 3) if rounds else 0,
        "attack_type":   attack_type,
    })


# ── /metrics ───────────────────────────────────────────────────────────────────
@app.route("/metrics", methods=["GET"])
def metrics():
    m = get_metrics()
    m["active_vpn_peers"] = len(list_peers())
    m["audit_events_count"] = len(_audit)
    return jsonify(m)


# ── /audit-log ─────────────────────────────────────────────────────────────────
@app.route("/audit-log", methods=["GET"])
def audit_log():
    limit  = int(request.args.get("limit", 50))
    events = list(reversed(_audit[-limit:]))
    return jsonify({"events": events, "total": len(_audit)})


# ── /benchmark ─────────────────────────────────────────────────────────────────
@app.route("/benchmark", methods=["GET"])
def benchmark():
    n = int(request.args.get("runs", 20))
    results = benchmark_pqc_vs_classical(n_runs=n)
    _log("benchmark_run", details={"n_runs": n})
    return jsonify(results)


# ── /security-analysis ─────────────────────────────────────────────────────────
@app.route("/security-analysis", methods=["GET"])
def security_analysis():
    n = int(request.args.get("samples", 300))
    results = generate_full_analysis(n_samples=n)
    _log("security_analysis", details={"n_samples": n})
    return jsonify(results)


# ── /hndl-demo ─────────────────────────────────────────────────────────────────
@app.route("/hndl-demo", methods=["GET"])
def hndl_demo():
    import os as _os
    fake_ct    = _os.urandom(768).hex()
    timestamp  = int(time.time())
    token_hash = hashlib.sha3_256(_os.urandom(32)).hexdigest()
    return jsonify({
        "scenario":    "Harvest-Now-Decrypt-Later (HNDL)",
        "threat_model":"Nation-state adversary archives encrypted traffic today for future quantum decryption.",
        "captured_today": {
            "timestamp": timestamp,
            "kyber_ciphertext_hex": fake_ct[:64] + "..." + fake_ct[-16:],
            "ciphertext_size_bytes": 768,
            "session_token_hash": token_hash[:32] + "...",
        },
        "future_attack_attempt": {
            "assumption": "Adversary has quantum computer capable of breaking Kyber KEM",
            "decryption": "Attacker recovers Kyber shared_secret K from archived ciphertext",
            "replay_attempt": "Attacker tries to reuse K to authenticate or replay session token",
        },
        "maqraf_defenses": [
            {"defense": "Session Token Rotation",    "detail": "Wiesner token consumed + rotated on every auth. Even with K, the token is already dead.", "status": "BLOCKS REPLAY"},
            {"defense": "Timestamp Binding",          "detail": "Dilithium signature includes timestamp. Replaying old signed claims fails freshness check.", "status": "BLOCKS REPLAY"},
            {"defense": "WireGuard Peer Expiry",      "detail": "Peer removed after 1 hour. No active tunnel exists to replay into.", "status": "BLOCKS TUNNEL"},
            {"defense": "Global Token Hash Registry", "detail": "SHA-256 hash of every consumed token stored permanently.", "status": "BLOCKS TOKEN REPLAY"},
            {"defense": "Kyber IND-CCA2 Security",    "detail": "Dilithium-signed claim is bound to specific user+timestamp.", "status": "LIMITS DAMAGE"},
        ],
        "conclusion": "MAQRAF's multi-layer design ensures a future quantum adversary cannot replay archived ciphertext — token, timestamp, and peer access have all expired.",
        "nist_references": ["NIST FIPS 203 (Kyber)", "NIST FIPS 204 (Dilithium)", "NIST IR 8413-upd1"],
    })


# ── /dilithium-verify ──────────────────────────────────────────────────────────
@app.route("/dilithium-verify", methods=["POST"])
def dilithium_verify_endpoint():
    data = request.json or {}
    user_id   = data.get("user_id")
    claim     = data.get("claim", {})
    signature = data.get("signature", "")
    if not user_id or not claim or not signature:
        return jsonify({"error": "user_id, claim, signature required"}), 400
    valid = verify_session_claim(user_id, claim, signature)
    return jsonify({
        "valid":     valid,
        "algorithm": "CRYSTALS-Dilithium-2 (FIPS 204)",
        "message":   "Signature valid — session claim authentic" if valid else "Signature INVALID — possible tampering",
    })


# ── /health ────────────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":    "online",
        "service":   "CNS PQC Security Bridge",
        "algorithm": "Kyber-512 (FIPS 203) + Dilithium-2 (FIPS 204) + Wiesner QKD",
        "timestamp": time.time(),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
