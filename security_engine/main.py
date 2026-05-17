"""
Security Engine — Core Logic
==============================
register_user   → Wiesner token generation + Kyber-512 keypair
authenticate_user → Token verify (quantum layer) + Kyber KEM (PQC layer)
run_attack_simulation → replay / random / partial-guess attacks
get_metrics → auth + attack statistics
"""

from .token_generator import generate_token
from .verifier import verify_token
from .pqc_module import (
    generate_pqc_keys, generate_secure_session,
    decapsulate_key, get_kyber_metadata,
    pqc_keys  # for checking if user keys are in memory
)
from .noise_model import add_noise
from .attack_simulator import replay_attack, random_attack, partial_guess_attack
import logging
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ── Metrics ────────────────────────────────────────────────────────────────────
metrics = {
    "auth_success":       0,
    "auth_total":         0,
    "attack_success":     0,
    "attack_total":       0,
    "confidence_scores":  [],
    "attacks_run":        0,
}


def register_user(user_id: str) -> dict:
    """
    Registration flow:
      1. Generate 16-position Wiesner quantum token (basis + bit per position)
      2. Generate CRYSTALS-Kyber-512 keypair for PQC key exchange
    """
    logger.info(f"[REGISTER] {user_id}")
    token      = generate_token(user_id)
    pub, meta  = generate_pqc_keys(user_id)

    return {
        "user_id":         user_id,
        "token":           token,
        "public_key":      pub.hex(),
        "kyber_meta":      meta,
        "wiesner_length":  len(token),
        "registered_at":   time.time(),
    }


def authenticate_user(user_id: str, received_token) -> dict:
    """
    Full authentication pipeline:
      [Layer 1] Wiesner QKD token verification → confidence score
      [Layer 2] CRYSTALS-Kyber KEM → session key

    Token is consumed (one-time) and rotated on every attempt.
    """
    metrics["auth_total"] += 1
    logger.info(f"[AUTH] {user_id}")

    # ── Layer 1: Wiesner token verify ──────────────────────────────────────────
    verification = verify_token(user_id, received_token)
    confidence   = verification["confidence"]
    metrics["confidence_scores"].append(confidence)

    if verification["status"] != "valid":
        logger.warning(f"[AUTH-FAIL] {user_id} conf={confidence:.2f} err={verification.get('error')}")
        next_tok = generate_token(user_id)
        return {
            "status":     "denied",
            "confidence": confidence,
            "error":      verification.get("error"),
            "next_token": next_tok,
            "layers_passed": 0,
        }

    logger.info(f"[AUTH] Layer 1 passed — conf={confidence:.2f}")

    # ── Layer 2: Kyber KEM ─────────────────────────────────────────────────────
    # If Flask was restarted, in-memory keys are gone — auto-regenerate from scratch
    if user_id not in pqc_keys:
        logger.warning(f"[AUTH] Keys not in memory for {user_id} — regenerating (Flask restart recovery)")
        generate_pqc_keys(user_id)

    session = generate_secure_session(user_id, confidence)
    if not session:
        logger.error(f"[AUTH] Kyber KEM failed for {user_id}")
        next_tok = generate_token(user_id)
        return {
            "status":     "pqc_failed",
            "confidence": confidence,
            "next_token": next_tok,
            "layers_passed": 1,
        }

    user_secret = decapsulate_key(user_id, session["ciphertext"])

    # Rotate token for next session
    next_tok = generate_token(user_id)

    if user_secret == session["shared_secret"]:
        metrics["auth_success"] += 1
        logger.info(f"[AUTH-OK] {user_id} — Kyber KEM verified + Dilithium signed ✓")
        return {
            "status":              "authenticated",
            "confidence":          confidence,
            "session_key":         session["shared_secret"].hex(),
            "kyber_ciphertext":    session["ciphertext"].hex()[:64] + "...",
            "kyber_algorithm":     session["algorithm"],
            "kyber_standard":      session["standard"],
            "security_bits":       session["security_bits"],
            "next_token":          next_tok,
            "layers_passed":       2,
            # Dilithium signature fields
            "dilithium_signature": session.get("dilithium_signature"),
            "dilithium_claim":     session.get("dilithium_claim"),
            "signature_verified":  session.get("signature_verified", False),
            "dilithium_meta":      session.get("dilithium_meta", {}),
        }
    else:
        logger.error(f"[AUTH] Kyber shared secret mismatch for {user_id}")
        return {
            "status":        "kyber_mismatch",
            "confidence":    confidence,
            "next_token":    next_tok,
            "layers_passed": 1,
        }


def run_attack_simulation(user_id: str) -> dict:
    """Run replay + random + partial-guess attacks and record outcomes."""
    logger.info(f"[ATTACK-SIM] {user_id}")
    results = {}

    # 1. Replay attack
    metrics["attack_total"] += 1
    metrics["attacks_run"]  += 1
    replay = replay_attack(user_id)
    if replay["status"] == "success":
        metrics["attack_success"] += 1
    results["replay"] = replay
    logger.info(f"[ATTACK] Replay: {replay['status']} conf={replay.get('confidence',0):.2f}")

    # 2. Random impersonation
    metrics["attack_total"] += 1
    metrics["attacks_run"]  += 1
    rand_tok = random_attack()
    r2 = verify_token(user_id, rand_tok)
    if r2["status"] == "valid":
        metrics["attack_success"] += 1
    results["random"] = {
        "status": "success" if r2["status"] == "valid" else "blocked",
        "confidence": r2["confidence"],
    }

    # 3. Partial guess (50 % knowledge)
    metrics["attack_total"] += 1
    metrics["attacks_run"]  += 1
    guess = partial_guess_attack(user_id, known_fraction=0.5)
    r3 = verify_token(user_id, guess) if guess else {"status": "failed", "confidence": 0.0}
    if r3.get("status") == "valid":
        metrics["attack_success"] += 1
    results["partial_guess"] = {
        "status": "success" if r3.get("status") == "valid" else "blocked",
        "confidence": r3.get("confidence", 0.0),
    }

    return results


def get_metrics() -> dict:
    scores = metrics["confidence_scores"]
    avg    = sum(scores) / len(scores) if scores else 0
    recent = scores[-10:] if len(scores) > 10 else scores
    return {
        "auth_success_rate":    metrics["auth_success"] / metrics["auth_total"] if metrics["auth_total"] else 0,
        "attack_success_rate":  metrics["attack_success"] / metrics["attack_total"] if metrics["attack_total"] else 0,
        "average_confidence":   avg,
        "confidence_history":   recent,
        "auth_total":           metrics["auth_total"],
        "auth_success":         metrics["auth_success"],
        "attacks_run":          metrics["attacks_run"],
        "attack_blocked":       metrics["attack_total"] - metrics["attack_success"],
    }
