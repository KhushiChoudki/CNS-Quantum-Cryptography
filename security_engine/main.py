from .token_generator import generate_token
from .verifier import verify_token
from .pqc_module import generate_pqc_keys, generate_secure_session, decapsulate_key
from .noise_model import add_noise
from .attack_simulator import replay_attack, random_attack, partial_guess_attack
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Metrics storage
metrics = {
    "auth_success": 0,
    "auth_total": 0,
    "attack_success": 0,
    "attack_total": 0,
    "confidence_scores": []
}

def register_user(user_id):
    """
    Registers a new user by generating a token and PQC keys.
    """
    logger.info(f"Registering user: {user_id}")
    token = generate_token(user_id)
    public_key = generate_pqc_keys(user_id)
    return {
        "user_id": user_id,
        "token": token,
        "public_key": public_key.hex()
    }

def authenticate_user(user_id, received_token):
    """
    Full authentication flow: Token Verification -> PQC Key Exchange.
    Refreshes token after EACH attempt.
    """
    metrics["auth_total"] += 1
    logger.info(f"Authenticating user: {user_id}")
    
    # Step 1: Verify Token (This marks it as used)
    verification = verify_token(user_id, received_token)
    confidence = verification["confidence"]
    metrics["confidence_scores"].append(confidence)
    
    if verification["status"] != "valid":
        logger.warning(f"Authentication failed for {user_id} (Confidence: {confidence:.2f}, Error: {verification.get('error', 'None')})")
        # Always refresh token after an attempt
        generate_token(user_id)
        return {"status": "denied", "confidence": confidence, "error": verification.get("error")}
    
    logger.info(f"Token verification successful (Confidence: {confidence:.2f})")
    
    # Step 2: Kyber Key Exchange
    session = generate_secure_session(user_id, confidence)
    if not session:
        logger.error(f"PQC Session generation failed for {user_id}")
        generate_token(user_id)
        return {"status": "pqc_failed", "confidence": confidence}
    
    # Simulate user decapsulating to recover the shared secret
    user_secret = decapsulate_key(user_id, session["ciphertext"])
    
    # Refresh token for NEXT session
    generate_token(user_id)
    
    # Verify shared secret
    if user_secret == session["shared_secret"]:
        metrics["auth_success"] += 1
        logger.info(f"PQC Key exchange successful for {user_id}")
        return {
            "status": "authenticated",
            "confidence": confidence,
            "session_key": session["shared_secret"].hex()
        }
    else:
        logger.error(f"Shared secret mismatch for {user_id}")
        return {"status": "pqc_error", "confidence": confidence}

def run_attack_simulation(user_id):
    """
    Runs a series of attacks and logs metrics.
    """
    logger.info("Starting attack simulation...")
    
    # 1. Replay Attack
    metrics["attack_total"] += 1
    replay = replay_attack(user_id)
    if replay["status"] == "success":
        metrics["attack_success"] += 1
    logger.info(f"Replay Attack: {replay['status']} (Confidence: {replay.get('confidence', 0):.2f})")
    
    # 2. Random Attack
    metrics["attack_total"] += 1
    rand_token = random_attack()
    result = verify_token(user_id, rand_token)
    if result["status"] == "valid":
        metrics["attack_success"] += 1
    logger.info(f"Random Attack: {result['status']} (Confidence: {result['confidence']:.2f})")
    
    # 3. Partial Guess Attack (50% knowledge)
    metrics["attack_total"] += 1
    guess_token = partial_guess_attack(user_id)
    result = verify_token(user_id, guess_token)
    if result["status"] == "valid":
        metrics["attack_success"] += 1
    logger.info(f"Partial Guess (50%) Attack: {result['status']} (Confidence: {result['confidence']:.2f})")

def get_metrics():
    """
    Returns authentication metrics.
    """
    avg_confidence = sum(metrics["confidence_scores"]) / len(metrics["confidence_scores"]) if metrics["confidence_scores"] else 0
    return {
        "auth_success_rate": metrics["auth_success"] / metrics["auth_total"] if metrics["auth_total"] else 0,
        "attack_success_rate": metrics["attack_success"] / metrics["attack_total"] if metrics["attack_total"] else 0,
        "average_confidence": avg_confidence
    }

if __name__ == "__main__":
    # Demonstration
    USER_ID = "quantum_user_001"
    
    # Registration
    reg_data = register_user(USER_ID)
    original_token = reg_data["token"]
    
    print("\n--- REGISTRATION ---")
    print(f"User: {USER_ID}")
    print(f"Public Key (PQC): {reg_data['public_key']}")
    
    # Correct Authentication
    print("\n--- CORRECT AUTHENTICATION ---")
    auth_result = authenticate_user(USER_ID, original_token)
    print(f"Result: {auth_result['status']}, Confidence: {auth_result['confidence']:.2f}")
    if "session_key" in auth_result:
        print(f"Session Key: {auth_result['session_key']}")
        
    # Authentication with NOISE
    print("\n--- AUTHENTICATION WITH NOISE (0.15) ---")
    noisy_token = add_noise(original_token, 0.15)
    auth_result = authenticate_user(USER_ID, noisy_token)
    print(f"Result: {auth_result['status']}, Confidence: {auth_result['confidence']:.2f}")

    # Authentication with HEAVY NOISE
    print("\n--- AUTHENTICATION WITH HEAVY NOISE (0.4) ---")
    heavy_noisy_token = add_noise(original_token, 0.4)
    auth_result = authenticate_user(USER_ID, heavy_noisy_token)
    print(f"Result: {auth_result['status']}, Confidence: {auth_result['confidence']:.2f}")

    # Attack Simulation
    print("\n--- ATTACK SIMULATION ---")
    run_attack_simulation(USER_ID)
    
    # Results
    print("\n--- SYSTEM METRICS ---")
    sys_metrics = get_metrics()
    print(f"Auth Success Rate: {sys_metrics['auth_success_rate']:.2%}")
    print(f"Attack Success Rate: {sys_metrics['attack_success_rate']:.2%}")
    print(f"Average Confidence: {sys_metrics['average_confidence']:.2f}")
