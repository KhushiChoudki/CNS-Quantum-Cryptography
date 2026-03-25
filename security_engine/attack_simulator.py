import random
from .token_generator import generate_token, get_stored_token
from .verifier import verify_token

def replay_attack(user_id):
    """
    Simulates a replay attack by intercepting a valid token and attempting to reuse it.
    """
    # 1. Intercept current valid token
    token_data = get_stored_token(user_id)
    if not token_data:
        return {"attack": "replay", "status": "failed", "reason": "No token found"}
    
    intercepted_token = list(token_data["token"])
    
    # 2. Use it legally (simulate a valid session)
    verify_token(user_id, intercepted_token)
    
    # 3. ATTEMPT REPLAY
    result = verify_token(user_id, intercepted_token)
    return {
        "attack": "replay", 
        "status": "success" if result["status"] == "valid" else "failed", 
        "confidence": result["confidence"], 
        "reason": result.get("error")
    }

def random_attack(length=16):
    """
    Simulates a random impersonation attack.
    """
    # Attacker doesn't know the user_id's token, so they generate a random one
    attacker_token = []
    bases = ['+', 'x']
    for _ in range(length):
        attacker_token.append((random.choice(bases), random.randint(0, 1)))
    
    # Attempt verification against a dummy or real user
    # For demonstration, we'll assume they try a random user
    return attacker_token

def partial_guess_attack(user_id, known_fraction=0.5):
    """
    Simulates an attack where the attacker knows some parts of the token.
    """
    token_data = get_stored_token(user_id)
    if not token_data:
        return None
        
    stored_token = token_data["token"]
    length = len(stored_token)
    attacker_token = []
    
    for i in range(length):
        if random.random() < known_fraction:
            # Attacker knows this bit/basis
            attacker_token.append(stored_token[i])
        else:
            # Attacker guesses
            attacker_token.append((random.choice(['+', 'x']), random.randint(0, 1)))
            
    return attacker_token
