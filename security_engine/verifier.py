import hashlib
from .token_generator import get_stored_token, mark_token_used

# Tracks hashes of all tokens ever consumed to prevent any replay
consumed_token_hashes = set()

def _get_token_hash(token):
    """
    Returns a deterministic hash of a token list of tuples.
    """
    token_str = str(token)
    return hashlib.sha256(token_str.encode()).digest()

def verify_token(user_id, received_token, threshold=0.85):
    """
    Verifies a received token against the stored token for a user.
    Uses probabilistic matching with a high threshold and GLOBAL replay protection.
    """
    token_data = get_stored_token(user_id)
    
    if not token_data:
        return {"status": "invalid", "confidence": 0.0, "error": "User not found"}
    
    # Check if this SPECIFIC token has been seen before (Global Replay Protection)
    received_hash = _get_token_hash(received_token)
    if received_hash in consumed_token_hashes:
        return {"status": "invalid", "confidence": 0.0, "error": "Token reuse detected (Global Replay Protection)"}

    # Internal state check (Freshness)
    if token_data.get("is_used", False):
         return {"status": "invalid", "confidence": 0.0, "error": "User token already consumed locally"}

    stored_token = token_data["token"]
    
    if len(stored_token) != len(received_token):
        return {"status": "invalid", "confidence": 0.0, "error": "Token length mismatch"}
    
    matches = 0
    total_comparisons = 0
    
    # Mark as used and add to global registry
    mark_token_used(user_id)
    consumed_token_hashes.add(received_hash)
    
    for i in range(len(stored_token)):
        stored_basis, stored_bit = stored_token[i]
        received_basis, received_bit = received_token[i]
        
        if stored_basis == received_basis:
            total_comparisons += 1
            if stored_bit == received_bit:
                matches += 1
            
    if total_comparisons == 0:
        confidence = 0.0 
    else:
        confidence = matches / total_comparisons
        
    status = "valid" if confidence >= threshold else "invalid"
    
    return {
        "status": status,
        "confidence": confidence
    }
