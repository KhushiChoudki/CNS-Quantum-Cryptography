import random

# In-memory storage for user tokens
# Format: {user_id: {"token": [(basis, bit), ...], "is_used": False}}
user_tokens = {}

def generate_token(user_id, length=16):
    """
    Generates a Wiesner-style quantum-inspired identity token.
    Each token is "destroyed" upon measurement (read).
    """
    bases = ['+', 'x']
    token = []
    
    for _ in range(length):
        basis = random.choice(bases)
        bit = random.randint(0, 1)
        token.append((basis, bit))
    
    user_tokens[user_id] = {
        "token": token,
        "is_used": False
    }
    return token

def get_stored_token(user_id):
    """
    Retrieves the stored token data for a given user.
    """
    return user_tokens.get(user_id)

def mark_token_used(user_id):
    """
    Marks a user's current token as used.
    """
    if user_id in user_tokens:
        user_tokens[user_id]["is_used"] = True
