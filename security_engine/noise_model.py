import random

def add_noise(token, noise_level=0.1):
    """
    Simulates noise in quantum memory by randomly flipping bits in the token.
    
    Args:
        token (list): The original token (list of (basis, bit) tuples).
        noise_level (float): Probability of a bit being flipped (0.0 to 1.0).
        
    Returns:
        list: A new token with possible bit flips.
    """
    noisy_token = []
    
    for basis, bit in token:
        if random.random() < noise_level:
            # Flip the bit
            new_bit = 1 - bit
            noisy_token.append((basis, new_bit))
        else:
            noisy_token.append((basis, bit))
            
    return noisy_token
