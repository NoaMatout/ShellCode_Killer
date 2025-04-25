import math

def calculate_entropy(data: bytes) -> float:
    """Calcule l'entropie d'un buffer de données."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x.to_bytes(1, 'big')) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

