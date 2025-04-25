from utils import calculate_entropy

SIGNATURES = [
    b"/bin/sh",
    b"\x31\xc0\x50\x68",
    b"\x89\xe3",
    b"\xb0\x0b",
    b"\xcd\x80",
]

def detect_shellcode_in_file(filepath: str):
    """Analyse statique d'un fichier binaire pour détection de shellcode."""
    try:
        with open(filepath, "rb") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"\033[91m[ERROR]\033[0m Fichier non trouvé : {filepath}")
        return

    print(f"[*] Analyse du fichier : {filepath}")

    alerts = []

    # Recherche de signatures connues
    for sig in SIGNATURES:
        if sig in content:
            alerts.append(f"\033[91m[CRITICAL]\033[0m Signature shellcode détectée : {sig.hex()}")

    # Calcul de l'entropie
    entropy = calculate_entropy(content)
    print(f"[*] Entropie calculée : {entropy:.2f}")

    if entropy > 7.5:
        alerts.append(f"\033[93m[WARNING]\033[0m Entropie élevée ({entropy:.2f}) - Possible code obfusqué.")

    # Affichage du résultat
    if alerts:
        print("\033[91m[!]\033[0m Alerte détectée :")
        for alert in alerts:
            print(f"    {alert}")
    else:
        print("\033[92m[+]\033[0m Aucun shellcode détecté.")

