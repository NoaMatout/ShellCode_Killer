from utils import calculate_entropy

SIGNATURES = [
    b"/bin/sh",
    b"\x31\xc0\x50\x68",
    b"\x48\x31\xc0\x50\x48",
    b"\x48\x31\xd2\x48\xbb",
    b"\xb0\x3b\x0f\x05"
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

def scan_once(pid: int):
    """Scanne une fois les segments exécutables d'un processus et calcule un score."""
    mem_path = f"/proc/{pid}/mem"
    regions = get_executable_memory_regions(pid)
    total_score = 0

    try:
        with open(mem_path, "rb") as mem_file:
            for start, end in regions:
                size = end - start
                try:
                    mem_file.seek(start)
                    chunk = mem_file.read(size)
                except (OSError, ValueError):
                    continue

                # Signatures
                for sig in SIGNATURES:
                    if sig in chunk:
                        msg = f"[CRITICAL] Shellcode détecté : {sig.hex()} dans {hex(start)}-{hex(end)}"
                        print(f"\033[91m{msg}\033[0m")
                        log_detection(pid, msg)
                        total_score += 50

                # Entropie
                entropy = calculate_entropy(chunk)
                if entropy > 7.5:
                    msg = f"[WARNING] Entropie élevée ({entropy:.2f}) détectée dans {hex(start)}-{hex(end)}"
                    print(f"\033[93m{msg}\033[0m")
                    log_detection(pid, msg)
                    total_score += 30

    except PermissionError:
        print(f"\033[91m[ERROR]\033[0m Permission refusée pour lire {mem_path}. Essayez avec sudo.")

    if total_score > 100:
        total_score = 100

    if total_score > 0:
        print(f"\n\033[91m[!!] Dangerosité détectée : {total_score}/100\033[0m")
    else:
        print("\033[92m[+] Aucun comportement suspect détecté.\033[0m")

    return total_score

