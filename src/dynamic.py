import os
import time
from utils import calculate_entropy, log_detection

SIGNATURES = [
    b"/bin/sh",
    b"\x31\xc0\x50\x68",
    b"\x48\x31\xc0\x50\x48",
    b"\x48\x31\xd2\x48\xbb",
    b"\xb0\x3b\x0f\x05"
]

def get_executable_memory_regions(pid: int):
    """Retourne les régions mémoire suspectes : r-xp, rwxp, ou rw-p."""
    regions = []
    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, "r") as maps_file:
            for line in maps_file:
                if any(flag in line for flag in ("r-xp", "rwxp", "rw-p")):
                    addr = line.split(' ')[0]
                    start_str, end_str = addr.split('-')
                    start = int(start_str, 16)
                    end = int(end_str, 16)
                    regions.append((start, end))
    except FileNotFoundError:
        print(f"\033[91m[ERROR]\033[0m Impossible d'ouvrir {maps_path}.")
    return regions

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


def detect_shellcode_in_process(pid: int, live_mode=False, interval=5):
    """Détecte du shellcode dans un processus (optionnellement en mode live)."""
    if not live_mode:
        print(f"[*] Analyse dynamique unique du PID {pid}...")
        scan_once(pid)
    else:
        print(f"[*] Surveillance continue du PID {pid} toutes les {interval}s. Appuyez sur Ctrl+C pour stopper.")
        try:
            while True:
                scan_once(pid)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n\033[92m[+] Surveillance stoppée par l'utilisateur.\033[0m")

