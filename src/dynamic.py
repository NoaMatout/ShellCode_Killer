import os
import time
from utils import calculate_entropy, log_detection

SIGNATURES = [
    b"/bin/sh",
    b"\x31\xc0\x50\x68",
    b"\x89\xe3",
    b"\xb0\x0b",
    b"\xcd\x80",
]

def get_executable_memory_regions(pid: int):
    """Récupère les plages mémoire exécutables d'un processus."""
    regions = []
    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, "r") as maps_file:
            for line in maps_file:
                if "r-xp" in line or "rwxp" in line:
                    addr = line.split(' ')[0]
                    start_str, end_str = addr.split('-')
                    start = int(start_str, 16)
                    end = int(end_str, 16)
                    regions.append((start, end))
    except FileNotFoundError:
        print(f"\033[91m[ERROR]\033[0m Impossible d'ouvrir {maps_path}.")
    return regions

def scan_once(pid: int):
    """Scanne une fois les segments exécutables d'un processus."""
    mem_path = f"/proc/{pid}/mem"
    regions = get_executable_memory_regions(pid)
    findings = []

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
                        findings.append(msg)
                        log_detection(pid, msg)

                # Entropie
                entropy = calculate_entropy(chunk)
                if entropy > 7.5:
                    msg = f"[WARNING] Entropie élevée ({entropy:.2f}) détectée dans {hex(start)}-{hex(end)}"
                    print(f"\033[93m{msg}\033[0m")
                    findings.append(msg)
                    log_detection(pid, msg)

    except PermissionError:
        print(f"\033[91m[ERROR]\033[0m Permission refusée pour lire {mem_path}. Essayez avec sudo.")

    return findings

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

