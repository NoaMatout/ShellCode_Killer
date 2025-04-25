import os
import struct
from utils import calculate_entropy

# Signatures shellcode connues
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

def detect_shellcode_in_process(pid: int):
    """Analyse la mémoire d'un processus pour détecter du shellcode."""
    print(f"[*] Analyse dynamique du PID {pid}...")

    mem_path = f"/proc/{pid}/mem"
    regions = get_executable_memory_regions(pid)

    if not regions:
        print("\033[93m[WARNING]\033[0m Aucun segment exécutable trouvé.")
        return

    try:
        with open(mem_path, "rb") as mem_file:
            for start, end in regions:
                size = end - start
                try:
                    mem_file.seek(start)
                    chunk = mem_file.read(size)
                except (OSError, ValueError):
                    continue  # Ignore les régions inaccessibles

                # Recherche de signatures
                for sig in SIGNATURES:
                    if sig in chunk:
                        print(f"\033[91m[CRITICAL]\033[0m Shellcode détecté : Signature {sig.hex()} dans la plage {hex(start)}-{hex(end)}")

                # Analyse d'entropie
                entropy = calculate_entropy(chunk)
                if entropy > 7.5:
                    print(f"\033[93m[WARNING]\033[0m Entropie élevée ({entropy:.2f}) détectée dans {hex(start)}-{hex(end)}")
    except PermissionError:
        print(f"\033[91m[ERROR]\033[0m Permission refusée pour lire {mem_path}. Essayez avec sudo.")

