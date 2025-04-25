import math
import os
from datetime import datetime

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

def log_detection(pid: int, message: str):
    """Log les détections dans un fichier rapport dans reports/."""
    os.makedirs("reports", exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/report_pid{pid}_{now}.log"
    with open(filename, "a") as log_file:
        log_file.write(f"{message}\n")

def display_banner():
    banner = r"""
           />_________________________________
 [########[]_________________________________>
           \>
           
         ⚔️  ShellCode_Killer ⚔️
  "Hunt the shellcodes. Kill the threat."
    """
    print(f"\033[96m{banner}\033[0m")
