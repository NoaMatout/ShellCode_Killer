import argparse
import psutil
from static import detect_shellcode_in_file
from dynamic import detect_shellcode_in_process
from utils import display_banner
from rich.console import Console
from rich.prompt import Prompt

console = Console()

def main():
    display_banner()
    
    console.rule("[bold cyan]ShellCode_Killer CLI")
    
    parser = argparse.ArgumentParser(description="ShellCode_Killer - Détecteur de shellcode")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Analyser un fichier binaire")
    group.add_argument("--pid", type=int, help="Analyser dynamiquement un processus par PID")
    group.add_argument("--scan-all", action="store_true", help="Scanner tous les processus dynamiquement")
    parser.add_argument("--live", action="store_true", help="Activer la surveillance continue (mode live)")

    args = parser.parse_args()

    if args.file:
        console.print(f"📂 Analyse du fichier : {args.file}", style="bold green")
        detect_shellcode_in_file(args.file)
    elif args.pid:
        console.print(f"🔍 Analyse du PID : {args.pid}", style="bold blue")
        detect_shellcode_in_process(args.pid, live_mode=args.live)
    elif args.scan_all:
        console.print("🚀 Scan global de tous les processus...", style="bold magenta")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                detect_shellcode_in_process(proc.info['pid'], live_mode=False)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

if __name__ == "__main__":
    main()
