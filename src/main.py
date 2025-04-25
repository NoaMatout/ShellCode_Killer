import argparse
from static import detect_shellcode_in_file
from dynamic import detect_shellcode_in_process
from utils import display_banner

def main():
    display_banner()

    parser = argparse.ArgumentParser(description="ShellCode_Killer - Détecteur de shellcode")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Analyser un fichier binaire")
    group.add_argument("--pid", type=int, help="Analyser dynamiquement un processus par PID")

    parser.add_argument("--live", action="store_true", help="Activer la surveillance continue (mode live)")

    args = parser.parse_args()

    if args.file:
        detect_shellcode_in_file(args.file)
    elif args.pid:
        detect_shellcode_in_process(args.pid, live_mode=args.live)

if __name__ == "__main__":
    main()

