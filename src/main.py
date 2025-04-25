import argparse
from static import detect_shellcode_in_file
from dynamic import detect_shellcode_in_process

def main():
    parser = argparse.ArgumentParser(description="ShellCode_Killer - Détecteur de shellcode")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Analyser un fichier binaire")
    group.add_argument("--pid", type=int, help="Analyser dynamiquement un processus par PID")

    args = parser.parse_args()

    if args.file:
        detect_shellcode_in_file(args.file)
    elif args.pid:
        detect_shellcode_in_process(args.pid)

if __name__ == "__main__":
    main()

