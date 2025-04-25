import ctypes
import time
import os

# Simule un shellcode en mémoire
payload = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x89\xe3\xb0\x0b\xcd\x80"

# Alloue un buffer avec les droits de lecture/écriture
buf = ctypes.create_string_buffer(payload)

print(f"[*] PID du fake process : {os.getpid()}")

# Garde le programme vivant pour pouvoir scanner
while True:
    time.sleep(10)
