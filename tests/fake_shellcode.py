import os

def generate_fake_shellcode():
    payload = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x89\xe3\xb0\x0b\xcd\x80"

    # S'assure que le fichier est bien dans tests/
    output_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(output_dir, "fake_shellcode.bin")

    with open(output_path, "wb") as f:
        f.write(payload)

    print(f"[*] Fichier {output_path} généré.")

if __name__ == "__main__":
    generate_fake_shellcode()
