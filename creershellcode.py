import subprocess

# XOR encoding


# Recuperer le shellcode qu'il faut exécuter
INFO    = "[INFO]   "
ERROR   = "[ERROR]  "
SUCCESS = "[SUCCES] "

dir = './'
shellcode = "execve_suid"
encoded   = "wished_encoding"
asmres    = "res.asm"

def get_shellcode(file_path):
    result = subprocess.run(['objdump', '-s', file_path], stdout=subprocess.PIPE)
    result = result.stdout.decode('utf-8')
    result = result.split('\n')
    result = result[4:]

    clean_res = []
    for i in result:
        r = ''.join(i.split(' ')[2:6])
        if r != '': clean_res.append(r)

    return bytes.fromhex(''.join(clean_res))


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
    if(len(shellcode) != len(encoded)):
        print(ERROR + "The lenght of the shellcode and the encoded code doesn't match in the `create_XOR_mask` function")
        exit(1)
    
    xor_mask = bytearray()
    for sc_byte, enc_byte in zip(shellcode, encoded):
        xor_mask.append(sc_byte ^ enc_byte)
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
    with open(file_path, 'r') as f:
        











if __name__ == '__main__':
    shellcode_data = get_shellcode(dir + shellcode)
    encoding = get_encoded_file(dir + encoded)

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

    write_assembly(mask, encoding, dir + asmres)



    