# Fonctionne avec le XOR


# Recuperer le shellcode qu'il faut exécuter


with open(__dir__ + "/shellcode.txt", "r") as file:
    shellcode = file.read()


# Recuperer l'encodage souhaité du shellcode


# Génerer le masque XOR


# Verfifier que l'encodage ^ masque = shellcode


# Vérifier que le shellcode ne dispose pas de caractères \x00