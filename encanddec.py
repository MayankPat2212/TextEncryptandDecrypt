from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import string

# Caesar Cipher Encrypt
def caesar_cipher_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                result += chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
            elif char.isupper():
                result += chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
        else:
            result += char
    return result

# Caesar Cipher Decrypt
def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)

# Vigenère Cipher Encrypt
def vigenere_cipher_encrypt(text, key):
    key = key.lower()
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    text_int = [ord(i) for i in text]
    result = ""
    for i in range(len(text_int)):
        value = (text_int[i] + key_as_int[i % key_length]) % 256
        result += chr(value)
    return result

# Vigenère Cipher Decrypt
def vigenere_cipher_decrypt(text, key):
    key = key.lower()
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    text_int = [ord(i) for i in text]
    result = ""
    for i in range(len(text_int)):
        value = (text_int[i] - key_as_int[i % key_length]) % 256
        result += chr(value)
    return result

# AES Encrypt
def aes_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

# AES Decrypt
def aes_decrypt(encrypted_text, key):
    iv = base64.b64decode(encrypted_text[:24])  # 24 chars = 16 bytes in base64 encoding
    ct = base64.b64decode(encrypted_text[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# Main Function to Handle User Input
def main():
    while True:
        print("Choose an encryption algorithm:")
        print("1. Caesar Cipher")
        print("2. Vigenère Cipher")
        print("3. AES")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            mode = input("Do you want to Encrypt or Decrypt? (E/D): ").upper()
            text = input("Enter text: ")
            shift = int(input("Enter shift value: "))

            if mode == 'E':
                encrypted_text = caesar_cipher_encrypt(text, shift)
                print("Encrypted text:", encrypted_text)
            elif mode == 'D':
                decrypted_text = caesar_cipher_decrypt(text, shift)
                print("Decrypted text:", decrypted_text)
            else:
                print("Invalid mode choice. Please choose 'E' for encrypt or 'D' for decrypt.")

        elif choice == '2':
            mode = input("Do you want to Encrypt or Decrypt? (E/D): ").upper()
            text = input("Enter text: ")
            key = input("Enter key: ")

            if mode == 'E':
                encrypted_text = vigenere_cipher_encrypt(text, key)
                print("Encrypted text:", encrypted_text)
            elif mode == 'D':
                decrypted_text = vigenere_cipher_decrypt(text, key)
                print("Decrypted text:", decrypted_text)
            else:
                print("Invalid mode choice. Please choose 'E' for encrypt or 'D' for decrypt.")

        elif choice == '3':
            mode = input("Do you want to Encrypt or Decrypt? (E/D): ").upper()
            text = input("Enter text: ")
            key = input("Enter key (16, 24, or 32 bytes): ")

            if len(key) not in [16, 24, 32]:
                print("Key must be 16, 24, or 32 bytes long.")
                continue
            key = key.ljust(32)[:32].encode()  # Ensure the key length is valid

            if mode == 'E':
                encrypted_text = aes_encrypt(text, key)
                print("Encrypted text:", encrypted_text)
            elif mode == 'D':
                decrypted_text = aes_decrypt(text, key)
                print("Decrypted text:", decrypted_text)
            else:
                print("Invalid mode choice. Please choose 'E' for encrypt or 'D' for decrypt.")

        elif choice == '4':
            break

        else:
            print("Invalid choice. Please try again.")

# Run the main function
if __name__ == "__main__":
    main()
