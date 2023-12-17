import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

# Defining Caesar Cipher functions #
def caesar_encrypt(message, shift):
    encrypted_message = ""
    for char in message:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                char_code = ord(char) + shift_amount
                if char_code > ord('z'):
                    char_code -= 26
                encrypted_message += chr(char_code)
            elif char.isupper():
                char_code = ord(char) + shift_amount
                if char_code > ord('Z'):
                    char_code -= 26
                encrypted_message += chr(char_code)
        else:
            encrypted_message += char
    return encrypted_message

def caesar_decrypt(encrypted_message, shift):
    return caesar_encrypt(encrypted_message, -shift)

# Defining Vigenère Cipher functions #
def vigenere_encrypt(message, keyword):
    encrypted_message = ""
    keyword_length = len(keyword)
    for i, char in enumerate(message):
        if char.isalpha():
            keyword_char = keyword[i % keyword_length]
            shift = ord(keyword_char.lower()) - ord('a')
            encrypted_message += caesar_encrypt(char, shift)
        else:
            encrypted_message += char
    return encrypted_message

def vigenere_decrypt(encrypted_message, keyword):
    decrypted_message = ""
    keyword_length = len(keyword)
    for i, char in enumerate(encrypted_message):
        if char.isalpha():
            keyword_char = keyword[i % keyword_length]
            shift = ord(keyword_char.lower()) - ord('a')
            decrypted_message += caesar_decrypt(char, shift)
        else:
            decrypted_message += char
    return decrypted_message

# Defining Substitution Cipher functions #
def substitution_cipher(key, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    key = key.upper()
    key_map = {}
    for i, char in enumerate(alphabet):
        if char.isalpha():
            key_map[char] = key[i % len(key)]

    def encrypt(message):
        encrypted_message = ""
        for char in message:
            if char.isalpha():
                encrypted_char = key_map.get(char.upper(), char)
                if char.islower():
                    encrypted_char = encrypted_char.lower()
                encrypted_message += encrypted_char
            else:
                encrypted_message += char
        return encrypted_message

    def decrypt(encrypted_message):
        inverted_key_map = {v: k for k, v in key_map.items()}
        decrypted_message = ""
        for char in encrypted_message:
            if char.isalpha():
                decrypted_char = inverted_key_map.get(char.upper(), char)
                if char.islower():
                    decrypted_char = decrypted_char.lower()
                decrypted_message += decrypted_char
            else:
                decrypted_message += char
        return decrypted_message

    return encrypt, decrypt

# Graphical User Interface (GUI) functions
def encrypt_message():
    message = input_text.get("1.0", "end-1c")
    selected_algorithm = algorithm_combobox.get()
    keyword = keyword_entry.get()
    shift = shift_entry.get()
    key = key_entry.get()

    if selected_algorithm == "Caesar":
        if not shift.isdigit():
            messagebox.showerror("Error", "Shift must be a positive integer")
            return
        shift = int(shift)
        result = caesar_encrypt(message, shift)
    elif selected_algorithm == "Vigenère":
        result = vigenere_encrypt(message, keyword)
    elif selected_algorithm == "Substitution":
        result = substitution_cipher(key)[0](message)
    output_text.delete("1.0", "end")
    output_text.insert("1.0", result)

def decrypt_message():
    message = input_text.get("1.0", "end-1c")
    selected_algorithm = algorithm_combobox.get()
    keyword = keyword_entry.get()
    shift = shift_entry.get()
    key = key_entry.get()

    if selected_algorithm == "Caesar":
        if not shift.isdigit():
            messagebox.showerror("Error", "Shift must be a positive integer")
            return
        shift = int(shift)
        result = caesar_decrypt(message, shift)
    elif selected_algorithm == "Vigenère":
        result = vigenere_decrypt(message, keyword)
    elif selected_algorithm == "Substitution":
        result = substitution_cipher(key)[1](message)
    output_text.delete("1.0", "end")
    output_text.insert("1.0", result)

# Create the main application window#
root = tk.Tk()
root.title("Cryptography Software")

# Input and output text areas#
input_text = tk.Text(root, width=40, height=10)
input_text.grid(row=0, column=0, padx=10, pady=10)

output_text = tk.Text(root, width=40, height=10)
output_text.grid(row=0, column=1, padx=10, pady=10)


# Algorithm selection #
algorithm_label = tk.Label(root, text="Select an algorithm:")
algorithm_label.grid(row=1, column=0, columnspan=2)

algorithm_var = tk.StringVar()
algorithm_combobox = ttk.Combobox(root, textvariable=algorithm_var, values=["Caesar", "Vigenère", "Substitution"])
algorithm_combobox.grid(row=2, column=0, columnspan=2)
algorithm_combobox.set("Caesar")

# Caesar cipher shift input #
shift_label = tk.Label(root, text="Shift (Caesar Cipher):")
shift_label.grid(row=3, column=0)

shift_entry = tk.Entry(root)
shift_entry.grid(row=3, column=1)


# Vigenère cipher keyword input#
keyword_label = tk.Label(root, text="Keyword (Vigenère Cipher):")
keyword_label.grid(row=4, column=0)

keyword_entry = tk.Entry(root)
keyword_entry.grid(row=4, column=1)


# Substitution cipher key input#
key_label = tk.Label(root, text="Key (Substitution Cipher):")
key_label.grid(row=5, column=0)

key_entry = tk.Entry(root)
key_entry.grid(row=5, column=1)

# Creating Encrypt and decrypt buttons#
encrypt_button = tk.Button(root, text="Encryption", command=encrypt_message)
encrypt_button.grid(row=6, column=0, padx=10, pady=10)

decrypt_button = tk.Button(root, text="Decryption", command=decrypt_message)
decrypt_button.grid(row=6, column=1, padx=10, pady=10)

root.mainloop()