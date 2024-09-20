import tkinter as tk
from tkinter import messagebox
import numpy as np

def vigenere_encrypt(plain_text, key):
    key = (key * (len(plain_text) // len(key))) + key[:len(plain_text) % len(key)]
    cipher_text = []
    for p, k in zip(plain_text, key):
        if p.isalpha():
            shift = (ord(p.upper()) + ord(k.upper())) % 26
            cipher_text.append(chr(shift + 65))
        else:
            cipher_text.append(p)
    return ''.join(cipher_text)

def vigenere_decrypt(cipher_text, key):
    key = (key * (len(cipher_text) // len(key))) + key[:len(cipher_text) % len(key)]
    plain_text = []
    for c, k in zip(cipher_text, key):
        if c.isalpha():
            shift = (ord(c.upper()) - ord(k.upper())) % 26
            plain_text.append(chr(shift + 65))
        else:
            plain_text.append(c)
    return ''.join(plain_text)

def create_playfair_matrix(key):
    key = ''.join(sorted(set(key), key=key.index))
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in key:
            key += char
    return [key[i:i + 5] for i in range(0, len(key), 5)]

def find_position(matrix, char):
    for row in range(len(matrix)):
        for col in range(len(matrix[row])):
            if matrix[row][col] == char:
                return row, col
    return None

def playfair_encrypt(plain_text, key):
    matrix = create_playfair_matrix(key)
    plain_text = ''.join(filter(str.isalpha, plain_text.upper().replace('J', 'I')))
    if len(plain_text) % 2 != 0:
        plain_text += 'X'
    pairs = [plain_text[i:i + 2] for i in range(0, len(plain_text), 2)]
    
    cipher_text = []
    for a, b in pairs:
        row_a, col_a = find_position(matrix, a)
        row_b, col_b = find_position(matrix, b)

        if row_a == row_b:
            cipher_text.append(matrix[row_a][(col_a + 1) % 5])
            cipher_text.append(matrix[row_b][(col_b + 1) % 5])
        elif col_a == col_b:
            cipher_text.append(matrix[(row_a + 1) % 5][col_a])
            cipher_text.append(matrix[(row_b + 1) % 5][col_b])
        else:
            cipher_text.append(matrix[row_a][col_b])
            cipher_text.append(matrix[row_b][col_a])

    return ''.join(cipher_text)

def playfair_decrypt(cipher_text, key):
    matrix = create_playfair_matrix(key)
    pairs = [cipher_text[i:i + 2] for i in range(0, len(cipher_text), 2)]
    
    plain_text = []
    for a, b in pairs:
        row_a, col_a = find_position(matrix, a)
        row_b, col_b = find_position(matrix, b)

        if row_a == row_b:
            plain_text.append(matrix[row_a][(col_a - 1) % 5])
            plain_text.append(matrix[row_b][(col_b - 1) % 5])
        elif col_a == col_b:
            plain_text.append(matrix[(row_a - 1) % 5][col_a])
            plain_text.append(matrix[(row_b - 1) % 5][col_b])
        else:
            plain_text.append(matrix[row_a][col_b])
            plain_text.append(matrix[row_b][col_a])

    return ''.join(plain_text)

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def hill_encrypt(text, key):
    key_matrix = np.array([[ord(key[0]) - 65, ord(key[1]) - 65],
                           [ord(key[2]) - 65, ord(key[3]) - 65]])
    
    text = ''.join(filter(str.isalpha, text)).upper()
    if len(text) % 2 != 0:
        text += 'X'

    text_matrix = np.array([[ord(text[i]) - 65, ord(text[i + 1]) - 65] for i in range(0, len(text), 2)])
    result_matrix = (text_matrix.dot(key_matrix)) % 26
    cipher_text = ''.join([chr(num + 65) for row in result_matrix for num in row])
    return cipher_text

def hill_decrypt(cipher_text, key):
    key_matrix = np.array([[ord(key[0]) - 65, ord(key[1]) - 65],
                           [ord(key[2]) - 65, ord(key[3]) - 65]])
    
    det = int(np.round(np.linalg.det(key_matrix))) % 26
    inv_det = mod_inverse(det, 26)
    if inv_det is None:
        raise ValueError("Matrix is not invertible.")

    # Calculate the inverse of the key matrix
    key_matrix_inv = np.round(inv_det * np.linalg.inv(key_matrix)).astype(int) % 26
    
    cipher_text = ''.join(filter(str.isalpha, cipher_text)).upper()
    text_matrix = np.array([[ord(cipher_text[i]) - 65, ord(cipher_text[i + 1]) - 65] for i in range(0, len(cipher_text), 2)])
    
    result_matrix = (text_matrix.dot(key_matrix_inv)) % 26
    plain_text = ''.join([chr(num + 65) for row in result_matrix for num in row])
    return plain_text

class CipherApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Cipher Program")

        self.cipher_var = tk.StringVar(value="Vigenere")
        self.input_text = tk.StringVar()
        self.key = tk.StringVar()
        self.output_text = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.master, text="Choose Cipher:").pack()

        tk.Radiobutton(self.master, text="Vigenere", variable=self.cipher_var, value="Vigenere").pack()
        tk.Radiobutton(self.master, text="Playfair", variable=self.cipher_var, value="Playfair").pack()
        tk.Radiobutton(self.master, text="Hill", variable=self.cipher_var, value="Hill").pack()

        tk.Label(self.master, text="Input Text:").pack()
        tk.Entry(self.master, textvariable=self.input_text, width=50).pack()

        tk.Label(self.master, text="Key (12+ for others, 4 for Hill):").pack()
        tk.Entry(self.master, textvariable=self.key, width=50).pack()

        tk.Button(self.master, text="Encrypt", command=self.encrypt).pack()
        tk.Button(self.master, text="Decrypt", command=self.decrypt).pack()

        tk.Label(self.master, text="Output:").pack()
        tk.Entry(self.master, textvariable=self.output_text, width=50).pack()

    def encrypt(self):
        text = self.input_text.get()
        key = self.key.get()

        if self.cipher_var.get() == "Hill" and len(key) != 4:
            messagebox.showerror("Error", "Hill key must be exactly 4 characters long.")
            return
        elif self.cipher_var.get() != "Hill" and len(key) < 12:
            messagebox.showerror("Error", "Key must be at least 12 characters long.")
            return

        if self.cipher_var.get() == "Vigenere":
            result = vigenere_encrypt(text, key)
        elif self.cipher_var.get() == "Playfair":
            result = playfair_encrypt(text, key)
        elif self.cipher_var.get() == "Hill":
            result = hill_encrypt(text, key)
        else:
            result = ""

        self.output_text.set(result)

    def decrypt(self):
        text = self.output_text.get()  # Menggunakan hasil dari enkripsi
        key = self.key.get()

        if self.cipher_var.get() == "Hill" and len(key) != 4:
            messagebox.showerror("Error", "Hill key must be exactly 4 characters long.")
            return
        elif self.cipher_var.get() != "Hill" and len(key) < 12:
            messagebox.showerror("Error", "Key must be at least 12 characters long.")
            return

        if self.cipher_var.get() == "Vigenere":
            result = vigenere_decrypt(text, key)
        elif self.cipher_var.get() == "Playfair":
            result = playfair_decrypt(text, key)
        elif self.cipher_var.get() == "Hill":
            result = hill_decrypt(text, key)
        else:
            result = ""

        self.output_text.set(result)

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()
