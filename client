import socket
import json
import random
from des_rsa import des_process, rsa_encrypt

def generate_random_des_key():
    # Membuat 16 karakter hexadecimal acak (64-bit key)
    return ''.join(random.choice('0123456789ABCDEF') for _ in range(16))

def client():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 12345))
    print("=============================================")
    print("      CLIENT (DEVICE 1) - RSA HANDSHAKE      ")
    print("=============================================")

    # 1. PROSES DISTRIBUSI KUNCI
    print("\n[STEP 1] Menerima Public Key RSA dari Server...")
    pub_key_data = s.recv(1024).decode()
    public_key = json.loads(pub_key_data)
    print(f"[*] Public Key Diterima: {public_key}")

    print("[STEP 2] Membuat Secret Key DES baru secara acak...")
    shared_key = generate_random_des_key()
    print(f"[*] Kunci DES yang akan digunakan: {shared_key}")

    print("[STEP 3] Mengenkripsi Kunci DES dengan Public Key Server...")
    enc_shared_key = rsa_encrypt(shared_key, public_key)
    
    # Kirim kunci DES yang sudah terenkripsi RSA ke Server
    s.send(json.dumps(enc_shared_key).encode())
    print("[*] Kunci DES Terenkripsi telah dikirim.")
    print("\n--- SALURAN KOMUNIKASI AMAN DIMULAI ---")

    # 2. PROSES CHAT DES 
    while True:
        user_input = input("\nMasukkan pesan untuk dikirim (8 char): ")
        original_text = user_input.ljust(8)[:8]
        original_hex = original_text.encode('utf-8').hex()
        
        cipher_hex = des_process(original_hex, shared_key, 'encrypt')
        print(f"\n--- HASIL ENKRIPSI ---")
        print(f"Ciphertext (HEX): {cipher_hex}")
        
        s.send(cipher_hex.encode('utf-8'))

        reply_data = s.recv(1024).decode('utf-8')
        print(f"\n[NOTIFIKASI] Balasan masuk (HEX): {reply_data}")
        cipher_reply_input = input("Masukkan Ciphertext (HEX) balasan untuk dekripsi: ")
        
        if cipher_reply_input.upper() == reply_data.upper():
            dec_hex = des_process(cipher_reply_input, shared_key, 'decrypt')
            dec_text = bytes.fromhex(dec_hex).decode('utf-8').strip()
            print(f"--- HASIL DEKRIPSI BALASAN: '{dec_text}' ---")

    s.close()

if __name__ == "__main__": client()
