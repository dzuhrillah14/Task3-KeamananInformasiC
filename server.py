import socket
import json
from des_rsa import des_process, rsa_decrypt

def server():
    # 1. SETUP KUNCI RSA SERVER (Statik untuk demo)
    # p=61, q=53 -> n=3233, e=17, d=2753
    public_key = (17, 3233)
    private_key = (2753, 3233)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 12345))
    s.listen(1)
    print("=============================================")
    print("      SERVER (DEVICE 2) - RSA READY          ")
    print("=============================================")
    conn, addr = s.accept()

    # 2. PROSES DISTRIBUSI KUNCI (HANDSHAKE)
    print("\n[STEP 1] Mengirim Public Key RSA ke Client...")
    conn.send(json.dumps(public_key).encode())

    print("[STEP 2] Menunggu Secret Key DES dari Client (Terenkripsi)...")
    enc_key_data = json.loads(conn.recv(4096).decode())
    
    # Dekripsi kunci DES menggunakan Private Key RSA milik Server
    shared_key = rsa_decrypt(enc_key_data, private_key)
    print(f"[*] Berhasil Mendapatkan Secret Key DES: {shared_key}")
    print("\n--- SALURAN KOMUNIKASI AMAN DIMULAI ---")

    # 3. PROSES CHAT DES
    while True:
        data = conn.recv(1024).decode('utf-8')
        if not data: break
        
        print(f"\n[NOTIFIKASI] Pesan masuk (HEX): {data}")
        cipher_input = input("Masukkan Ciphertext (HEX) untuk proses dekripsi: ")
        
        if cipher_input.upper() == data.upper():
            dec_hex = des_process(cipher_input, shared_key, 'decrypt')
            try:
                dec_text = bytes.fromhex(dec_hex).decode('utf-8').strip()
                print(f"\n--- HASIL DEKRIPSI ---")
                print(f"Pesan asli ditemukan: '{dec_text}'")
                print(f"Hexadecimal asli    : {dec_hex}")
                print("-" * 22)
            except:
                print(f"\nDecrypted (hex): {dec_hex}")
        else:
            print("Error: HEX tidak sesuai!")

        msg_reply = input("\nBalas pesan ke Client (8 char): ").ljust(8)[:8]
        reply_hex = msg_reply.encode('utf-8').hex()
        cipher_reply = des_process(reply_hex, shared_key, 'encrypt')
        conn.send(cipher_reply.encode('utf-8'))

    conn.close()

if __name__ == "__main__": server()
