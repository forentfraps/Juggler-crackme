from Crypto.Cipher import AES

key = [67, 129, 131, 129, 131, 129, 131, 129, 131, 129, 131, 129, 131, 129, 131, 129]

if __name__=="__main__":
    print("Starting Encryption")
    with open("mod2.dll", "rb") as f:
        data = f.read()
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    pad_len = len(data) // 16 * 16 + 16 - len(data)
    data = data + b'0' * pad_len
    with open("mod2.dll.enc", "wb") as f:
        for i in range(0, len(data), 16):
            f.write(cipher.encrypt(data[i:i+16]))
    print("Finished Encrypting")


