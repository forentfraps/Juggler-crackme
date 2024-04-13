from Crypto.Cipher import AES

key = [67, 129, 131, 129, 131, 129, 131, 129, 131, 129, 131, 129, 131, 129, 131, 129]



def sieve_of_eratosthenes(n):
    primes = [True] * (n+1)
    p = 2
    while (p * p <= n):
        if (primes[p] == True):
            for i in range(p * p, n+1, p):
                primes[i] = False
        p += 1
    prime_numbers = [p for p in range(2, n+1) if primes[p]]
    return prime_numbers

if __name__=="__main__":
    print("Starting Encryption")
    with open("mod2_nocrt.dll", "rb") as f:
        data = f.read()
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    t = print(list(cipher.encrypt(bytes(([0] * 16)))))
    pad_len = len(data) // 16 * 16 + 16 - len(data)
    data = data + b'0' * pad_len
    print(len(data)//16)
    indexes_to_encrypt = sieve_of_eratosthenes(len(data) // 16)
    indexes_to_encrypt = set(indexes_to_encrypt)
    print(len(indexes_to_encrypt))
    with open("mod2.dll.enc", "wb") as f:
        for i in range(0, len(data), 16):
            f.write(cipher.encrypt(data[i:i+16]))

    print("Finished Encrypting")


