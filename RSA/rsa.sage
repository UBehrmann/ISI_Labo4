e = 65537


def key_gen():
    print("Generate p")
    p = random_prime(2**1024)
    print("Generate q")
    q = random_prime(2**1024)
    print("Compute n")
    n = p*q
    phi = (p-1)*(q-1)

    d = power_mod(e, -1, phi)

    return d, n


def encrypt(m, n):
    return power_mod(m, e, n)


# TODO : def decrypt(...):


def main():
    d, n = key_gen()

    salary = 200000
    c = encrypt(salary, n)

    # p = decrypt(...)

    print(f"Plaintext:  {salary}")
    print(f"Ciphertext: {c}")
    # assert p == salary, "Decryption failed"


if __name__ == '__main__':
    main()
