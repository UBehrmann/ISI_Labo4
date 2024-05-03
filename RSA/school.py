from Crypto.PublicKey import RSA
import sys


def str_to_int(s):
    return int(s.encode().hex(), 16)


def int_to_str(i):
    hex_string = hex(int(i))[2:]
    if (len(hex_string) % 2) == 1:
        hex_string = '0' + hex_string
    return bytes.fromhex(hex_string).decode('utf-8')


def encode():
    print("\nEnter a word to encode:\n")
    sys.stdout.flush()
    s = input()
    print(str_to_int(s))
    sys.stdout.flush()


def decode():
    print("\nEnter an encoded word to decode:\n")
    sys.stdout.flush()
    i = input()
    print(int_to_str(i))
    sys.stdout.flush()


def verify(word, signature):
    return pow(signature, priv.e, priv.n) == word


def sign(word):
    return pow(word, priv.d, priv.n)


def school():
    print("\nDo you have a signed word from your mother? First enter the plain word: \n")
    sys.stdout.flush()
    word = input()
    print("Now enter the signed word: \n")
    sys.stdout.flush()
    signed = input()
    signature = int(signed)

    print("\nVerifying message with e = %d and n = %d\n" % (pub.e, pub.n))
    sys.stdout.flush()
    if verify(str_to_int(word), signature):
        if word == "sick":
            print("\nSorry to hear that you were sick... Here is a flag for you : 'ISI{m4lL3aB1liTy}'")
            sys.stdout.flush()
        else:
            print("\nSo you were not sick?")
            sys.stdout.flush()
    else:
        print("\nThis word is not from your mother.")
        sys.stdout.flush()


def mom_plain():
    print("\nEnter the plain word you want me to sign:\n")
    sys.stdout.flush()
    word = input()
    if word == "sick":
        print("\nYou were not sick, I will not sign that.")
        sys.stdout.flush()
    else:
        print(sign(str_to_int(word)))
        sys.stdout.flush()


def mom_encoded():
    print("\nEnter the encoded word you want me to sign:\n")
    sys.stdout.flush()
    word = input()
    try:
        if int_to_str(word) == "sick":
            print("\nYou were not sick, I will not sign that.")
            sys.stdout.flush()
            return
    except UnicodeError:
        pass
    print(sign(int(word)))
    sys.stdout.flush()


def menu():
    leave = False
    while not leave:
        print(
            "\nWhat do you want to do?\n1 - Encode a word\n2 - Ask your mom to sign an encoded word for you\n3 - Ask "
            "your mom to sign a plain word for you\n4 - Send signed word to school\n5 - Leave")
        sys.stdout.flush()
        num = int(input())
        if num == 1:
            encode()
        if num == 2:
            mom_encoded()
        if num == 3:
            mom_plain()
        if num == 4:
            school()
        if num == 5:
            leave = True


if __name__ == '__main__':
    global priv
    global pub
    with open('private.pem', 'r') as fk:
        priv = fk.read()
        fk.close()
    with open('public.pem', 'r') as fp:
        pub = fp.read()
        fp.close()
    priv = RSA.importKey(priv)
    pub = RSA.importKey(pub)
    menu()
