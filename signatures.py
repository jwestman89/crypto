#signatures.py

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def generate_keys():
    private = rsa.generate_private_key(public_exponent=65537,key_size=512,)
    public = private.public_key()
    return private, public

def sign(message, private_key):
    _sig = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    return _sig

def verify(message, sig, public):
    try:
        public.verify(
        sig,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
        )
    except InvalidSignature:
        return False
    except Exception as e:
        print(e)
    return True

def is_correct(check):
    if check:
        print("Success")
    else:
        print("Failed")

if __name__ == '__main__':
    pr,pu = generate_keys()
    pr2,pu2 = generate_keys()

    message = b'Secret message'
    message2 = b'Fake Message'

    sig = sign(message, pr)
    fake_sig = sign(message,pr2)

    print("Verifying message with real signature and public key")
    is_correct(verify(message,sig,pu))

    print("Verifying message with a fake signature")
    is_correct(verify(message, fake_sig, pu))

    print("Verifying message with wrong public key")
    is_correct(verify(message, sig, pu2))

    print("Verifying the wrong message")
    is_correct(verify(message2, sig, pu))