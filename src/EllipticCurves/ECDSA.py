from ecdsa import SigningKey, VerifyingKey, SECP256k1


def generate_ECDSA_keys(sk_pem_name, vk_pem_name):
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    vk.precompute()

    with open("CryptoKeys/" + sk_pem_name, "wb") as f:
        f.write(sk.to_pem())
    with open("CryptoKeys/" + vk_pem_name, "wb") as f:
        f.write(vk.to_pem())


def sign_message(message, private_pem):
    sk = SigningKey.from_pem(private_pem)
    return sk.sign(message)


def verify_message(message, signature, public_pem):
    with open(public_pem) as f:
        vk = VerifyingKey.from_pem(f.read())
        print()
        assert vk.verify(signature, message)
        return True
    return False
