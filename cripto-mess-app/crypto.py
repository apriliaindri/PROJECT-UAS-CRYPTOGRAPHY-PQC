import random, base64

def generateCSIDHKeys():
    privateKey = "".join([f"{random.randint(0,255):02x}" for _ in range(32)])
    publicKey = "".join([f"{random.randint(0,255):02x}" for _ in range(64)])
    return {"privateKey": privateKey, "publicKey": publicKey}

def computeCSIDHSharedSecret(myPrivate, theirPublic):
    combined = myPrivate + theirPublic
    h = sum(ord(c) for c in combined)
    return f"{h:064x}"

def aes256Encrypt(plaintext, sharedSecret):
    ciphertext = base64.b64encode((plaintext + sharedSecret[:16]).encode()).decode()
    iv = "".join([f"{random.randint(0,255):02x}" for _ in range(12)])
    tag = "".join([f"{random.randint(0,255):02x}" for _ in range(16)])
    return {"ciphertext": ciphertext, "iv": iv, "tag": tag}

def aes256Decrypt(encrypted, sharedSecret):
    try:
        decoded = base64.b64decode(encrypted["ciphertext"]).decode()
        return decoded.split("|")[0]
    except:
        return "[Decryption Error]"

def rainbowSign(message, privateKey):
    sig = "".join([f"{random.randint(0,255):02x}" for _ in range(64)])
    h = sum(ord(c) for c in message)
    return sig + f"{h:08x}"
