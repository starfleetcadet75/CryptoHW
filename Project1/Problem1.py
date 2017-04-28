from Crypto.Cipher import AES
from Crypto import Random
import Crypto.Util.Counter

def padMessage(message, blockSize):
    pad = (blockSize - (len(message) % blockSize))
    return message + chr(pad) * pad

class Counter():
    def __init__(self, value):
        self.value = value

    def increment(self):
        return self.value

    def __repr__(self):
        return self.value

def encrypt(plaintext, key, mode, iv):
    if mode == AES.MODE_CBC:
        assert iv != None
        block = list(ord(b) for b in iv)

        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = bytearray(plaintext)
        plaintext = [plaintext[i:i+AES.block_size] for i in range(0, len(plaintext), AES.block_size)]
        ciphertext = [iv]

        for i in range(len(plaintext)):
            block = [(x ^ y) for (x, y) in zip(plaintext[i], block)]
            block = "".join(chr(b) for b in block)
            block = cipher.encrypt(block)
            ciphertext.append(block)
        return ciphertext
    elif mode == AES.MODE_CTR:
        cipher = AES.new(key, AES.MODE_ECB)
        counter = Counter(iv)
        plaintext = bytearray(plaintext)
        plaintext = [plaintext[i:i+AES.block_size] for i in range(0, len(plaintext), AES.block_size)]
        ciphertext = [iv]

        for i in range(len(plaintext)):
            block = cipher.encrypt(str(counter))
            counter.increment()
            block = list(ord(b) for b in block)
            block = [(x ^ y) for (x, y) in zip(plaintext[i], block)]
            ciphertext.append(block)
        return ciphertext

def decrypt(ciphertext, key, mode, iv=None):
    if mode == AES.MODE_CBC:
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = []

        for i in range(1, len(ciphertext)):
            block = cipher.decrypt(ciphertext[i])
            block = list(ord(c) for c in block)
            plaintext.append([(x ^ y) for (x, y) in zip(block, list(ord(c) for c in ciphertext[i-1]))])

        p = ""
        for s in range(len(plaintext)):
            p += "".join(chr(b) for b in plaintext[s])
        return p
    elif mode == AES.MODE_CTR:
        cipher = AES.new(key, AES.MODE_ECB)
        counter = Counter(ciphertext[0])
        plaintext = []

        for i in range(1, len(ciphertext)):
            block = cipher.encrypt(str(counter))
            counter.increment()
            block = list(ord(b) for b in block)
            block = [(x ^ y) for (x, y) in zip(ciphertext[i], block)]
            plaintext.append(block)

        p = ""
        for s in range(len(plaintext)):
            p += "".join(chr(b) for b in plaintext[s])
        return p

if __name__ == '__main__':
    iv = Random.new().read(AES.block_size)
    key = Random.new().read(AES.block_size)
    message = padMessage("Test message", AES.block_size)

    # CBC mode for part (a)
    ciphertext = iv + AES.new(key, AES.MODE_CBC, iv).encrypt(message)
    decryption = AES.new(key, AES.MODE_CBC, ciphertext[:16]).decrypt(ciphertext[16:])
    assert decryption == message

    # CBC mode for part (b)
    ciphertext = encrypt(message, key, AES.MODE_CBC, iv)
    assert message == decrypt(ciphertext, key, AES.MODE_CBC)

    # CTR mode for part (a)
    ciphertext = AES.new(key, AES.MODE_CTR, counter=Crypto.Util.Counter.new(128, initial_value=long(iv.encode("hex"), 16))).encrypt(message)
    decryption = AES.new(key, AES.MODE_CTR, counter=Crypto.Util.Counter.new(128, initial_value=long(iv.encode("hex"), 16))).decrypt(ciphertext)
    assert decryption == message

    # CTR mode for part (b)
    ciphertext = encrypt(message, key, AES.MODE_CTR, iv)
    assert message == decrypt(ciphertext, key, AES.MODE_CTR, iv)

    # Part (c)
    for _ in range(10):
        key = Random.new().read(AES.block_size)
        message = Random.new().read(AES.block_size)

        ciphertext1 = iv + AES.new(key, AES.MODE_CBC, iv).encrypt(message)
        ciphertext2 = encrypt(message, key, AES.MODE_CBC, iv)
        assert AES.new(key, AES.MODE_CBC, ciphertext1[:16]).decrypt(ciphertext1[16:]) == decrypt(ciphertext2, key, AES.MODE_CBC)

        ciphertext1 = AES.new(key, AES.MODE_CTR, counter=Crypto.Util.Counter.new(128, initial_value=long(iv.encode("hex"), 16))).encrypt(message)
        ciphertext2 = encrypt(message, key, AES.MODE_CTR, iv)
        assert AES.new(key, AES.MODE_CTR, counter=Crypto.Util.Counter.new(128, initial_value=long(iv.encode("hex"), 16))).decrypt(ciphertext1) == decrypt(ciphertext2, key, AES.MODE_CTR, iv)
