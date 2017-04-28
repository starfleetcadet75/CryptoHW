import base64
import bcrypt
import binascii
from OpenSSL import crypto
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC
from Cryptodome.Util import Padding
from Cryptodome import Random

# hash function using SHA256
def hash(data):
    h = SHA256.new()
    h.update(data)
    return h.hexdigest()

# generate new salt value
def gen_salt():
    return bcrypt.gensalt()

# generates pub/priv key pair for RSA
def generate_rsa_keys(n=2048):
    new_key = RSA.generate(n, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")
    return public_key, private_key

# encryption function using RSA+OAEP
def rsa_encrypt(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    message = message.encode('hex')
    return base64.b64encode(cipher.encrypt(message))

# decryption function using RSA+OAEP
def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    ciphertext = base64.b64decode(ciphertext)
    return cipher.decrypt(ciphertext).decode('hex')

# generate key to be used for private key encryption
def generate_symmetric_key(n=1024):
    return hash(Random.new().read(n))[:24].encode('utf-8')

# uses AES in CBC mode with HMAC-SHA256 to perform authenticated encryption
def authenticated_encrypt(aes_key, hmac_key, data):
    data = Padding.pad(data, AES.block_size, style='pkcs7')

    iv = Random.new().read(AES.block_size)  # create random IV
    ciphertext = iv + AES.new(aes_key, AES.MODE_CBC, iv).encrypt(data.encode('utf-8'))  # encrypt the data using AES in CBC

    # tag the encrypted data using HMAC-SHA256
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(ciphertext)
    tag = hmac.hexdigest()

    return base64.b64encode(ciphertext + tag)

# uses AES in CBC mode with HMAC-SHA256 to perform authenticated decryption
def authenticated_decrypt(aes_key, hmac_key, data):
    data = base64.b64decode(data)
    tag = data[-64:]
    data = data[:-64]

    # verify the HMAC tag
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(data)

    if tag != hmac.hexdigest():
        raise AuthenticationError("failure")

    # decrypt the data using AES
    data = AES.new(aes_key, AES.MODE_CBC, data[:AES.block_size]).decrypt(data[AES.block_size:])
    return Padding.unpad(data, AES.block_size, style='pkcs7')

class AuthenticationError(Exception): pass
