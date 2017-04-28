import json
from pwn import *
from util import *

class Client:
    def __init__(self):
        self.username = "test"
        self.master_password = "password"

        keys = generate_rsa_keys()
        self.public_key = RSA.importKey(keys[0])
        self.private_key = RSA.importKey(keys[1])
        self.server_public_key = None
        self.connection = remote('localhost', 8888)
        self.recv()

    def send(self, data):
        try:
            self.connection.sendline(base64.b64encode(json.dumps(data)))
        except:
            print("Error occurred on the server")

    def recv(self):
        try:
            data = json.loads(base64.b64decode(self.connection.recvline()))
            print("Client Recieved: " + str(data))
        except:
            print("Error occurred on the server")
        return data

    def create_account(self):
        self.send({'create_account': self.username})

        data = self.recv()
        certificate = data['certificate']
        self.server_public_key = RSA.importKey(certificate)
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)

        trusted_ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open('cacert.pem', 'r').read())
        store = crypto.X509Store()
        store.add_cert(trusted_ca_cert)
        store_ctx = crypto.X509StoreContext(store, certificate)

        if store_ctx == None:
            self.send({'message': 'CA could not verify this cert'})
            return

        self.send({'message': 'CA has verified this cert'})

        # create and send the master password encrypted using server's public key
        ciphertext = rsa_encrypt(self.server_public_key, self.master_password)
        self.send({'master_password': ciphertext})
        self.recv()

    def add(self, website, password):
        self.authenticate()
        message = {'website': website, 'password': password}
        ciphertext = rsa_encrypt(self.server_public_key, json.dumps(message))
        self.send({'add': ciphertext})
        self.recv()

    def update(self, website, password):
        self.authenticate()
        message = {'website': website, 'password': password}
        ciphertext = rsa_encrypt(self.server_public_key, json.dumps(message))
        self.send({'update': ciphertext})
        self.recv()

    def read(self, website):
        self.authenticate()
        message = {'website': website}
        ciphertext = rsa_encrypt(self.server_public_key, json.dumps(message))
        self.send({'read': ciphertext})
        self.recv()

    def remove(self, website):
        self.authenticate()
        message = {'website': website}
        ciphertext = rsa_encrypt(self.server_public_key, json.dumps(message))
        self.send({'remove': ciphertext})
        self.recv()

    def change_master_password(self, new_master_password):
        self.authenticate()
        ciphertext = rsa_encrypt(self.server_public_key, new_master_password)
        self.send({'change_master_password': ciphertext})
        self.recv()

    def authenticate(self):
        self.send({'authenticate': self.username})
        data = self.recv()

        if self.server_public_key != RSA.importKey(data['certificate']):
            return

        data = self.recv()
        nonce = data['nonce']
        ciphertext = rsa_encrypt(self.server_public_key, nonce + self.master_password)
        self.send({'master_password': ciphertext})

    def logout(self):
        self.send({'logout': ''})
        self.recv()
        self.connection.close()

if __name__ == "__main__":
    client = Client()
    client.create_account()
    client.add('www.gmail.com', 'gmailpassword')
    client.add('www.bankofamerica.com', 'bankofamericapassword')
    client.add('www.reddit.com', 'redditpassword')
    client.update('www.bankofamerica.com', 'bankofamericapassword')
    client.read('www.bankofamerica.com')
    client.remove('www.bankofamerica.com')
    client.change_master_password('newmasterpassword')
    client.logout()
