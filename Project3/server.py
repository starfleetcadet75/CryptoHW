import json
from pwn import *
from util import *

class Account:
    def __init__(self, ):
        self.username = None
        self.salt_a = None
        self.salt_e = None
        self.salt_h = None
        self.password = None
        self.aes_key = None
        self.hmac_key = None
        self.table = {}

class Server:
    def __init__(self):
        self.certificate = open('server_pub.pem', 'r').read()
        self.public_key = RSA.importKey(self.certificate)
        self.private_key = RSA.importKey(open('server_priv.pem', 'rt').read())

        self.connection = None
        self.accounts = {}

    def send(self, data):
        try:
            self.connection.sendline(base64.b64encode(json.dumps(data)))
        except:
            print("Error occurred on the client")

    def recv(self):
        try:
            data = json.loads(base64.b64decode(self.connection.recvline()))
            print("Server Recieved: " + str(data))
        except:
            print("Error occurred on the client")

        return data

    def create_account(self, data):
        username = data['create_account']
        if username in self.accounts:
            self.send({'message', 'username already exists'})
            return

        self.send({'certificate': self.certificate})

        data = self.recv()
        data = self.recv()
        master_password = data['master_password']
        master_password = rsa_decrypt(self.private_key, master_password)

        # generate salts
        salt_a = gen_salt()
        salt_e = gen_salt()
        salt_h = gen_salt()

        key_e = hash(salt_e + master_password)[:24].encode('utf-8')  # AES-CBC key for AE
        key_h = hash(salt_h + master_password)[:24].encode('utf-8')  # HMAC-SHA256 key for AE

        aes_key = generate_symmetric_key()  # key for AES-CBC
        hmac_key = generate_symmetric_key()  # key for HMAC-SHA256

        aes_key = authenticated_encrypt(key_e, key_h, aes_key)  # encrypt the AES-CBC key under AE
        hmac_key = authenticated_encrypt(key_e, key_h, hmac_key)  # encrypt the HMAC-SHA256 key under AE

        # create account
        account = Account()
        account.username = username
        account.salt_a = salt_a
        account.salt_e = salt_e
        account.salt_h = salt_h
        account.password = hash(salt_a + master_password)
        account.aes_key = aes_key
        account.hmac_key = hmac_key

        self.accounts[username] = account
        self.send({'message': 'new account created'})

    def authenticate(self, data):
        self.send({'certificate': self.certificate})

        username = data['authenticate']
        if username not in self.accounts:
            print("safew")
            self.send({'message', 'username does not exist'})
            return

        nonce = Random.new().read(8).encode('hex')
        self.send({'nonce': nonce})

        data = self.recv()
        master_password = data['master_password']
        master_password = rsa_decrypt(self.private_key, master_password)

        # check the nonce
        if str(nonce) != (master_password[:16]):
            self.send({'message': 'error'})
            return

        master_password = master_password[16:]
        account = self.accounts[username]

        if (hash(account.salt_a + master_password) == account.password):
            return (account.username, master_password)
        else:
            return ()

    def add(self, auth, data):
        account = self.accounts[auth[0]]
        message = data['add']
        message = rsa_decrypt(self.private_key, message)
        message = json.loads(message)

        website_name = message['website']
        website_password = message['password']

        key_e = hash(account.salt_e + auth[1])[:24].encode('utf-8')  # AES-CBC key for AE
        key_h = hash(account.salt_h + auth[1])[:24].encode('utf-8')  # HMAC-SHA256 key for AE

        aes_key = authenticated_decrypt(key_e, key_h, account.aes_key)  # decrypt the AES-CBC key under AE
        hmac_key = authenticated_decrypt(key_e, key_h, account.hmac_key)  # decrypt the HMAC-SHA256 key under AE

        self.accounts[auth[0]].table[website_name] = authenticated_encrypt(aes_key, hmac_key, website_password)
        self.send({'message': 'added website'})

    def update(self, auth, data):
        account = self.accounts[auth[0]]
        message = data['update']
        message = rsa_decrypt(self.private_key, message)
        message = json.loads(message)

        website_name = message['website']
        website_password = message['password']

        key_e = hash(account.salt_e + auth[1])[:24].encode('utf-8')  # AES-CBC key for AE
        key_h = hash(account.salt_h + auth[1])[:24].encode('utf-8')  # HMAC-SHA256 key for AE

        aes_key = authenticated_decrypt(key_e, key_h, account.aes_key)  # decrypt the AES-CBC key under AE
        hmac_key = authenticated_decrypt(key_e, key_h, account.hmac_key)  # decrypt the HMAC-SHA256 key under AE

        self.accounts[auth[0]].table[website_name] = authenticated_encrypt(aes_key, hmac_key, website_password)
        self.send({'message': 'updated website'})

    def read(self, auth, data):
        account = self.accounts[auth[0]]
        message = data['read']
        message = rsa_decrypt(self.private_key, message)
        message = json.loads(message)
        website_name = message['website']

        key_e = hash(account.salt_e + auth[1])[:24].encode('utf-8')  # AES-CBC key for AE
        key_h = hash(account.salt_h + auth[1])[:24].encode('utf-8')  # HMAC-SHA256 key for AE

        aes_key = authenticated_decrypt(key_e, key_h, account.aes_key)  # decrypt the AES-CBC key under AE
        hmac_key = authenticated_decrypt(key_e, key_h, account.hmac_key)  # decrypt the HMAC-SHA256 key under AE

        website_password = self.accounts[auth[0]].table[website_name]
        website_password = authenticated_decrypt(aes_key, hmac_key, website_password)
        self.send({'message': website_password})

    def remove(self, auth, data):
        account = self.accounts[auth[0]]
        message = data['remove']
        message = rsa_decrypt(self.private_key, message)
        message = json.loads(message)
        website_name = message['website']

        key_e = hash(account.salt_e + auth[1])[:24].encode('utf-8')  # AES-CBC key for AE
        key_h = hash(account.salt_h + auth[1])[:24].encode('utf-8')  # HMAC-SHA256 key for AE

        aes_key = authenticated_decrypt(key_e, key_h, account.aes_key)  # decrypt the AES-CBC key under AE
        hmac_key = authenticated_decrypt(key_e, key_h, account.hmac_key)  # decrypt the HMAC-SHA256 key under AE

        self.accounts[auth[0]].table.pop(website_name, 0)
        self.send({'message': 'website removed'})

    def change_master_password(self, auth, data):
        account = self.accounts[auth[0]]
        new_master_password = data['change_master_password']
        new_master_password = rsa_decrypt(self.private_key, new_master_password)

        # decrypt the AE keys
        key_e = hash(account.salt_e + auth[1])[:24].encode('utf-8')  # AES-CBC key for AE
        key_h = hash(account.salt_h + auth[1])[:24].encode('utf-8')  # HMAC-SHA256 key for AE

        aes_key = authenticated_decrypt(key_e, key_h, account.aes_key)  # decrypt the AES-CBC key under AE
        hmac_key = authenticated_decrypt(key_e, key_h, account.hmac_key)  # decrypt the HMAC-SHA256 key under AE

        # generate new salts
        new_salt_a = gen_salt()
        new_salt_e = gen_salt()
        new_salt_h = gen_salt()

        new_key_e = hash(new_salt_e + new_master_password)[:24].encode('utf-8')  # compute new AES-CBC key for AE
        new_key_h = hash(new_salt_h + new_master_password)[:24].encode('utf-8')  # compute new HMAC-SHA256 key for AE

        new_aes_key = authenticated_encrypt(new_key_e, new_key_h, aes_key)  # encrypt the AES-CBC key under AE
        new_hmac_key = authenticated_encrypt(new_key_e, new_key_h, hmac_key)  # encrypt the HMAC-SHA256 key under AE

        # update the account
        account.salt_a = new_salt_a
        account.salt_e = new_salt_e
        account.salt_h = new_salt_h
        account.password = hash(new_salt_a + new_master_password)
        account.aes_key = new_aes_key
        account.hmac_key = new_hmac_key

        self.send({'message': 'master password changed'})

    def run(self):
        self.connection = listen(port=8888, bindaddr='127.0.0.1')
        self.send({'message': '==PasswordManager=='})

        # handle messages from the client
        while True:
            data = self.recv()

            if "create_account" in data:
                self.create_account(data)

            if "authenticate" in data:
                auth = self.authenticate(data)
                if auth == ():
                    break

                data = self.recv()
                if "add" in data:
                    self.add(auth, data)

                if "update" in data:
                    self.update(auth, data)

                if "read" in data:
                    self.read(auth, data)

                if "remove" in data:
                    self.remove(auth, data)

                if "change_master_password" in data:
                    self.change_master_password(auth, data)

            if "logout" in data:
                self.send({'message': 'logging out'})
                break

        self.connection.close()

if __name__ == "__main__":
    server = Server()
    server.run()
