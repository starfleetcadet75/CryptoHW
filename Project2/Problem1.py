#!/usr/bin/python2

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import random
import string
import math

def hash(data):
	h = SHA256.new()
	h.update(data)
	return h.hexdigest()

pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size) 
unpad = lambda s : s[0:-ord(s[-1])]

############## Problem 1 (a) ##############
# Generate prime number of size n bits
def generate_prime(n):
    t = 5
    while True:
        prime = random.randrange(2**(n-1), 2**(n))
        if isPrimeMR(prime, t):
            return prime

# Get number p, test if it's prime using Miller-Rabin
def isPrimeMR(p, t):
    if p % 2 == 0:  # If N is even, return composite
        return False

    # Decompose p
    e = 0
    r = p - 1
    while r % 2 == 0:
        r = r / 2
        e += 1

    for _ in range(t):  # Test t times to find witnesses
        witness = pow(random.randint(2, p - 2), r, p)
        if witness == 1 or witness == p - 1:
            return True

        for _ in range(e):
            witness = pow(witness, 2, p)

            if witness == p - 1:
                return True
    return False

# Primality test using the naive approach
def isPrimeNaive(p):
    for i in range(2, int(math.sqrt(p))+2):
        if p % i == 0:
            return False
    return True

# Test for 10 small numbers, size n = 20 bits
for _ in range(10):
    n = 20
    p = generate_prime(n)
    assert isPrimeNaive(p) is True

############## Problem 1 (b) ##############
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def egcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    return b, x, y

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        return None
    else:
        return x % m

class RSA:
    # Initialize RSA, generate e, d
    def __init__(self, n=1024):
        self.n = n
        self.gen()

    def gen(self):
        self.p = generate_prime(self.n)
        self.q = generate_prime(self.n)
        self.modulus = self.p * self.q  # Generate N = pq
        self.phi = (self.p - 1) * (self.q - 1)  # Get totient of N

        gcd = self.gen_e_value()
        while gcd != 1:  # Ensure the gcd of e and phi is 1
            gcd = self.gen_e_value()
        self.d = modinv(self.e, self.phi)  # Extended Euclid's Algorithm

        print("e: " + str(self.e))
        print("d: " + str(self.d))

    def gen_e_value(self):
        self.e = random.randrange(1, self.phi)  # Generate e that is coprime to phi
        return gcd(self.e, self.phi)

    # F(pk, x) = x^e mod N
    def trapdoor(self, x):
        return pow(x, self.e) % self.modulus

    # F^-1(sk, y) = y^d mod N
    def inverse(self, y):
        return pow(y, self.d) % self.modulus

# Generate random x in Z_N^*
def gen_x_value(modulus):
    x = gcd(random.randrange(1, modulus - 1), modulus)
    while x != 1:
        x = gcd(random.randrange(1, modulus - 1), modulus)
    return x

# Test 10 pairs of (x, y)
rsa = RSA()
for _ in range(10):
    x = gen_x_value(rsa.modulus)
    y = rsa.trapdoor(x)
    assert rsa.inverse(y) == x

############## Problem 1 (c) ##############
class ISO_RSA:
    # Initialize RSA, generate e, d, ISO RSA implementation
    def __init__(self):
        self.k = 128  # security parameter for sauthenticated encryption 
        self.n = 1024  # security parameter for trapdoor
        self.gen()

    def gen(self):
        self.p = generate_prime(self.n)
        self.q = generate_prime(self.n)
        self.modulus = self.p * self.q  # Generate N = pq
        self.phi = (self.p - 1) * (self.q - 1)  # Get totient of N


        gcd = self.gen_e_value()
        while gcd != 1:  # Ensure the gcd of e and phi is 1
            gcd = self.gen_e_value()
        self.d = modinv(self.e, self.phi)  # Extended Euclid's Algorithm

        print("e: " + str(self.e))
        print("d: " + str(self.d))

    def gen_e_value(self):
        self.e = random.randrange(1, self.phi)  # Generate e that is coprime to phi
        return gcd(self.e, self.phi)

    # F(pk, x) = x^e mod N
    def trapdoor(self, x):
        return pow(x, self.e) % self.modulus

    # F^-1(sk, y) = y^d mod N
    def inverse(self, y):
        return pow(y, self.d) % self.modulus

    def encrypt(self, m):
        x = gen_x_value(self.modulus)
        y = self.trapdoor(x)
        k = hash(str(x))
        key = bytes(k)
        c = AES.new(key[:32], AES.MODE_CBC, bytes(b'\0' * 16)).encrypt(pad(m))
        return (y, c)

    def decrypt(self, y, c):
        x = self.inverse(y)
        k = hash(str(x))
        key = bytes(k)
        return unpad(AES.new(key[:32], AES.MODE_CBC, bytes(b'\0' * 16)).decrypt(c))

# test ISO RSA, do it 10 times
# Generate random messages
rsa = ISO_RSA()
for _ in range(10):
    m = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)])
    y, c = rsa.encrypt(m)
    assert rsa.decrypt(y, c) == m
