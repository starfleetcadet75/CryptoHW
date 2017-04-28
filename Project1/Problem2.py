import struct
from Crypto.Cipher import AES
from Crypto import Random

numberOfQueries = 0

def padMessage(message, blockSize):
    pad = (blockSize - (len(message) % blockSize))
    return message + chr(pad) * pad

def encrypt(plaintext, key, iv):
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)

def decrypt(ciphertext, key):
    return AES.new(key, AES.MODE_CBC, ciphertext[:16]).decrypt(ciphertext[16:])

# Returns 1 when the ciphertext is properly formatted
def paddingOracle(ciphertext, key):
    global numberOfQueries
    numberOfQueries += 1
    message = decrypt(str(ciphertext), key)  # Decrypt the ciphertext
    b = struct.unpack("B", message[-1])[0]  # Read the value b of the final byte in the encoded data
    return (message[-b:] == struct.pack("B", b) * b)  # Returns whether the last b bytes have the same b value

# Determines the padding b of the ciphertext
def findPadSize(ciphertext):
    byte = AES.block_size  # First byte of ciphertext starts after the IV block
    previousValue = ciphertext[byte]  # Save the previous byte to be restored
    ciphertext[byte] = 0x00  # Init the test value

    searching = True
    while searching:
        if paddingOracle(ciphertext, key):  # Try modifying the next byte of the ciphertext
            print "Padding oracle did not give an error. Continuing to search."
            ciphertext[byte] = previousValue
            byte += 1
            previousValue = ciphertext[byte]
            ciphertext[byte] = 0x00
        else:  # Not valid padding, therefore b has been identified
            print "Padding oracle responded with an error"
            ciphertext[byte] = previousValue
            searching = False

    return AES.block_size - (byte % AES.block_size)  # The determined value of b

# Changes the padding of the ciphertext to the new padding value
def modifyPadding(startPosition, pad):
    for _ in range(pad):
        ciphertext[startPosition] = ciphertext[startPosition] ^ pad ^ (pad + 1)
        startPosition -= 1
    return ciphertext

# Brute forces the plaintext from the last byte of the ciphertext
def findNextPlaintext(ciphertext, startPosition, pad):
    byte = startPosition
    testValue = 0x00
    previousValue = ciphertext[byte]  # Save the previous value
    ciphertext[byte] = testValue  # Set the value to the initial test value

    while True:
        if paddingOracle(ciphertext, key):  # The padding is correct
            return hex((pad + 1) ^ testValue ^ previousValue)
        else:  # Continue searching with the next test value
            testValue += 1
            ciphertext[byte] = testValue

if __name__ == '__main__':
    # Init test values
    iv = Random.new().read(AES.block_size)
    key = Random.new().read(AES.block_size)
    message = padMessage("123456789abcdef0123456789abcde", AES.block_size)

    # Create the AES cipher to be used
    ciphertext = encrypt(message, key, iv)
    ciphertext = bytearray(ciphertext)

    b = findPadSize(ciphertext)
    print "Value of b is: " + str(b)

    print "\nRecovering plaintext in hex from the last block:"
    startPosition = 29
    for _ in range(AES.block_size - b):
        ciphertext = modifyPadding(len(ciphertext) - (AES.block_size + 1), b)
        print findNextPlaintext(ciphertext, startPosition, b)
        startPosition -= 1
        b += 1

    print "Total Number of Oracle Queries: " + str(numberOfQueries)
