import math
import random

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n as 2^r * d + 1
    r=0
    d=n-1
    while d % 2 == 0:
        r += 1
        d = d//2   # floor division
    
    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)         # a^d mod n
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)  
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits=1024):
    while True:
        # Generate a random odd number with specified bit length
        p = random.getrandbits(bits)
        # Make sure it's odd
        p |= (1 << bits - 1) | 1   
        if is_prime(p):
            return p

def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find gcd and coefficients"""
    if a == 0:
        return b, 0, 1          # ax+by = gcd(a,b)
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def mod_inverse(e, phi):
    """Find modular multiplicative inverse of e under modulo phi"""
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % phi

def generate_keypair(bits=1024):
    """Generate RSA public and private key pair"""
    # Generate two distinct large prime numbers
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    while p == q:
        q = generate_large_prime(bits // 2)
    
    # Calculate n and phi
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = 65537  # Common choice, known to be prime and efficient
    while math.gcd(e, phi) != 1:
        e += 2
    
    # Calculate d, the modular multiplicative inverse of e (mod phi)
    d = mod_inverse(e, phi)
    
    # Return public key (e, n) and private key (d, n)
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    """Encrypt data using public key"""
    e, n = public_key
    # Convert plaintext to bytes if it's a string
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    # Break plaintext into blocks to prevent integer overflow
    block_size = n.bit_length() // 16  # Block size in bytes
    blocks = [plaintext[i:i+block_size] for i in range(0, len(plaintext), block_size)]
    
    encrypted_blocks = []
    for block in blocks:
        # Convert block to integer
        m = int.from_bytes(block, byteorder='big')
        # Ensure m is less than n
        if m >= n:
            raise ValueError("Message too large for the key size")
        # Apply RSA encryption: c = m^e mod n
        c = pow(m, e, n)
        encrypted_blocks.append(c)
    
    return encrypted_blocks

def decrypt(private_key, encrypted_blocks):
    """Decrypt data using private key"""
    d, n = private_key
    
    decrypted_data = bytearray()
    for c in encrypted_blocks:
        # Apply RSA decryption: m = c^d mod n
        m = pow(c, d, n)
        # Calculate bytes needed to represent this number
        bytes_needed = (m.bit_length() + 7) // 8
        # Convert integer back to bytes
        block = m.to_bytes(bytes_needed, byteorder='big')
        decrypted_data.extend(block)
    
    return bytes(decrypted_data)