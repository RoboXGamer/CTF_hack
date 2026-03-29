import random
import requests
from Crypto.Util.number import long_to_bytes, inverse, isPrime
import math

# --- Provided Challenge Data ---
n = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007
e = 65537
c1 = 15334857637284957398475938475938475938475938475938
c2 = 15334857637284957398475938475938475938475938475939
c3 = 15334857637284957398475938475938475938475938475940
hint = 1337
ciphertexts = [c1, c2, c3]

def decrypt_flag(p, q):
    """Decrypts the ciphertexts using the recovered primes."""
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    
    flag = b""
    for c in ciphertexts:
        m = pow(c, d, n)
        flag += long_to_bytes(m)
    
    print(f"\n[+] Success! Decrypted Flag: {flag.decode(errors='ignore')}")
    return True

def attack_factordb(n):
    """Checks if n has already been factored and indexed online."""
    print("[*] Checking FactorDB...")
    try:
        res = requests.get(f"http://factordb.com/api?query={n}").json()
        if res.get('status') == 'FF':
            factors = res.get('factors')
            p = int(factors[0][0])
            q = int(factors[1][0])
            print("[+] Factors found on FactorDB!")
            decrypt_flag(p, q)
            return True
    except Exception as err:
        print(f"[-] FactorDB check failed: {err}")
    return False

def fermat_factorization(n):
    """Attacks n if p and q are too close to each other (performance optimization)."""
    print("[*] Attempting Fermat's Factorization...")
    a = math.isqrt(n)
    b2 = a*a - n
    b = math.isqrt(b2)
    count = 0
    
    while b*b != b2:
        a += 1
        b2 = a*a - n
        b = math.isqrt(b2)
        count += 1
        if count > 1000000: # Limit iterations
            return False
            
    p = a + b
    q = a - b
    print(f"[+] Fermat's Factorization successful!")
    decrypt_flag(p, q)
    return True

def attack_seeded_prng():
    """Simulates a naive prime generation script seeded with the hint."""
    print(f"[*] Testing Python random seeded with hint: {hint}...")
    random.seed(hint)
    
    # Simulate generating two 512-bit primes
    def get_prime(bits=512):
        while True:
            # Generate a random odd number of given bit length
            num = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if isPrime(num):
                return num
                
    p = get_prime()
    q = get_prime()
    
    if p * q == n:
        print("[+] Seeded PRNG attack successful! Primes recovered.")
        decrypt_flag(p, q)
        return True
    return False

# --- Run Attacks ---
if not attack_factordb(n):
    if not attack_seeded_prng():
        if not fermat_factorization(n):
            print("[-] Standard quick attacks failed. The p XOR q anomaly might require a custom branch-and-prune script.")