# CTF Writeup: RSA Common Factor

**Challenge Name:** RSA Common Factor
**Category:** Crypto / RSA
**Flag Format:** MythX{...}

### Challenge Description

Given two RSA public keys (n1, n2) and a ciphertext encrypted with the first key, recover the plaintext/flag. The keys are from a shared-generation environment, so shared prime factors are suspected.

---

### Solution

#### Step 1: Analyze Provided Data

- Two RSA modulus values (`n1`, `n2`) and public exponent `e` were provided.
- Ciphertext `c` encrypted with public key 1.

#### Step 2: Check for Weak Key Generation (GCD)

- Compute `g = gcd(n1, n2)`.
- If `g` > 1 and `< n1`, then `g` is a shared prime factor (`p`).
- This indicates both keys share `p`, which breaks RSA security.

#### Step 3: Factor n1

- `p = g`.
- `q = n1 // p`.

#### Step 4: Compute Private Key

- Compute $(n1) = (p - 1)(q - 1)$.
- Compute private exponent `d = e^{-1} mod (n1)`.

#### Step 5: Decrypt Ciphertext

- Compute plaintext as `m = pow(c, d, n1)`.
- Decode the plaintext message to get flag text.

---

### Conclusion

This challenge demonstrates the RSA common prime vulnerability. Shared factors between moduli allow recovery of private keys and decryption of ciphertexts. The flag is recovered once plaintext is decoded.

---

### Tools Used

- Python (math and Crypto utilities)
- GCD factoring via Python `math.gcd`
- RSA decryption via modular exponentiation
