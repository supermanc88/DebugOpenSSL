# SLH-DSA Digital Signature Algorithm Test Program

This program demonstrates the implementation and usage of SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) using OpenSSL 3.5+.

## Overview

SLH-DSA is a post-quantum digital signature scheme based on the SPHINCS+ algorithm family. It was standardized by NIST as part of the Post-Quantum Cryptography (PQC) standardization process. SLH-DSA is a stateless hash-based signature scheme that provides strong security guarantees against quantum attacks.

### Supported SLH-DSA Variants

This program tests several SLH-DSA parameter sets organized by hash function and optimization:

#### SHA2 Variants
- **SLH-DSA-SHA2-128s**: NIST Security Level 1, small signatures (~7.8KB)
- **SLH-DSA-SHA2-128f**: NIST Security Level 1, fast signing (~17KB)
- **SLH-DSA-SHA2-192s**: NIST Security Level 3, small signatures (~16KB)
- **SLH-DSA-SHA2-192f**: NIST Security Level 3, fast signing (~35KB)
- **SLH-DSA-SHA2-256s**: NIST Security Level 5, small signatures (~29KB)
- **SLH-DSA-SHA2-256f**: NIST Security Level 5, fast signing (~49KB)

#### SHAKE Variants
- **SLH-DSA-SHAKE-128s**: NIST Security Level 1, small signatures
- **SLH-DSA-SHAKE-128f**: NIST Security Level 1, fast signing
- **SLH-DSA-SHAKE-192s**: NIST Security Level 3, small signatures
- **SLH-DSA-SHAKE-192f**: NIST Security Level 3, fast signing
- **SLH-DSA-SHAKE-256s**: NIST Security Level 5, small signatures  
- **SLH-DSA-SHAKE-256f**: NIST Security Level 5, fast signing

**Notation:**
- `s` = Small signature size (slower signing)
- `f` = Fast signing (larger signature size)

## Requirements

- OpenSSL 3.5.0 or later with SLH-DSA support
- GCC or compatible C compiler
- POSIX-compliant system (Linux, macOS, etc.)

## Building

1. Ensure you have OpenSSL 3.5+ installed with PQC support
2. Update the Makefile paths if necessary to point to your OpenSSL installation
3. Build the program:

```bash
make
```

## Running

Execute the test program:

```bash
make test
# or
./slh_dsa_sig_test
```

## Program Features

### Key Generation
- Generates SLH-DSA public/private key pairs for selected parameter sets
- Uses OpenSSL's EVP_PKEY interface for key generation
- Displays key sizes for each algorithm

### Digital Signing
- Signs test messages using the generated private keys
- Uses OpenSSL's EVP_DigestSign interface (required for SLH-DSA)
- SLH-DSA signs raw messages directly without pre-hashing
- Shows signature sizes for each SLH-DSA variant

### Signature Verification
- Verifies signatures using the corresponding public keys
- Uses OpenSSL's EVP_DigestVerify interface (required for SLH-DSA)
- Tests both valid signatures and tampered messages (should fail)
- Provides clear pass/fail results

### Error Handling
- Comprehensive error checking and reporting
- OpenSSL error message display
- Memory management and cleanup

## Sample Output

```
SLH-DSA (SPHINCS+ Post-Quantum Digital Signature Algorithm) Test Program
========================================================================
This program demonstrates the SLH-DSA signature algorithms supported in OpenSSL 3.5+
SLH-DSA is based on the SPHINCS+ algorithm family.

Checking OpenSSL version and SLH-DSA support...
OpenSSL Version: OpenSSL 3.5.2
✓ SLH-DSA support confirmed!

Testing SLH-DSA-SHA2-128s...
========================================
Testing SLH-DSA algorithm: SLH-DSA-SHA2-128s
========================================
Test message: "Hello, this is a test message for SLH-DSA signature!" (53 bytes)

Step 1: Generating key pair...
Key generation successful for SLH-DSA-SHA2-128s:
  Public key length: 32 bytes
  Private key length: 64 bytes

Step 2: Signing message...
Signature generation successful for SLH-DSA-SHA2-128s:
  Message length: 53 bytes
  Signature length: 7856 bytes

Step 3: Verifying signature...
Signature verification successful for SLH-DSA-SHA2-128s:
  Message length: 53 bytes
  Signature length: 7856 bytes
  Verification result: VALID
✓ Signature verification PASSED!

Step 4: Testing with modified message (should fail)...
✓ Modified message verification correctly FAILED (as expected)

========================================
Test result for SLH-DSA-SHA2-128s: PASSED
========================================
```

## SLH-DSA Algorithm Details

### Key and Signature Sizes

| Algorithm | Public Key | Private Key | Signature (approx) |
|-----------|------------|-------------|-------------------|
| SLH-DSA-SHA2-128s | 32 bytes | 64 bytes | 7,856 bytes |
| SLH-DSA-SHA2-128f | 32 bytes | 64 bytes | 17,088 bytes |
| SLH-DSA-SHA2-192s | 48 bytes | 96 bytes | 16,224 bytes |
| SLH-DSA-SHA2-256s | 64 bytes | 128 bytes | 29,792 bytes |

### Security Levels

- **128-bit variants**: Provides security equivalent to AES-128 against quantum attacks
- **192-bit variants**: Provides security equivalent to AES-192 against quantum attacks
- **256-bit variants**: Provides security equivalent to AES-256 against quantum attacks

### Trade-offs

- **Small signatures (s)**: Smaller signature sizes but slower signing
- **Fast signing (f)**: Faster signing but larger signature sizes

## Code Structure

- `check_slh_dsa_support()`: Verifies OpenSSL version and SLH-DSA algorithm availability
- `call_slh_dsa_sig_gen_key()`: Generates SLH-DSA key pairs using OpenSSL EVP_PKEY interface
- `call_slh_dsa_sig_sign()`: Creates digital signatures using EVP_DigestSign interface (required for SLH-DSA)
- `call_slh_dsa_sig_verify()`: Verifies SLH-DSA signatures using EVP_DigestVerify interface
- `test_slh_dsa_algorithm()`: Complete test suite for each SLH-DSA parameter set
- `print_hex()`: Utility function for displaying binary data in hexadecimal format

## Implementation Notes

### Why EVP_DigestSign/EVP_DigestVerify?
SLH-DSA algorithms in OpenSSL require the use of digest signing interfaces rather than direct PKEY signing:
- `EVP_DigestSignInit()` with NULL digest parameter for direct message signing
- `EVP_DigestSign()` for signature generation
- `EVP_DigestVerifyInit()` with NULL digest parameter for verification setup  
- `EVP_DigestVerify()` for signature verification

This is different from traditional algorithms like RSA/ECDSA and is required by OpenSSL's post-quantum cryptography architecture.

## Troubleshooting

### SLH-DSA Not Supported Error
If you see "SLH-DSA-SHA2-128s is not supported in this OpenSSL build":
- Ensure you're using OpenSSL 3.5.0 or later
- Verify your OpenSSL build includes FIPS or post-quantum cryptography support
- Check that the PQC provider is properly loaded

### Provider Signature Not Supported Error
If you encounter "provider signature not supported" during signing:
- This indicates incorrect use of EVP_PKEY_sign instead of EVP_DigestSign
- SLH-DSA requires the digest signing interface, not the direct PKEY signing interface
- Ensure code uses EVP_DigestSignInit/EVP_DigestSign for signing
- Ensure code uses EVP_DigestVerifyInit/EVP_DigestVerify for verification

### Compilation Issues
- Update include and library paths in the Makefile
- Ensure OpenSSL development headers are installed
- Verify OpenSSL shared libraries are accessible

### Performance Considerations
- SLH-DSA signature generation can be slower than traditional algorithms
- Signature sizes are significantly larger than ECDSA/RSA
- Choose 'f' variants for faster signing at the cost of larger signatures
- Choose 's' variants for smaller signatures at the cost of slower signing

## References

- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [SPHINCS+](https://sphincs.org/)
- [OpenSSL 3.5 Post-Quantum Cryptography](https://www.openssl.org/docs/)
- [FIPS 205: Stateless Hash-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.205)