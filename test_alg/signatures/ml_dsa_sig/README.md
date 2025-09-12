# ML-DSA Digital Signature Algorithm Test Program

This program demonstrates the implementation and usage of ML-DSA (Machine Learning Digital Signature Algorithm) using OpenSSL 3.5+.

## Overview

ML-DSA is a post-quantum digital signature scheme based on the CRYSTALS-Dilithium algorithm family. It was standardized by NIST as part of the Post-Quantum Cryptography (PQC) standardization process.

### Supported ML-DSA Variants

This program supports all three ML-DSA parameter sets:

- **ML-DSA-44**: NIST Security Level 2 (roughly equivalent to AES-128)
- **ML-DSA-65**: NIST Security Level 3 (roughly equivalent to AES-192)  
- **ML-DSA-87**: NIST Security Level 5 (roughly equivalent to AES-256)

## Requirements

- OpenSSL 3.5.0 or later with ML-DSA support
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
./ml_dsa_sig_test
```

## Program Features

### Key Generation
- Generates ML-DSA public/private key pairs for all three parameter sets
- Uses OpenSSL's EVP_PKEY interface for key generation
- Displays key sizes for each algorithm

### Digital Signing
- Signs test messages using the generated private keys
- Uses OpenSSL's EVP_DigestSign interface (required for ML-DSA)
- ML-DSA signs raw messages directly without pre-hashing
- Shows signature sizes for each ML-DSA variant

### Signature Verification
- Verifies signatures using the corresponding public keys
- Uses OpenSSL's EVP_DigestVerify interface (required for ML-DSA)
- Tests both valid signatures and tampered messages (should fail)
- Provides clear pass/fail results

### Error Handling
- Comprehensive error checking and reporting
- OpenSSL error message display
- Memory management and cleanup

## Sample Output

```
ML-DSA (Post-Quantum Digital Signature Algorithm) Test Program
==============================================================
This program demonstrates the ML-DSA signature algorithms supported in OpenSSL 3.5+
ML-DSA is based on the CRYSTALS-Dilithium algorithm family.

Checking OpenSSL version and ML-DSA support...
OpenSSL Version: OpenSSL 3.5.0-dev
✓ ML-DSA support confirmed!

Testing ML-DSA-44 (NIST Security Level 2)...
========================================
Testing ML-DSA algorithm: ML-DSA-44
========================================
Test message: "Hello, this is a test message for ML-DSA signature!" (51 bytes)

Step 1: Generating key pair...
Key generation successful for ML-DSA-44:
  Public key length: 1312 bytes
  Private key length: 2560 bytes

Step 2: Signing message...
Signature generation successful for ML-DSA-44:
  Message length: 51 bytes
  Signature length: 2420 bytes

Step 3: Verifying signature...
Signature verification successful for ML-DSA-44:
  Message length: 51 bytes
  Signature length: 2420 bytes
  Verification result: VALID
✓ Signature verification PASSED!

Step 4: Testing with modified message (should fail)...
✓ Modified message verification correctly FAILED (as expected)

========================================
Test result for ML-DSA-44: PASSED
========================================
```

## ML-DSA Algorithm Details

### Key and Signature Sizes

| Algorithm | Public Key | Private Key | Signature |
|-----------|------------|-------------|-----------|
| ML-DSA-44 | 1,312 bytes | 2,560 bytes | ~2,420 bytes |
| ML-DSA-65 | 1,952 bytes | 4,032 bytes | ~3,309 bytes |
| ML-DSA-87 | 2,592 bytes | 4,896 bytes | ~4,627 bytes |

### Security Levels

- **ML-DSA-44**: Provides security equivalent to AES-128 against quantum attacks
- **ML-DSA-65**: Provides security equivalent to AES-192 against quantum attacks
- **ML-DSA-87**: Provides security equivalent to AES-256 against quantum attacks

## Code Structure

- `check_ml_dsa_support()`: Verifies OpenSSL version and ML-DSA algorithm availability
- `call_ml_dsa_sig_gen_key()`: Generates ML-DSA key pairs using OpenSSL EVP_PKEY interface
- `call_ml_dsa_sig_sign()`: Creates digital signatures using EVP_DigestSign interface (required for ML-DSA)
- `call_ml_dsa_sig_verify()`: Verifies ML-DSA signatures using EVP_DigestVerify interface
- `test_ml_dsa_algorithm()`: Complete test suite for each ML-DSA parameter set
- `print_hex()`: Utility function for displaying binary data in hexadecimal format

## Implementation Notes

### Why EVP_DigestSign/EVP_DigestVerify?
ML-DSA algorithms in OpenSSL require the use of digest signing interfaces rather than direct PKEY signing:
- `EVP_DigestSignInit()` with NULL digest parameter for direct message signing
- `EVP_DigestSign()` for signature generation
- `EVP_DigestVerifyInit()` with NULL digest parameter for verification setup  
- `EVP_DigestVerify()` for signature verification

This is different from traditional algorithms like RSA/ECDSA and is required by OpenSSL's post-quantum cryptography architecture.

## Troubleshooting

### ML-DSA Not Supported Error
If you see "ML-DSA-44 is not supported in this OpenSSL build":
- Ensure you're using OpenSSL 3.5.0 or later
- Verify your OpenSSL build includes FIPS or post-quantum cryptography support
- Check that the PQC provider is properly loaded

### Provider Signature Not Supported Error
If you encounter "provider signature not supported" during signing:
- This indicates incorrect use of EVP_PKEY_sign instead of EVP_DigestSign
- ML-DSA requires the digest signing interface, not the direct PKEY signing interface
- Ensure code uses EVP_DigestSignInit/EVP_DigestSign for signing
- Ensure code uses EVP_DigestVerifyInit/EVP_DigestVerify for verification

### Compilation Issues
- Update include and library paths in the Makefile
- Ensure OpenSSL development headers are installed
- Verify OpenSSL shared libraries are accessible

## References

- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)
- [OpenSSL 3.5 Post-Quantum Cryptography](https://www.openssl.org/docs/)
- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.204)