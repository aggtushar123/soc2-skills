# Cryptography Policy

## Purpose

This policy ensures the proper and effective use of cryptography to protect the confidentiality, authenticity, and integrity of information. It establishes requirements for the use and protection of cryptographic keys and methods throughout the entire encryption lifecycle.

## Scope

This policy applies to all information systems developed and/or controlled by [COMPANY NAME] that store or transmit confidential data.

## Policy

[COMPANY NAME] will evaluate the risks associated with processing and storing data and implement cryptographic controls to mitigate those risks as appropriate. Strong cryptography and key management processes and procedures will be implemented and documented. All encryption will adhere to industry standards, including NIST SP 800-57. Customer or confidential company data must use strong ciphers and configurations in accordance with vendor recommendations and industry best practices, including NIST, when stored or transferred over a public network.

## Key Management

Access to keys and secrets must be tightly controlled according to the Access Control Policy. The table below outlines the recommended usage for cryptographic keys:

| Domain | Key Type | Algorithm | Key Length | Max Expiration |
|---|---|---|---|---|
| Web Certificate | RSA or ECC with SHA2+ signature | RSA or ECC with SHA2+ signature | 2048 bit or greater/RSA, 256 bit or greater/ECC | Up to 1 year |
| Web Cipher (TLS) | Asymmetric Encryption | Ciphers of B or greater grade on SSL Labs Rating | Varies | N/A |
| Confidential Data at Rest | Symmetric Encryption | AES | 256 bit | 1 Year |
| Passwords | One-way Hash | Bcrypt, PBKDF2, scrypt, Argon2 | 256 bit+10K Stretch. Include unique cryptographic salt+pepper | N/A |
| Endpoint Storage (SSD/HDD) | Symmetric Encryption | AES | 256 bit | N/A |

## Exceptions

Requests for exceptions to this policy must be submitted to the CISO for approval. A documented exception is required before moving, copying, or storing customer or company confidential data on any media or removable device. All portable devices and removable media containing sensitive data must be encrypted using approved standards and mechanisms.

## Violations & Enforcement

Any known violations of this policy should be reported to the CISO. Violations can result in the immediate withdrawal or suspension of system and network privileges and/or disciplinary action in accordance with company procedures, up to and including termination of employment.
