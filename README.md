# Certificate Policy for Internal PKI

## 1. Introduction
This document defines the policies and procedures for the issuance, management, and revocation of certificates within the internal Public Key Infrastructure (PKI) used for QUBIP. The PKI consists of a **Root Certificate Authority (Root CA)**, two **Intermediate Certificate Authorities (Intermediate CAs)**, and End-Entity certificates for users, servers, and services.

## 2. Certificate Authorities
### 2.1 Root Certificate Authority (Root CA)
- **Storage**: Private key is securely encrypted with AES-256.
- **Usage**: Only used to sign Intermediate CA certificates.
- **Validity Period**: 20 years.
- **Key Algorithm**: SPHINCS+-SHAKE256-s.
- **Revocation**: Only revoked if compromised.

### 2.2 Intermediate Certificate Authorities (Intermediate CAs)
- **Storage**: Private key is securely encrypted with AES-256.
- **Usage**: Used to issue End-Entity certificates (e.g., server, user, device certificates).
- **Validity Period**: 10 years.
- **Key Algorithm**: ED25519/MLDSA-65.
- **Revocation**: Revoked if the private key is compromised or no longer needed.
 
## 3. End-Entity Certificate Policy
| **Category**       | **Policy**                                         |
|--------------------|---------------------------------------------------|
| **Who Can Request?** | QUBIP Partners. |
| **Usage**          | TLS/SSL (internal services), code signing, device signing. |
| **Validity Period** | 1 year (users, code signing), 2 years (servers). |
| **Key Algorithm**  | classical or post-quantum (pure and composite) algorithms. |
| **Revocation**     | Revoked if an employee leaves, a server is decommissioned, or compromised. |

## 4. Available algorithms for End-Entity certificates
| **Algorithm**       | **Type**                                         |
|--------------------|---------------------------------------------------|
| **RSA-2048** | Classical |
| **RSA-4096**          |Classical |
| **ED25519** | Classical |
| **MLDSA-44**  | Pure Post-Quantum |
| **MLDSA-65**     | Pure Post-Quantum |
| **MLDSA-87**     |Pure Post-Quantum |
| **MLDSA-44/ED25519**     | Post-Quantum Composite |
| **MLDSA-65/ED25519**     | Post-Quantum Composite |
## 5. Certificate Issuance Procedure (Version 1)
1. The user decides the key algorithm and the type of certificate they need: tls-server, tls-client or code-signing.
2. The backend generates both the certificate and the key. The certificate is signed by the intermediate CA (TLS-CA if the purpose is "tls-server" or "tls-client", SOFTWARE-CA if the purpose is "code-signing").
3. The user downloads a zip file containing the key, the certificate and the chain.

## 6. Certificate Issuance Procedure (Version 2)
1. The requester submits a certificate request (CSR) to the Intermediate CA.
2. The request is reviewed for compliance with the policy.
3. The Intermediate CA signs and issues the certificate.
4. The certificate is distributed to the requester and added to the appropriate trust store.

## 7. Revocation and Certificate Status Checking
- A **Certificate Revocation List (CRL)** is published every 24 hours.
- An **Online Certificate Status Protocol (OCSP) responder** is available for real-time revocation checks.

## 8. Trust Establishment
- The Root CA certificate must be manually installed on all systems that need to trust the PKI.
- Intermediate CA certificates must be included in the certificate chain for verification.

## 9. Security Considerations
- Private keys must never be shared or exported.

