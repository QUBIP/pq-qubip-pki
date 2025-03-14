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
- **Key Algorithm**: ED25519/MLDSA-44 or ED25519/MLDSA-65.
- **Revocation**: Revoked if the private key is compromised or no longer needed.

## 3. End-Entity Certificate Policy
| **Category**       | **Policy**                                         |
|--------------------|---------------------------------------------------|
| **Who Can Request?** | QUBIP Partners. |
| **Usage**          | TLS/SSL (internal services), email encryption, code signing, device signing. |
| **Validity Period** | 1 year (users, code signing), 2 years (servers). |
| **Key Algorithm**  | classical or post-quantum algorithms. |
| **Revocation**     | Revoked if an employee leaves, a server is decommissioned, or compromised. |

## 4. Certificate Issuance Procedure
1. The requester submits a certificate request (CSR) to the Intermediate CA.
2. The request is reviewed for compliance with the policy.
3. The Intermediate CA signs and issues the certificate.
4. The certificate is distributed to the requester and added to the appropriate trust store.

## 5. Revocation and Certificate Status Checking
- A **Certificate Revocation List (CRL)** is published every 24 hours.
- An **Online Certificate Status Protocol (OCSP) responder** is available for real-time revocation checks.

## 6. Trust Establishment
- The Root CA certificate must be manually installed on all systems that need to trust the PKI.
- Intermediate CA certificates must be included in the certificate chain for verification.

## 7. Security Considerations
- Private keys must never be shared or exported.

## 8. Policy Review and Updates
- This policy is reviewed annually.
- Updates require approval from security leadership.

---

