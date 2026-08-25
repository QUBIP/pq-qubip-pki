# Web Interface for QUBIP Post-Quantum (PQ) PKI - v2

## 1. Introduction
This document defines the policies and procedures for the issuance, management, and revocation of certificates within the internal PQ Public Key Infrastructure (PKI) used for QUBIP. The PKI consists of a single chain with a root CA that is self-signed and issued two intermediate CAs, one for issuing server certificates and one for issuing client certificates. 


 ### 1.1 Legacy OQS chain: QUBIP MCU chain (OQS provider)
This chain is used within the DM pilot for MCU IoT devices that connect to the MQTT broker. It consists of a Root CA and an intermediate CA:
- The root CA is self-signed with MLDSA44/ED25519 composite key
- The intermediate TLS CA has a MLDSA44/ED25519 composite keypair and its certificate is signed with the root CA's key.
The purpose of this chain is to keep the legacy OQS provider for MCU devices that are already deployed in the field. The chain is not used for new devices and will be deprecated in the future.

## 2. End-Entity Certificate Policy
| **Category**       | **Policy**                                         |
|--------------------|---------------------------------------------------|
| **Who Can Request?** | QUBIP Partners. |
| **Usage**          | client and servers |
| **Validity Period** | 1 year |
| **Key Algorithm**  | classical or post-quantum (pure and composite) algorithms. |
| **Revocation**     | Revoked if an employee leaves, a server is decommissioned, or compromised. |

## 3. Available algorithms for End-Entity certificates
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
## 4. Certificate Issuance Procedure (private key + certificate)
1. The user decides the key algorithm and the type of certificate they need: server or client.
2. The user selects between a Fully Qualified Domain Name (FQDN) or an IP address as Common Name (CN) to identify the owner of the certificate.
3. The user selects for which device the certificate is needed, which corresponds to the CA that will sign the certificate: MPU device, MCU device or TLS endpoint.
4. The backend generates both the certificate and the key. The certificate is signed by the selected intermediate CA.
4. The user downloads a zip file containing the key, the certificate (in both PEM and DER format) and the chain.

## 5. Certificate Issuance Procedure (certificate only)
1. The requester submits a certificate request (CSR) to the Intermediate CA.
2. The request is reviewed for compliance with the policy.
3. The Intermediate CA signs and issues the certificate.
4. The certificate is distributed to the requester and added to the appropriate trust store.

## 6. Revocation and Certificate Status Checking
- A **Certificate Revocation List (CRL)** is published every 24 hours.
- For each CA, there is an OCSP responder that can be queried to check the status of a specific certificate

## 7. Trust Establishment
- The Root CA certificate must be manually installed on all systems that need to trust the PKI.
- Intermediate CA certificates must be included in the certificate chain for verification.

## 8. Security Considerations
Private keys are immediately deleted from the server after the user has downloaded them. Thus, once generated, the certificate material cannot be downloaded anymore. 

## 9. Software used
- **OpenSSL 3.2.2**: for certificate generation and signing.
- **aurora provider 0.10.0**: for post-quantum algorithms and encoding of the keys and certificates.

## 10. Conclusions
This document outlines the policies and procedures for managing certificates within the QUBIP PQ PKI.
For security reasons, the private keys are not stored on the server after issuance. The PKI supports both classical and post-quantum algorithms, ensuring future-proof security for QUBIP applications.
Only authorized QUBIP partners can request certificates upon logging in to the web interface. The system is designed to be user-friendly while maintaining strict security standards.