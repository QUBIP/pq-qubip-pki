# Web Interface for QUBIP Post-Quantum (PQ) PKI

## 1. Introduction
This document defines the policies and procedures for the issuance, management, and revocation of certificates within the internal PQ Public Key Infrastructure (PKI) used for QUBIP. The PKI consists of three certificate chains, each one with a root CA and an intermediate CA. Such CAs are able to issue End-Entity certificates for users, servers, and services.

## 2. Certificate Chains
This PQ PKI is used by two pilots of the QUBIP project: Internet Browsing (IB) and Digital Manufacturing (DM).
Both the pilots require the usage of server and client certificates to establish TLS connections. However, the separation between the two certificate chains is due to the differing levels of support for post-quantum algorithms across the devices used in each pilot.
The features of the CAs are explained below:
- **Storage**: Private key is securely encrypted with AES-256.
- **Usage**: Only used to sign Intermediate CA certificates (for root CA) or issue End-Entity certificates (for intermediate CAs).
- **Validity Period**: 20 years (root CA), 10 years (intermediate CAs).
- **Revocation**: Only revoked if compromised.

### 2.1 IB: QUBIP TLS chain
This chain is used within the IB pilot to set up a TLS connection in Firefox. It consists of a Root CA and an intermediate CA:
- The root CA is self-signed with SPHINCS+-SHAKE256Ssimple key
- The intermediate TLS CA has a MLDSA65 keypair and its certificate is signed with the root CA's key


 ### 2.2 DM: QUBIP MPU chain
This chain is used within the DM pilot for MPU IoT devices that connect to the MQTT broker. It consists of a Root CA and an intermediate CA:
- The root CA is self-signed with MLDSA65/ED25519 composite key
- The intermediate TLS CA has a MLDSA65/ED25519 composite keypair and its certificate is signed with the root CA's key

 ### 2.3 DM: QUBIP MCU chain
This chain is used within the DM pilot for MCU IoT devices that connect to the MQTT broker. It consists of a Root CA and an intermediate CA:
- The root CA is self-signed with MLDSA44/ED25519 composite key
- The intermediate TLS CA has a MLDSA44/ED25519 composite keypair and its certificate is signed with the root CA's key

## 3. End-Entity Certificate Policy
| **Category**       | **Policy**                                         |
|--------------------|---------------------------------------------------|
| **Who Can Request?** | QUBIP Partners. |
| **Usage**          | client and servers |
| **Validity Period** | 1 year |
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
1. The user decides the key algorithm and the type of certificate they need: server or client.
2. The user selects between a Fully Qualified Domain Name (FQDN) or an IP address as Common Name (CN) to identify the owner of the certificate.
3. The user selects for which device the certificate is needed, which corresponds to the CA that will sign the certificate: MPU device, MCU device or TLS endpoint.
4. The backend generates both the certificate and the key. The certificate is signed by the selected intermediate CA.
4. The user downloads a zip file containing the key, the certificate (in both PEM and DER format) and the chain.

## 6. TODO Certificate Issuance Procedure
1. The requester submits a certificate request (CSR) to the Intermediate CA.
2. The request is reviewed for compliance with the policy.
3. The Intermediate CA signs and issues the certificate.
4. The certificate is distributed to the requester and added to the appropriate trust store.

## 7. TODO Revocation and Certificate Status Checking
- A **Certificate Revocation List (CRL)** is published every 24 hours.

## 8. Trust Establishment
- The Root CA certificate must be manually installed on all systems that need to trust the PKI.
- Intermediate CA certificates must be included in the certificate chain for verification.

## 9. Security Considerations
Private keys are immediately deleted from the server after the user has downloaded them. Thus, once generated, the certificate material cannot be downloaded anymore. 
