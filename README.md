# Project Logbook — cauth / assignment_2526

This logbook records what was done, when, and why — to preserve decisions and make the project reproducible.

## Summary
- Project: cauth — a minimal TLS server that will become an online intermediate CA.
- Goal: run a TLS server for development, then convert the setup so the server signs CSRs using an intermediate CA signed by an offline Root.

---

## Entries

### 2025-11-26 — Created development Root CA keystore
- What: Generated a PKCS#12 keystore `cauth/keystore.p12` containing a self-signed certificate (alias `root_ca`) for initial TLS testing.
- Command:
  - keytool -genkeypair -alias root_ca -keyalg RSA -keysize 2048 -dname "CN=localhost,OU=Dev,O=Example,L=City,ST=State,C=US" -keypass serverpassword -storepass serverpassword -keystore cauth/keystore.p12 -storetype PKCS12 -validity 3650
- Why: Provide a local trust anchor and server identity for development; root kept for signing intermediate CAs.

### 2025-11-26 — Launched the cauth TLS server
- Action:
  - Built and ran `Main.java` in `cauth` which:
    - Registers BouncyCastle provider.
    - Loads `keystore.p12`.
    - Creates an SSLContext and listens on port 8443.
    - Accepts JSON requests and responds to a `{"method":"test"}` request.
- Why:
  - Validate TLS setup and a minimal request/response protocol before adding CSR handling.

### 2025-11-26 — Verified TLS with openssl and exported cert
- Action:
  - Exported server certificate to `cauth/cert.pem`:
    - `keytool -exportcert -rfc -alias root_ca -keystore cauth/keystore.p12 -storetype PKCS12 -storepass serverpassword -file cauth/cert.pem`
  - Tested connection with:
    - `printf '{"method":"test"}\n' | openssl s_client -connect localhost:8443 -servername localhost -CAfile cauth/cert.pem -quiet -ign_eof`
- Why:
  - Client trust fails for self-signed certs by default; exporting root cert and supplying it to the client verifies full TLS+application behavior.

### 2025-11-26 — Decided on proper CA hierarchy (Root offline, Intermediate online)
- Action:
  - Planned steps to create an intermediate CA and sign it with the existing root keystore:
    1. Create `cauth/intermediate.p12` (new keypair).
    2. Generate CSR for intermediate.
    3. Use `cauth/keystore.p12` (root) to sign CSR, adding CA extensions (`BasicConstraints`, `KeyUsage`).
    4. Import root cert + signed intermediate into `intermediate.p12`.
    5. Point server to `intermediate.p12`.
- Why:
  - Best practice: keep root CA offline and use an intermediate CA for online issuance to reduce the risk of root key compromise.

### 2025-11-26 — Plan to extend server to sign CSRs
- Action:
  - Designed a minimal CSR-signing flow to add into `Main.java`:
    - Accept JSON with a PEM CSR: `{"method":"csr","csr":"-----BEGIN CERTIFICATE REQUEST-----..."}`
    - Parse PKCS#10 with BouncyCastle.
    - Sign CSR with intermediate private key and return PEM certificate chain.
- Why:
  - Convert cauth into an online intermediate CA to issue end-entity certificates over a secure channel.

---

## Commands to create and configure the Intermediate CA
1. Create intermediate keypair:
   - `keytool -genkeypair -alias intermediate -keyalg RSA -keysize 2048 -dname "CN=Intermediate CA, O=Example, OU=CA" -keypass interpass -storepass interpass -keystore cauth/intermediate.p12 -storetype PKCS12 -validity 3650`
2. Create CSR for intermediate:
   - `keytool -certreq -alias intermediate -keystore cauth/intermediate.p12 -storetype PKCS12 -file cauth/intermediate.csr -storepass interpass`
3. Sign intermediate with Root and add CA extensions:
   - `keytool -gencert -alias root_ca -keystore cauth/keystore.p12 -storetype PKCS12 -infile cauth/intermediate.csr -outfile cauth/intermediate.crt -rfc -validity 3650 -storepass serverpassword -ext KeyUsage:critical=keyCertSign,cRLSign -ext BasicConstraints:critical=ca:true,pathlen:0`
4. Export root cert and import chain into intermediate keystore:
   - `keytool -exportcert -alias root_ca -keystore cauth/keystore.p12 -rfc -file cauth/root.crt -storepass serverpassword`
   - `keytool -importcert -alias root_ca -keystore cauth/intermediate.p12 -file cauth/root.crt -storepass interpass -noprompt`
   - `keytool -importcert -alias intermediate -keystore cauth/intermediate.p12 -file cauth/intermediate.crt -storepass interpass`
5. Verify:
   - `keytool -list -v -keystore cauth/intermediate.p12 -storetype PKCS12 -storepass interpass`

---

## Notes and operational considerations
- Security:
  - Keep the Root keystore (`cauth/keystore.p12`) offline and protected.
  - Protect the intermediate private key (`intermediate.p12`) with strong access controls; consider HSM for production.
- Issuance policy:
  - Implement serial number persistence, certificate record storage, and revocation (CRL/OCSP).
  - Add checks and authentication for CSR requests.
  - Add X.509 extensions (SANs, KeyUsage) according to policy.
- Development:
  - Use `cert.pem` (root.crt) to trust the chain in tests.
  - Update `Main.java` constants to point to `./intermediate.p12` and the correct password/alias after intermediate creation.

---

## Next actions (recommended)
- Create and sign the intermediate as described above.
- Update `Main.java` to load `intermediate.p12` at startup.
- Apply the CSR-signing code to `Main.java` and add persistent serial tracking.
- Implement a test client that generates a CSR and requests a signed certificate.

If you want, I can:
- produce the exact patch to `Main.java` to add CSR-signing and update constants,
- generate a test client that requests a certificate,
- add simple serial persistence logic.
