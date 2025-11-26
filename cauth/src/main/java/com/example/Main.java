package com.example;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.json.JSONException;
import org.json.JSONObject;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class Main {
    // NOTE: after you create intermediate.p12, set KEYSTORE_PATH to "./intermediate.p12"
    private static final int PORT = 8443;
    private static final String KEYSTORE_PATH = "./keystore.p12";
    private static final String KEYSTORE_PASSWORD = "serverpassword";
    private static final String CA_ALIAS = "intermediate"; // alias inside intermediate.p12
    private static final Path SERIAL_FILE = Path.of("./cauth_serial.txt");
    private static final Path ISSUED_LOG = Path.of("./cauth_issued.log");
    private static KeyStore keyStore;
    private static final SecureRandom secureRandom = new SecureRandom();

    static {
        // Register Bouncy Castle as a static security provider if not already present
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            System.out.println("BouncyCastle provider added");
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println("Loading keystore: " + KEYSTORE_PATH);
            // Load the keystore (I_CA private key + cert chain)
            keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
                keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
            }

            // Create KeyManagerFactory for server certificate (I_CA as server identity)
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            // Create SSL context with server certificate
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null); // use default trust managers (optional)

            // Create SSL server socket
            SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(PORT);

            // Hardening: restrict to modern TLS protocols
            try {
                serverSocket.setEnabledProtocols(new String[] { "TLSv1.3", "TLSv1.2" });
            } catch (Exception ex) {
                System.err.println("Warning: failed to set enabled protocols: " + ex.getMessage());
            }

            serverSocket.setNeedClientAuth(false);
            serverSocket.setWantClientAuth(false);

            System.out.println("TLS Server (Intermediate CA) started on port " + PORT);

            // Thread pool for clients
            ExecutorService executor = Executors.newCachedThreadPool();

            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                executor.submit(new ClientHandler(clientSocket));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* -----------------------
       CSR signing + helpers
       ----------------------- */

    private static synchronized BigInteger nextSerial() throws IOException {
        // simple persistent serial: stored as decimal in SERIAL_FILE
        BigInteger serial;
        if (Files.exists(SERIAL_FILE)) {
            String s = Files.readString(SERIAL_FILE, StandardCharsets.UTF_8).trim();
            serial = new BigInteger(s).add(BigInteger.ONE);
        } else {
            // start with a random 64-bit positive integer
            serial = new BigInteger(64, secureRandom).abs().add(BigInteger.ONE);
        }
        Files.writeString(SERIAL_FILE, serial.toString(), StandardCharsets.UTF_8);
        return serial;
    }

    private static synchronized void logIssued(String entry) {
        try (FileWriter fw = new FileWriter(ISSUED_LOG.toFile(), true)) {
            fw.append(entry).append("\n");
        } catch (IOException e) {
            System.err.println("Failed to write issued log: " + e.getMessage());
        }
    }

    private static X509Certificate signCSR(PKCS10CertificationRequest csr, String entityType, JSONObject metadata) throws Exception {
        // verify CSR signature
        var verifier = new JcaContentVerifierProviderBuilder().setProvider("BC")
                .build(csr.getSubjectPublicKeyInfo());
        if (!csr.isSignatureValid(verifier)) {
            throw new IllegalArgumentException("CSR signature invalid");
        }

        // policy checks
        // check key type and size
        var keyInfo = csr.getSubjectPublicKeyInfo();
        java.security.PublicKey pub = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().setProvider("BC").getPublicKey(keyInfo);
        if (pub instanceof RSAPublicKey) {
            int bits = ((RSAPublicKey) pub).getModulus().bitLength();
            if (bits < 2048) {
                throw new IllegalArgumentException("RSA key too small: " + bits);
            }
        } else {
            throw new IllegalArgumentException("Unsupported key type, only RSA is allowed");
        }

        // load CA private key and cert
        Key key = keyStore.getKey(CA_ALIAS, KEYSTORE_PASSWORD.toCharArray());
        if (!(key instanceof PrivateKey)) throw new IllegalStateException("CA key is not a private key");
        PrivateKey caKey = (PrivateKey) key;
        X509Certificate caCert = (X509Certificate) keyStore.getCertificate(CA_ALIAS);
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        X500Name subject = csr.getSubject();

        BigInteger serial = nextSerial();
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60);
        Date notAfter = new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000)); // 1 year

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, csr.getSubjectPublicKeyInfo());

        // add extensions: basic usage for end-entity
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        // Optionally include metadata in SAN or certificate fields (example: put metadata.name as CN if provided)
        // (For brevity we do not add SAN parsing here; metadata could be added as certificate policy or subject alt name)

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caKey);
        X509Certificate signed = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certBuilder.build(signer));

        // log issuance
        String logEntry = String.format("%s | serial=%s | subject=%s | issuer=%s | entity=%s | valid=%s->%s",
                new Date().toString(), serial.toString(), signed.getSubjectX500Principal().getName(),
                signed.getIssuerX500Principal().getName(), entityType, notBefore.toString(), notAfter.toString());
        logIssued(logEntry);

        return signed;
    }

    /* -----------------------
       Client handler: JSON over TLS
       Endpoints:
         - {"method":"test"}
         - {"method":"enroll","entity":"CO","csr":"BASE64-CSR","metadata":{...}}
         - {"method":"get_ca"} -> returns ca cert chain base64
       ----------------------- */

    static class ClientHandler implements Runnable {
        private SSLSocket clientSocket;

        public ClientHandler(SSLSocket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                    PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true)) {

                System.out.println("Client connected: " + clientSocket.getRemoteSocketAddress());

                String inputLine;
                StringBuilder jsonBuffer = new StringBuilder();
                int jsonAttempts = 0;
                final int MAX_BUFFER = 10_000;
                final int MAX_ATTEMPTS = 5;

                while ((inputLine = reader.readLine()) != null) {
                    jsonBuffer.append(inputLine);

                    try {
                        JSONObject jsonRequest = new JSONObject(jsonBuffer.toString());
                        System.out.println("Received JSON: " + jsonRequest.toString(2));

                        String method = jsonRequest.optString("method", jsonRequest.optString("type", "unknown"));

                        switch (method) {
                            case "test" -> {
                                JSONObject responseJson = new JSONObject();
                                responseJson.put("response", "Test method executed");
                                writer.write(responseJson.toString() + "\n");
                                writer.flush();
                            }
                            case "get_ca" -> {
                                // return CA chain as base64 DER
                                JSONObject resp = new JSONObject();
                                java.util.List<String> chain = new java.util.ArrayList<>();
                                Certificate[] certChain = keyStore.getCertificateChain(CA_ALIAS);
                                if (certChain != null) {
                                    for (Certificate c : certChain) {
                                        chain.add(Base64.getEncoder().encodeToString(c.getEncoded()));
                                    }
                                } else {
                                    // fallback: single cert
                                    Certificate c = keyStore.getCertificate(CA_ALIAS);
                                    if (c != null) chain.add(Base64.getEncoder().encodeToString(c.getEncoded()));
                                }
                                resp.put("ca_chain", chain);
                                writer.write(resp.toString() + "\n");
                                writer.flush();
                            }

                            
                            case "signCSR" -> {
                                String b64csr = jsonRequest.optString("csr", null);
                                if (b64csr == null) {
                                    JSONObject err = new JSONObject();
                                    err.put("response", "ERROR");
                                    err.put("reason", "missing csr");
                                    writer.write(err.toString() + "\n");
                                    writer.flush();
                                    break;
                                }

                                try {
                                    byte[] csrBytes = Base64.getDecoder().decode(b64csr);
                                    PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);

                                    // entity is optional here; for now use "SP" or "unknown"
                                    String entity = jsonRequest.optString("entity", "SP");
                                    JSONObject metadata = jsonRequest.optJSONObject("metadata");

                                    X509Certificate signed = signCSR(csr, entity, metadata);

                                    // Build response expected by SP:
                                    //  - "response"
                                    //  - "certificate"
                                    //  - "caCertificate" (root)
                                    JSONObject resp = new JSONObject();
                                    resp.put("response", "OK");
                                    resp.put("certificate", Base64.getEncoder().encodeToString(signed.getEncoded()));

                                    Certificate[] certChain = keyStore.getCertificateChain(CA_ALIAS);
                                    if (certChain != null && certChain.length > 0) {
                                        // assume root is last element of chain
                                        Certificate root = certChain[certChain.length - 1];
                                        resp.put("caCertificate", Base64.getEncoder().encodeToString(root.getEncoded()));
                                    }

                                    writer.write(resp.toString() + "\n");
                                    writer.flush();
                                } catch (IllegalArgumentException iae) {
                                    JSONObject err = new JSONObject();
                                    err.put("response", "ERROR");
                                    err.put("reason", "invalid base64 CSR or policy: " + iae.getMessage());
                                    writer.write(err.toString() + "\n");
                                    writer.flush();
                                } catch (Exception ex) {
                                    JSONObject err = new JSONObject();
                                    err.put("response", "ERROR");
                                    err.put("reason", "internal error: " + ex.getMessage());
                                    writer.write(err.toString() + "\n");
                                    writer.flush();
                                    ex.printStackTrace();
                                }
                            }

                            // (optional) keep old "enroll"/"csr" for CO/HO clients later
                            case "enroll", "csr" -> {
                                String entity = jsonRequest.optString("entity", "unknown");
                                String b64csr = jsonRequest.optString("csr", null);
                                if (b64csr == null) {
                                    JSONObject err = new JSONObject();
                                    err.put("status", "ERROR");
                                    err.put("reason", "missing csr");
                                    writer.write(err.toString() + "\n");
                                    writer.flush();
                                    break;
                                }

                                try {
                                    byte[] csrBytes = Base64.getDecoder().decode(b64csr);
                                    PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);

                                    JSONObject metadata = jsonRequest.optJSONObject("metadata");
                                    X509Certificate signed = signCSR(csr, entity, metadata);

                                    JSONObject resp = new JSONObject();
                                    resp.put("status", "OK");
                                    resp.put("certificate", Base64.getEncoder().encodeToString(signed.getEncoded()));

                                    java.util.List<String> chain = new java.util.ArrayList<>();
                                    Certificate[] certChain = keyStore.getCertificateChain(CA_ALIAS);
                                    if (certChain != null) {
                                        for (Certificate c : certChain) {
                                            chain.add(Base64.getEncoder().encodeToString(c.getEncoded()));
                                        }
                                    } else {
                                        Certificate c = keyStore.getCertificate(CA_ALIAS);
                                        if (c != null) chain.add(Base64.getEncoder().encodeToString(c.getEncoded()));
                                    }
                                    resp.put("ca_chain", chain);

                                    writer.write(resp.toString() + "\n");
                                    writer.flush();
                                } catch (IllegalArgumentException iae) {
                                    JSONObject err = new JSONObject();
                                    err.put("status", "ERROR");
                                    err.put("reason", "invalid base64 CSR or policy: " + iae.getMessage());
                                    writer.write(err.toString() + "\n");
                                    writer.flush();
                                } catch (Exception ex) {
                                    JSONObject err = new JSONObject();
                                    err.put("status", "ERROR");
                                    err.put("reason", "internal error: " + ex.getMessage());
                                    writer.write(err.toString() + "\n");
                                    writer.flush();
                                    ex.printStackTrace();
                                }
                            }

                            default -> {
                                JSONObject responseJson = new JSONObject();
                                responseJson.put("response", "Unknown method");
                                writer.write(responseJson.toString() + "\n");
                                writer.flush();
                            }
                        }

                        jsonBuffer.setLength(0); // reset buffer for next JSON
                        jsonAttempts = 0;
                    } catch (JSONException je) {
                        // incomplete or invalid JSON - defend against unbounded growth and abusive clients
                        jsonAttempts++;
                        if (jsonBuffer.length() > MAX_BUFFER || jsonAttempts > MAX_ATTEMPTS) {
                            JSONObject err = new JSONObject();
                            err.put("status", "ERROR");
                            err.put("reason", "invalid or too large JSON request");
                            writer.write(err.toString() + "\n");
                            writer.flush();
                            System.err.println("Closing connection due to invalid JSON from " + clientSocket.getRemoteSocketAddress());
                            break;
                        }
                        // otherwise keep reading more lines
                        continue;
                    } catch (Exception e) {
                        // other parsing errors: respond and close
                        JSONObject err = new JSONObject();
                        err.put("status", "ERROR");
                        err.put("reason", "bad request");
                        writer.write(err.toString() + "\n");
                        writer.flush();
                        break;
                    }
                }

            } catch (IOException e) {
                System.err.println("Error handling client: " + e.getMessage());
            } finally {
                try {
                    clientSocket.close();
                    System.out.println("Client disconnected");
                } catch (IOException e) {
                    System.err.println("Error closing client socket: " + e.getMessage());
                }
            }
        }
    }
}