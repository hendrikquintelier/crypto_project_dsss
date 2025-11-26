package com.example;

import java.io.*;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;
import java.util.Date;
import java.util.Enumeration;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.json.JSONObject;

public class Main {
    // CAuth server details (for enrollment)
    private static final String CAUTH_HOST = "172.20.0.10";
    private static final int CAUTH_PORT = 8443;
    
    // SP server details (for accepting client connections)
    private static final int SP_SERVER_PORT = 8444;
    
    private static final String TRUSTSTORE_PATH = "./truststore.p12";
    private static final String TRUSTSTORE_PASSWORD = "trustpassword";
    
    // Local storage for SP's credentials
    private static final String SP_KEYSTORE_PATH = "./keystore.p12";
    private static final String SP_KEYSTORE_PASSWORD = "serverpassword";
    private static final String SP_KEY_ALIAS = "sp_key";
    
    private static final String HASH_ALGORITHM = "SHA-256";

    private static KeyPair spKeyPair;
    private static X509Certificate spCertificate;
    private static SSLContext sslContext;

    public static void main(String[] args) {
        // Sleep to allow CAuth to start
        try {
            System.out.println("Waiting for CAuth to start...");
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        
        try {
            System.out.println("\n=== Service Provider Starting ===");
            
            // Check if we already have a certificate
            if (hasCertificate()) {
                System.out.println("Found existing certificate, loading from keystore...");
                loadExistingCertificate();
            } else {
                System.out.println("No existing certificate found, enrolling with CAuth...");
                enrollWithCAuth();
            }
            
            if (spCertificate!=null){
                System.out.println("\n=== Certificate Ready ===");
                System.out.println("Subject: " + spCertificate.getSubjectX500Principal().getName());
                System.out.println("Valid from: " + spCertificate.getNotBefore());
                System.out.println("Valid until: " + spCertificate.getNotAfter());
                System.out.println("Issuer: " + spCertificate.getIssuerX500Principal().getName());
            }
            // Now start the TLS server for clients
            System.out.println("\n=== Starting SP Server ===");
            startServer();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Check if we already have a certificate stored locally
     */
    private static boolean hasCertificate() {
        File keystoreFile = new File(SP_KEYSTORE_PATH);
        if (!keystoreFile.exists()) {
            return false;
        }
        
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(SP_KEYSTORE_PATH)) {
                ks.load(fis, SP_KEYSTORE_PASSWORD.toCharArray());
            }
            return ks.containsAlias(SP_KEY_ALIAS);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Load existing certificate and key pair from keystore
     */
    private static void loadExistingCertificate() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(SP_KEYSTORE_PATH)) {
            ks.load(fis, SP_KEYSTORE_PASSWORD.toCharArray());
        }
        
        spCertificate = (X509Certificate) ks.getCertificate(SP_KEY_ALIAS);
        PrivateKey privateKey = (PrivateKey) ks.getKey(SP_KEY_ALIAS, SP_KEYSTORE_PASSWORD.toCharArray());
        PublicKey publicKey = spCertificate.getPublicKey();
        spKeyPair = new KeyPair(publicKey, privateKey);
        
        // Check if certificate is still valid
        try {
            spCertificate.checkValidity();
        } catch (Exception e) {
            System.out.println("Warning: Certificate has expired or is not yet valid!");
        }
    }
    
    /**
     * Enroll with CAuth to get a signed certificate
     */
    private static void enrollWithCAuth() throws Exception {
        System.out.println("\nStep 1: Generating key pair...");
        spKeyPair = generateKeyPair();

        System.out.println("Step 2: Building CSR...");
        PKCS10CertificationRequest csr = createCSR(spKeyPair);

        System.out.println("\nStep 3: Connecting to CAuth server...");

        // DEBUG: show resolved CA host and system ssl props
        try {
            System.out.println("CAUTH_HOST = " + CAUTH_HOST + ", CAUTH_PORT = " + CAUTH_PORT);
            InetAddress addr = InetAddress.getByName(CAUTH_HOST);
            System.out.println("Resolved CAUTH_HOST to: " + addr.getHostAddress());
        } catch (Exception e) {
            System.out.println("Failed to resolve CAUTH_HOST: " + e.getMessage());
        }
        System.out.println("javax.net.ssl.trustStore = " + System.getProperty("javax.net.ssl.trustStore"));
        System.out.println("javax.net.ssl.trustStorePassword = " +
                (System.getProperty("javax.net.ssl.trustStorePassword") != null ? "<set>" : "<not-set>"));

        // DEBUG: inspect configured truststore file
        debugTruststore(TRUSTSTORE_PATH, TRUSTSTORE_PASSWORD);

        System.out.println("Step 3b: Requesting certificate from CAuth...");
        X509Certificate[] certChain = requestCertificateFromCAuth(csr);

        if (certChain == null || certChain.length == 0 || certChain[0] == null) {
            System.out.println("No certificate has been received, cannot store credentials.");
            return;
        }

        spCertificate = certChain[0]; // The first cert is always the SP's own
        System.out.println("Certificate received from CAuth");

        System.out.println("\nStep 4: Storing certificate and private key...");
        storeCertificateAndKey(certChain);
        System.out.println("Credentials stored in " + SP_KEYSTORE_PATH);
    }

    // DEBUG helper: load and list truststore contents
    private static void debugTruststore(String truststorePath, String truststorePassword) {
        try {
            Path tsPath = Path.of(truststorePath);
            if (!Files.exists(tsPath)) {
                System.out.println("Truststore file not found at: " + tsPath.toAbsolutePath());
                return;
            }
            System.out.println("Truststore file found: " + tsPath.toAbsolutePath() + " (size=" + Files.size(tsPath) + " bytes)");

            KeyStore ts = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(tsPath.toFile())) {
                ts.load(fis, truststorePassword != null ? truststorePassword.toCharArray() : null);
            }

            System.out.println("Loaded truststore, type=" + ts.getType() + ", entryCount=" + ts.size());
            Enumeration<String> aliases = ts.aliases();
            while (aliases.hasMoreElements()) {
                String a = aliases.nextElement();
                System.out.println(" - alias: " + a + " (trusted=" + ts.isCertificateEntry(a) + ", keyEntry=" + ts.isKeyEntry(a) + ")");
                if (ts.isCertificateEntry(a) || ts.isKeyEntry(a)) {
                    Certificate cert = ts.getCertificate(a);
                    if (cert instanceof java.security.cert.X509Certificate) {
                        java.security.cert.X509Certificate x = (java.security.cert.X509Certificate) cert;
                        System.out.println("   subject: " + x.getSubjectX500Principal().getName());
                        System.out.println("   issuer:  " + x.getIssuerX500Principal().getName());
                        System.out.println("   serial:  " + x.getSerialNumber());
                        System.out.println("   valid:   " + x.getNotBefore() + " -> " + x.getNotAfter());
                    } else if (cert != null) {
                        System.out.println("   cert class: " + cert.getClass().getName());
                    } else {
                        System.out.println("   no certificate available for alias");
                    }
                }
            }

            // show how many trust managers would be created (sanity)
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
            System.out.println("TrustManagerFactory initialized: providers=" + Objects.toString(tmf.getProvider().getName()));
        } catch (Exception e) {
            System.out.println("Error inspecting truststore: " + e.getMessage());
            e.printStackTrace(System.out);
        }
    }

    /**
     * Generate RSA key pair
     */
    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }
    
    /**
     * Create a Certificate Signing Request (CSR)
     */
    private static PKCS10CertificationRequest createCSR(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name(
            "CN=ServiceProvider-" + System.currentTimeMillis() + 
            ", O=Parking System, C=BE"
        );
        
        JcaPKCS10CertificationRequestBuilder csrBuilder = 
            new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .build(keyPair.getPrivate());
        
        return csrBuilder.build(signer);
    }
    
    /**
     * Connect to CAuth and request certificate signing
     */
    private static X509Certificate[] requestCertificateFromCAuth(PKCS10CertificationRequest csr)
            throws Exception {

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm()
        );
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);

        SSLSocketFactory factory = sslContext.getSocketFactory();

        System.out.println("Attempting TCP connect to " + CAUTH_HOST + ":" + CAUTH_PORT + " (5s timeout)");
        java.net.Socket raw = new java.net.Socket();
        raw.connect(new InetSocketAddress(CAUTH_HOST, CAUTH_PORT), 5000);
        raw.setSoTimeout(15000);
        System.out.println("TCP connect successful, wrapping TLS socket and starting handshake...");

        SSLSocket socket = (SSLSocket) factory.createSocket(raw, CAUTH_HOST, CAUTH_PORT, true);
        socket.setSoTimeout(15000);

        try {
            socket.startHandshake();
            System.out.println("TLS handshake completed. Peer certificates:");
            java.security.cert.Certificate[] peerCerts = socket.getSession().getPeerCertificates();
            for (int i = 0; i < peerCerts.length; i++) {
                if (peerCerts[i] instanceof java.security.cert.X509Certificate) {
                    java.security.cert.X509Certificate x = (java.security.cert.X509Certificate) peerCerts[i];
                    System.out.println("  [" + i + "] subject=" + x.getSubjectX500Principal().getName());
                    System.out.println("      issuer=" + x.getIssuerX500Principal().getName());
                } else {
                    System.out.println("  [" + i + "] cert class=" + peerCerts[i].getClass().getName());
                }
            }
        } catch (SSLException se) {
            System.out.println("TLS handshake failed: " + se.getMessage());
            throw se;
        }

        System.out.println("Connected to CAuth at " + CAUTH_HOST + ":" + CAUTH_PORT);

        try (PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            JSONObject request = new JSONObject();
            request.put("method", "signCSR");
            request.put("csr", java.util.Base64.getEncoder().encodeToString(csr.getEncoded()));

            System.out.println("Sending CSR to CAuth...");
            writer.println(request.toString());

            System.out.println("Waiting for response (read timeout 15s)...");
            String response = reader.readLine();
            if (response == null) {
                System.out.println("No response received (reader returned null)");
                return new X509Certificate[] { null, null };
            }
            System.out.println("Received response from CAuth: " + (response.length() > 200 ? response.substring(0,200) + "..." : response));
            JSONObject jsonResponse = new JSONObject(response);

            if (jsonResponse.optString("response","").equals("Unknown method")) {
                System.out.println("CAuth responded Unknown method");
                return new X509Certificate[] { null, null };
            }

            // Parse certificates separately
            java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509");

            // Parse the signed certificate
            String certB64 = jsonResponse.getString("certificate");
            byte[] certBytes = java.util.Base64.getDecoder().decode(certB64);
            X509Certificate spCert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(certBytes)
            );

            // Parse root CA cert
            X509Certificate rootCert = null;
            if (jsonResponse.has("caCertificate")) {
                String caB64 = jsonResponse.getString("caCertificate");
                byte[] caBytes = java.util.Base64.getDecoder().decode(caB64);
                rootCert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(caBytes)
                );
                System.out.println("Received CA root certificate from CAuth.");
            }
            System.out.println("Certificate signed by CAuth!");

            if (rootCert != null) {
                return new X509Certificate[] { spCert, rootCert };
            } else {
                return new X509Certificate[] { spCert };
            }

        } finally {
            try { socket.close(); } catch (Exception ignore) {}
        }
    }
    
    /**
     * Store the certificate and private key in a keystore
     */
    private static void storeCertificateAndKey(X509Certificate[] chain) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        
        File keystoreFile = new File(SP_KEYSTORE_PATH);
        if (keystoreFile.exists()) {
            try (FileInputStream fis = new FileInputStream(SP_KEYSTORE_PATH)) {
                ks.load(fis, SP_KEYSTORE_PASSWORD.toCharArray());
            }
        } else {
            ks.load(null, null);
        }

        // Use the chain as received from CAuth (already contains [SP cert, Root CA])
        System.out.println("Storing certificate chain with " + chain.length + " certificate(s)");
        for (int i = 0; chain[i]!=null && i < chain.length; i++) {
            System.out.println("  [" + i + "] " + chain[i].getSubjectX500Principal().getName());
        }
        System.out.println("\nVerifying stored certificate chain:");
        if (chain[0]!=null)
            ks.setKeyEntry(
                SP_KEY_ALIAS,
                spKeyPair.getPrivate(),
                SP_KEYSTORE_PASSWORD.toCharArray(),
                chain
            );
        else
            System.out.println("Fake certificate detected!");
        // Verify the chain was stored correctly
        java.security.cert.Certificate[] storedChain = ks.getCertificateChain(SP_KEY_ALIAS);
        for (int i = 0; storedChain!=null && i < storedChain.length; i++) {
            X509Certificate cert = (X509Certificate) storedChain[i];
            System.out.println("  [" + i + "]");
            System.out.println("    Subject: " + cert.getSubjectX500Principal().getName());
            System.out.println("    Issuer:  " + cert.getIssuerX500Principal().getName());
            System.out.println("    Valid from: " + cert.getNotBefore());
            System.out.println("    Valid to:   " + cert.getNotAfter());
        }
        try (FileOutputStream fos = new FileOutputStream(SP_KEYSTORE_PATH)) {
            ks.store(fos, SP_KEYSTORE_PASSWORD.toCharArray());
        }
    }
    
    /**
     * Start TLS server to accept client connections
     */
    private static void startServer() throws Exception {
        // Load truststore (contains CAuth's root certificate for verifying HO certs)
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(fis, TRUSTSTORE_PASSWORD.toCharArray());
        }
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm()
        );
        tmf.init(trustStore);
        
        // Load our keystore (contains our certificate and private key)
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(SP_KEYSTORE_PATH)) {
            keyStore.load(fis, SP_KEYSTORE_PASSWORD.toCharArray());
        }
        
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm()
        );
        kmf.init(keyStore, SP_KEYSTORE_PASSWORD.toCharArray());
        
        // Create SSL context with both key managers and trust managers
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        
        // Create SSL server socket
        SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(SP_SERVER_PORT);
        
        // Require client authentication
        serverSocket.setNeedClientAuth(false);
        
        System.out.println("SP Server started on port " + SP_SERVER_PORT);
        System.out.println("Waiting for inbound connections...");
        
        // Create thread pool for handling clients
        ExecutorService executor = Executors.newCachedThreadPool();
        
        while (true) {
            SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
            executor.submit(new ClientHandler(clientSocket));
        }
    }

    /**
     * Handler for client connections
     */
    static class ClientHandler implements Runnable {
        private SSLSocket clientSocket;
        
        public ClientHandler(SSLSocket clientSocket) {
            this.clientSocket = clientSocket;
        }
        
        @Override
        public void run() {
            String cn = null;
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(clientSocket.getInputStream()));
                 PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true)) {
                
                System.out.println("\n=== Inbound Connection ===");

                // Force handshake to complete before accessing peer certificates
                clientSocket.startHandshake();
                // Get client certificate
                X509Certificate[] clientCerts = (X509Certificate[]) clientSocket.getSession()
                    .getPeerCertificates();
                String dn = clientCerts[0].getSubjectX500Principal().getName();

                try {
                    LdapName ldapDN = new LdapName(dn);
                    for (Rdn rdn : ldapDN.getRdns()) {
                        if (rdn.getType().equalsIgnoreCase("CN")) {
                            cn = rdn.getValue().toString();
                            break;
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                System.out.println("\n=== "+cn+" Connected ===");
                System.out.println("Client address: " + clientSocket.getRemoteSocketAddress());
                System.out.println("Client certificate: " + clientCerts[0].getSubjectX500Principal().getName());
                System.out.println("Certificate issuer: " + clientCerts[0].getIssuerX500Principal().getName());
                System.out.println("Cipher suite: " + clientSocket.getSession().getCipherSuite());
                System.out.println("Protocol: " + clientSocket.getSession().getProtocol());
                
                String inputLine;
                while ((inputLine = reader.readLine()) != null) {
                    try {
                        JSONObject request = new JSONObject(inputLine);
                        System.out.println("\nReceived from "+cn+": " + request.toString(2));
                        
                        String method = request.getString("method");
                        JSONObject response = new JSONObject();
                        
                        switch (method) {
                            case "hello" -> {
                                response.put("status", "success");
                                response.put("message", "Hello "+clientCerts[0].getSubjectX500Principal().getName()+"! Welcome to SP.");
                                response.put("timestamp", new Date().toString());
                            }
                            default -> {
                                response.put("status", "error");
                                response.put("message", "Unknown method: " + method);
                            }
                        }
                        
                        writer.println(response.toString());
                        System.out.println("Sent response: " + response.toString(2));
                        
                    } catch (Exception e) {
                        System.err.println("Error processing request: " + e.getMessage());
                        JSONObject errorResponse = new JSONObject();
                        errorResponse.put("status", "error");
                        errorResponse.put("message", "Error processing request");
                        writer.println(errorResponse.toString());
                    }
                }
            
            } catch (Exception e) {
                System.err.println("Error handling client: " + e.getMessage());
                e.printStackTrace();
            } finally {
                try {
                    clientSocket.close();
                    System.out.println("\n"+cn+" disconnected");
                } catch (Exception e) {
                    System.err.println("Error closing socket: " + e.getMessage());
                }
            }
        }
    }
}
