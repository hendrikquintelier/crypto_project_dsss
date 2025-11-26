package com.example;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import org.json.JSONObject;

public class Main {
    private static final int PORT = 8443;
    private static final String KEYSTORE_PATH = "./keystore.p12"; // Changed from truststore
    private static final String KEYSTORE_PASSWORD = "serverpassword";
    private static final String ROOT_CA_ALIAS = "root_ca";
    private static KeyStore keyStore;

    static {
        // Register Bouncy Castle as a static security provider if not already present
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            System.out.println("BouncyCastle provider added");
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println("Loading keystore: "+KEYSTORE_PATH);
            // Load the keystore (server's private key and certificate)
            keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
                keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
            }

            // Create KeyManagerFactory for server certificate
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            // Create SSL context with server certificate
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null); // No trust managers needed

            // Create SSL server socket
            SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(PORT);
            serverSocket.setNeedClientAuth(false);
            serverSocket.setWantClientAuth(false);

            System.out.println("TLS Server started on port " + PORT);

            // Create thread pool for handling clients
            ExecutorService executor = Executors.newCachedThreadPool();

            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                executor.submit(new ClientHandler(clientSocket));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

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

                while ((inputLine = reader.readLine()) != null) {
                    jsonBuffer.append(inputLine);

                    // Try to parse the accumulated data as JSON
                    try {
                        JSONObject jsonRequest = new JSONObject(jsonBuffer.toString());
                        System.out.println("Received JSON: " + jsonRequest.toString(2));

                        switch (jsonRequest.get("method").toString()) {
                            case "test" -> {
                                // Handle registration logic here
                                System.out.println("test method invoked");
                                JSONObject responseJson = new JSONObject();
                                responseJson.put("response", "Test method executed");
                                writer.write(responseJson.toString() + "\n");
                                writer.flush();
                            }
                            default -> {
                                System.out.println("Unknown method: " + jsonRequest.get("method"));
                                JSONObject responseJson = new JSONObject();
                                responseJson.put("response", "Unknown method");
                                writer.write(responseJson.toString() + "\n");
                                writer.flush();
                            }
                        }

                        // Reset buffer for next JSON object
                        jsonBuffer.setLength(0);

                    } catch (Exception e) {
                        // Not a complete JSON yet, continue reading
                        continue;
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