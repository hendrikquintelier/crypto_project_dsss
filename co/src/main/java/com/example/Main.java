package com.example;

public class Main {

    public static void main(String[] args) {
        System.out.println("[CO] Car Owner service starting...");

        // Just keep the container alive and print a heartbeat
        try {
            while (true) {
                System.out.println("[CO] Still running (test setup only)...");
                Thread.sleep(30000); // 30 seconds
            }
        } catch (InterruptedException e) {
            System.out.println("[CO] Interrupted, shutting down.");
            Thread.currentThread().interrupt();
        }
    }
}
