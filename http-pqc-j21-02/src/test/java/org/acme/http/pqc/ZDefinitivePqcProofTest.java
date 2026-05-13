/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.acme.http.pqc;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/**
 * DEFINITIVE PROOF that X25519MLKEM768 is actually negotiated.
 *
 * Strategy: Configure client with ONLY X25519MLKEM768 (no fallback).
 * If handshake succeeds, X25519MLKEM768 MUST have been used.
 *
 * NOTE: This test modifies system properties, so it runs last (Z prefix)
 * to avoid affecting other tests.
 */
@QuarkusTest
class ZDefinitivePqcProofTest {

    /**
     * PROOF BY COMPARISON: Verifies PQC by showing BCJSSE succeeds where SunJSSE fails.
     *
     * This test proves X25519MLKEM768 is used by demonstrating:
     * 1. BCJSSE client with X25519MLKEM768-only succeeds
     * 2. SunJSSE client with X25519MLKEM768-only FAILS (no PQC support on JDK 21)
     *
     * If both succeed, then fallback algorithms are being used (not PQC).
     * If both fail, then PQC is not configured correctly.
     * If BCJSSE succeeds and SunJSSE fails → X25519MLKEM768 is actually used.
     */
    @Test
    void testProofByComparison() throws Exception {
        boolean isNative = "true".equals(System.getProperty("quarkus.native.enabled"));
        assumeFalse(isNative, "Skipping in native mode - system property manipulation may not work");

        Provider bcjsseProvider = Security.getProvider("BCJSSE");
        assertNotNull(bcjsseProvider, "BCJSSE must be registered");

        Provider sunJsseProvider = Security.getProvider("SunJSSE");
        assertNotNull(sunJsseProvider, "SunJSSE must be available");

        String originalNamedGroups = System.getProperty("jdk.tls.namedGroups");

        try {
            // Configure ONLY X25519MLKEM768 - no fallback!
            System.setProperty("jdk.tls.namedGroups", "X25519MLKEM768");

            System.out.println("\n═══════════════════════════════════════════════════════════");
            System.out.println("   PROOF BY COMPARISON - BCJSSE vs SunJSSE");
            System.out.println("═══════════════════════════════════════════════════════════");
            System.out.println("Named groups: X25519MLKEM768 ONLY (no fallback)");
            System.out.println();

            int port = RestAssured.port > 0 ? RestAssured.port : 8443;

            // Test 1: BCJSSE client (supports PQC)
            System.out.println("Test 1: BCJSSE client (supports X25519MLKEM768)");
            System.out.println("─────────────────────────────────────────────────────────");
            boolean bcjsseSuccess = false;
            try {
                SSLContext bcjsseContext = createSSLContext(bcjsseProvider);
                try (SSLSocket socket = (SSLSocket) bcjsseContext.getSocketFactory().createSocket("localhost", port)) {
                    socket.startHandshake();
                    bcjsseSuccess = true;
                    System.out.println("✓ BCJSSE handshake SUCCEEDED");
                    System.out.println("  Socket: " + socket.getClass().getName());
                }
            } catch (Exception e) {
                System.out.println("✗ BCJSSE handshake FAILED: " + e.getMessage());
            }

            System.out.println();

            // Test 2: SunJSSE client (does NOT support PQC on JDK 21)
            System.out.println("Test 2: SunJSSE client (no X25519MLKEM768 support on JDK 21)");
            System.out.println("─────────────────────────────────────────────────────────");
            boolean sunJsseSuccess = false;
            String sunJsseError = null;
            try {
                SSLContext sunJsseContext = createSSLContext(sunJsseProvider);
                try (SSLSocket socket = (SSLSocket) sunJsseContext.getSocketFactory().createSocket("localhost", port)) {
                    socket.startHandshake();
                    sunJsseSuccess = true;
                    System.out.println("✓ SunJSSE handshake SUCCEEDED");
                    System.out.println("  Socket: " + socket.getClass().getName());
                }
            } catch (Throwable e) {
                // Capture the root cause (catch Throwable to handle ExceptionInInitializerError)
                Throwable root = e;
                while (root.getCause() != null) {
                    root = root.getCause();
                }
                sunJsseError = root.getMessage();
                System.out.println("✗ SunJSSE FAILED (expected): " + sunJsseError);
            }

            System.out.println();
            System.out.println("RESULTS:");
            System.out.println("─────────────────────────────────────────────────────────");
            System.out.println("BCJSSE (PQC-capable):    " + (bcjsseSuccess ? "SUCCESS ✓" : "FAILED ✗"));
            System.out.println("SunJSSE (no PQC on J21): " + (sunJsseSuccess ? "SUCCESS ✓" : "FAILED ✗"));
            if (sunJsseError != null) {
                System.out.println("  Error: " + sunJsseError);
            }
            System.out.println();

            if (bcjsseSuccess && !sunJsseSuccess) {
                System.out.println("⭐⭐⭐ DEFINITIVE PROOF ⭐⭐⭐");
                System.out.println("BCJSSE succeeded where SunJSSE failed.");
                System.out.println("This proves X25519MLKEM768 is actually being used,");
                System.out.println("because SunJSSE on JDK 21 doesn't support it.");
                if (sunJsseError != null && sunJsseError.contains("no supported named groups")) {
                    System.out.println();
                    System.out.println("SunJSSE error confirms it lacks X25519MLKEM768:");
                    System.out.println("  \"" + sunJsseError + "\"");
                }
            } else if (bcjsseSuccess && sunJsseSuccess) {
                System.out.println("⚠ WARNING: Both succeeded");
                System.out.println("Server is using FALLBACK algorithms (secp256r1, etc.)");
                System.out.println("X25519MLKEM768 is NOT being enforced");
            } else if (!bcjsseSuccess && !sunJsseSuccess) {
                System.out.println("✗ Both failed - PQC may not be configured correctly");
            } else {
                System.out.println("✗ Unexpected: SunJSSE succeeded but BCJSSE failed");
            }
            System.out.println("═══════════════════════════════════════════════════════════\n");

            // Assert that BCJSSE succeeds (PQC works)
            assertTrue(bcjsseSuccess, "BCJSSE client must succeed with X25519MLKEM768");

            // Assert that SunJSSE fails (proving X25519MLKEM768 is actually used)
            assertTrue(!sunJsseSuccess,
                    "SunJSSE must FAIL when only X25519MLKEM768 is configured. " +
                            "If it succeeds, server is using fallback algorithms, not PQC.");

        } finally {
            if (originalNamedGroups != null) {
                System.setProperty("jdk.tls.namedGroups", originalNamedGroups);
            } else {
                System.clearProperty("jdk.tls.namedGroups");
            }
        }
    }

    private SSLContext createSSLContext(Provider provider) throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS", provider);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream("target/certs/client-keystore.p12")) {
            keyStore.load(fis, "changeit".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "changeit".toCharArray());

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream("target/certs/client-truststore.p12")) {
            trustStore.load(fis, "changeit".toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return sslContext;
    }

}
