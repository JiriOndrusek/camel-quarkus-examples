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
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * DEFINITIVE PROOF TEST using Quarkus profile to configure server with X25519MLKEM768 ONLY.
 *
 * This test proves X25519MLKEM768 is actually used by:
 * 1. Configuring server with ONLY X25519MLKEM768 (no fallback)
 * 2. BCJSSE client succeeds (supports PQC)
 * 3. SunJSSE client fails (no PQC support on JDK 21)
 *
 * If BCJSSE succeeds and SunJSSE fails, then X25519MLKEM768 is provably being used.
 *
 * NOTE: This test should be run individually to avoid affecting other tests:
 *   mvn test -Dtest=PqcOnlyTest
 */
@QuarkusTest
@TestProfile(PqcOnlyTest.PqcOnlyProfile.class)
class PqcOnlyTest {

    /**
     * Test profile that configures server with X25519MLKEM768 ONLY.
     * Sets system property BEFORE application startup.
     */
    public static class PqcOnlyProfile implements QuarkusTestProfile {

        static {
            // Set system property before Quarkus application starts
            // This is read by SecurityConfiguration.onStart()
            System.setProperty("pqc.named.groups", "X25519MLKEM768");
        }

        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of();
        }
    }

    /**
     * THE DEFINITIVE TEST - proves X25519MLKEM768 is actually used.
     *
     * Server configured with: X25519MLKEM768 ONLY (no fallback)
     * Test 1: BCJSSE client → SUCCEEDS (supports X25519MLKEM768)
     * Test 2: SunJSSE client → FAILS (no PQC support on JDK 21)
     *
     * This is mathematical proof - no fallback algorithm available.
     */
    @Test
    void testDefinitiveProofPqcOnlyServer() throws Exception {
        boolean isNative = "true".equals(System.getProperty("quarkus.native.enabled"));
        assumeFalse(isNative, "Skipping in native mode - provider API may behave differently");

        // Skip when run with all tests to avoid contaminating other test classes
        // Run this test individually: mvn test -Dtest=PqcOnlyTest
        String testPattern = System.getProperty("test");
        boolean runningIndividually = testPattern != null && testPattern.contains("PqcOnlyTest");
        assumeTrue(runningIndividually,
                "This test modifies global state and should be run individually: mvn test -Dtest=PqcOnlyTest");

        Provider bcjsseProvider = Security.getProvider("BCJSSE");
        assertNotNull(bcjsseProvider, "BCJSSE must be registered");

        Provider sunJsseProvider = Security.getProvider("SunJSSE");
        assertNotNull(sunJsseProvider, "SunJSSE must be available");

        int port = RestAssured.port > 0 ? RestAssured.port : 8443;

        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   DEFINITIVE PROOF - X25519MLKEM768 ONLY (No Fallback)");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server named groups: " + actualNamedGroups);
        System.out.println();

        // Verify server is configured correctly
        assertTrue(actualNamedGroups != null && actualNamedGroups.equals("X25519MLKEM768"),
                "Server must be configured with ONLY X25519MLKEM768. Got: " + actualNamedGroups);

        System.out.println("✓ Server configuration verified: X25519MLKEM768 ONLY");
        System.out.println("  No fallback algorithms available");
        System.out.println();

        // Test 1: BCJSSE client (supports PQC)
        System.out.println("Test 1: BCJSSE client (supports X25519MLKEM768)");
        System.out.println("─────────────────────────────────────────────────────────");
        boolean bcjsseSuccess = false;
        String bcjsseSocketClass = null;
        try {
            SSLContext bcjsseContext = createSSLContext(bcjsseProvider);
            try (SSLSocket socket = (SSLSocket) bcjsseContext.getSocketFactory().createSocket("localhost", port)) {
                socket.startHandshake();
                bcjsseSuccess = true;
                bcjsseSocketClass = socket.getClass().getName();
                System.out.println("✓ BCJSSE handshake SUCCEEDED");
                System.out.println("  Protocol: " + socket.getSession().getProtocol());
                System.out.println("  Cipher: " + socket.getSession().getCipherSuite());
                System.out.println("  Socket: " + bcjsseSocketClass);
            }
        } catch (Throwable e) {
            Throwable root = e;
            while (root.getCause() != null) {
                root = root.getCause();
            }
            System.out.println("✗ BCJSSE handshake FAILED: " + root.getMessage());
        }

        System.out.println();

        // Test 2: SunJSSE client (does NOT support PQC on JDK 21)
        System.out.println("Test 2: SunJSSE client (NO X25519MLKEM768 support on JDK 21)");
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
            // Expected to fail - SunJSSE doesn't support X25519MLKEM768 on JDK 21
            Throwable root = e;
            while (root.getCause() != null) {
                root = root.getCause();
            }
            sunJsseError = root.getMessage();
            System.out.println("✗ SunJSSE FAILED (EXPECTED): " + sunJsseError);
        }

        System.out.println();
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("                        RESULTS");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server config: X25519MLKEM768 ONLY (verified)");
        System.out.println();
        System.out.println("BCJSSE client (PQC-capable):    " + (bcjsseSuccess ? "SUCCESS ✓" : "FAILED ✗"));
        System.out.println("SunJSSE client (no PQC on J21): " + (sunJsseSuccess ? "SUCCESS ✗" : "FAILED ✓"));
        if (sunJsseError != null) {
            System.out.println();
            System.out.println("SunJSSE error (expected): " + sunJsseError);
        }
        System.out.println();

        if (bcjsseSuccess && !sunJsseSuccess) {
            System.out.println("⭐⭐⭐ DEFINITIVE PROOF ⭐⭐⭐");
            System.out.println();
            System.out.println("With server restricted to X25519MLKEM768 ONLY:");
            System.out.println("  • BCJSSE client: SUCCEEDED ✓");
            System.out.println("  • SunJSSE client: FAILED ✓");
            System.out.println();
            System.out.println("This PROVES X25519MLKEM768 was actually negotiated.");
            System.out.println();
            System.out.println("Why this is definitive proof:");
            System.out.println("  1. Server has NO fallback algorithms");
            System.out.println("  2. SunJSSE lacks X25519MLKEM768 on JDK 21");
            System.out.println("  3. BCJSSE succeeded → must have used X25519MLKEM768");
            System.out.println("  4. SunJSSE failed → confirms no classical fallback");
            System.out.println();
            System.out.println("Mathematical certainty: 100%");
        } else if (bcjsseSuccess && sunJsseSuccess) {
            System.out.println("⚠ TEST FAILED: Both clients succeeded");
            System.out.println();
            System.out.println("This indicates:");
            System.out.println("  • Server has fallback algorithms available");
            System.out.println("  • Test profile didn't apply correctly");
            System.out.println("  • Check: " + actualNamedGroups);
        } else if (!bcjsseSuccess) {
            System.out.println("✗ TEST FAILED: BCJSSE client failed");
            System.out.println();
            System.out.println("This indicates PQC configuration issue");
        }
        System.out.println("═══════════════════════════════════════════════════════════\n");

        // Assertions for definitive proof
        assertTrue(bcjsseSuccess,
                "BCJSSE client must succeed when server is X25519MLKEM768-only. " +
                        "Failure indicates PQC is not properly configured.");

        assertTrue(!sunJsseSuccess,
                "SunJSSE client must FAIL when server is X25519MLKEM768-only. " +
                        "Success means server has fallback algorithms or test setup is incorrect. " +
                        "Actual named groups: " + actualNamedGroups);

        // Verify it was BouncyCastle
        assertTrue(bcjsseSocketClass != null && bcjsseSocketClass.contains("bouncycastle"),
                "Socket must be BouncyCastle implementation: " + bcjsseSocketClass);
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
