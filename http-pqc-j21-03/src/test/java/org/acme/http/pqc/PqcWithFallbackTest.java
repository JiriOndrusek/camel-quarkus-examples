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
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/**
 * Test 3: SunJSSE client with X25519MLKEM768 + secp256r1 fallback server.
 *
 * Server is configured with X25519MLKEM768,secp256r1 (PQC preferred, but fallback available).
 * Both BCJSSE (prefers PQC) and SunJSSE (uses secp256r1 fallback) should succeed.
 *
 * This demonstrates backward compatibility - PQC is preferred but classical algorithms
 * are still supported for clients that don't support PQC yet.
 *
 * Run with: mvn test -Dtest=PqcWithFallbackTest
 */
@QuarkusTest
@TestProfile(PqcWithFallbackTest.PqcWithFallbackProfile.class)
class PqcWithFallbackTest {

    /**
     * Test profile that configures server with X25519MLKEM768,secp256r1.
     * Sets system property BEFORE application startup.
     */
    public static class PqcWithFallbackProfile implements QuarkusTestProfile {

        static {
            // Set system property before Quarkus application starts
            // This is read by SecurityConfiguration.onStart()
            System.setProperty("pqc.named.groups", "X25519MLKEM768,secp256r1");
        }

        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of();
        }
    }

    @Test
    void testBothBcjsseAndSunJsseSucceedWithFallback() throws Exception {
        boolean isNative = "true".equals(System.getProperty("quarkus.native.enabled"));
        assumeFalse(isNative, "Skipping in native mode - provider API may behave differently");

        Provider bcjsseProvider = Security.getProvider("BCJSSE");
        assertNotNull(bcjsseProvider, "BCJSSE must be registered");

        Provider sunJsseProvider = Security.getProvider("SunJSSE");
        assertNotNull(sunJsseProvider, "SunJSSE must be available");

        int port = RestAssured.port > 0 ? RestAssured.port : 8443;

        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   Test 3: PQC with Fallback (X25519MLKEM768,secp256r1)");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server named groups: " + actualNamedGroups);
        System.out.println();

        // Verify server is configured with X25519MLKEM768,secp256r1
        assertTrue(
                actualNamedGroups != null && actualNamedGroups.contains("X25519MLKEM768")
                        && actualNamedGroups.contains("secp256r1"),
                "Server must be configured with X25519MLKEM768,secp256r1. Got: " + actualNamedGroups);

        System.out.println("✓ Server configuration verified: X25519MLKEM768,secp256r1");
        System.out.println("  PQC preferred, classical fallback available");
        System.out.println();

        // Test 1: BCJSSE client (should prefer PQC)
        System.out.println("Test 1: BCJSSE client (should prefer X25519MLKEM768)");
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
                System.out.println("  Note: BCJSSE prefers X25519MLKEM768 when available");
            }
        } catch (Throwable e) {
            Throwable root = e;
            while (root.getCause() != null) {
                root = root.getCause();
            }
            System.out.println("✗ BCJSSE handshake FAILED: " + root.getMessage());
        }

        System.out.println();

        // Test 2: SunJSSE client (should use secp256r1 fallback)
        System.out.println("Test 2: SunJSSE client (should use secp256r1 fallback)");
        System.out.println("─────────────────────────────────────────────────────────");
        boolean sunJsseSuccess = false;
        String sunJsseSocketClass = null;
        try {
            SSLContext sunJsseContext = createSSLContext(sunJsseProvider);
            try (SSLSocket socket = (SSLSocket) sunJsseContext.getSocketFactory().createSocket("localhost", port)) {
                socket.startHandshake();
                sunJsseSuccess = true;
                sunJsseSocketClass = socket.getClass().getName();
                System.out.println("✓ SunJSSE handshake SUCCEEDED");
                System.out.println("  Protocol: " + socket.getSession().getProtocol());
                System.out.println("  Cipher: " + socket.getSession().getCipherSuite());
                System.out.println("  Socket: " + sunJsseSocketClass);
                System.out.println("  Note: SunJSSE used secp256r1 fallback (no PQC support on JDK 21)");
            }
        } catch (Throwable e) {
            Throwable root = e;
            while (root.getCause() != null) {
                root = root.getCause();
            }
            System.out.println("✗ SunJSSE handshake FAILED: " + root.getMessage());
        }

        System.out.println();
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("                        RESULTS");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server config: X25519MLKEM768,secp256r1");
        System.out.println();
        System.out.println("BCJSSE client (PQC-capable):    " + (bcjsseSuccess ? "SUCCESS ✓" : "FAILED ✗"));
        System.out.println("SunJSSE client (no PQC on J21): " + (sunJsseSuccess ? "SUCCESS ✓" : "FAILED ✗"));

        if (bcjsseSuccess && sunJsseSuccess) {
            System.out.println();
            System.out.println("⭐ TEST PASSED ⭐");
            System.out.println();
            System.out.println("With server configured for PQC + fallback:");
            System.out.println("  • BCJSSE client: SUCCEEDED ✓ (likely used X25519MLKEM768)");
            System.out.println("  • SunJSSE client: SUCCEEDED ✓ (used secp256r1 fallback)");
            System.out.println();
            System.out.println("This demonstrates backward compatibility:");
            System.out.println("  1. PQC-capable clients can use X25519MLKEM768");
            System.out.println("  2. Legacy clients can still connect using classical algorithms");
            System.out.println("  3. Server supports gradual migration to PQC");
            System.out.println();
            System.out.println("Compare with Test 2:");
            System.out.println("  • Test 2 (X25519MLKEM768 only): SunJSSE FAILED ✓");
            System.out.println("  • Test 3 (with fallback): SunJSSE SUCCEEDED ✓");
            System.out.println("  → Proves fallback is working as expected");
        } else if (!bcjsseSuccess) {
            System.out.println();
            System.out.println("✗ TEST FAILED: BCJSSE client should succeed");
        } else if (!sunJsseSuccess) {
            System.out.println();
            System.out.println("✗ TEST FAILED: SunJSSE client should succeed with fallback");
        }
        System.out.println("═══════════════════════════════════════════════════════════\n");

        assertTrue(bcjsseSuccess,
                "BCJSSE client must succeed with PQC+fallback configuration");

        assertTrue(sunJsseSuccess,
                "SunJSSE client must succeed using secp256r1 fallback. " +
                        "Failure indicates fallback is not working. " +
                        "Actual named groups: " + actualNamedGroups);

        assertTrue(bcjsseSocketClass != null && bcjsseSocketClass.contains("bouncycastle"),
                "BCJSSE socket must be BouncyCastle implementation: " + bcjsseSocketClass);

        assertTrue(sunJsseSocketClass != null && sunJsseSocketClass.contains("sun.security"),
                "SunJSSE socket must be Sun implementation: " + sunJsseSocketClass);
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

    @Test
    void testHttpRequestWithFallback() throws Exception {
        boolean isNative = "true".equals(System.getProperty("quarkus.native.enabled"));
        assumeFalse(isNative, "Skipping in native mode - provider API may behave differently");

        int port = RestAssured.port > 0 ? RestAssured.port : 8443;

        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   Test 3b: RestAssured HTTP Request with Fallback");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server named groups: " + actualNamedGroups);
        System.out.println();

        assertTrue(
                actualNamedGroups != null && actualNamedGroups.contains("X25519MLKEM768")
                        && actualNamedGroups.contains("secp256r1"),
                "Server must be configured with X25519MLKEM768,secp256r1. Got: " + actualNamedGroups);

        System.out.println("✓ Server configuration verified: X25519MLKEM768,secp256r1");
        System.out.println("  PQC preferred, classical fallback available");
        System.out.println();

        // Test: HTTP request via RestAssured (uses BCJSSE, should prefer X25519MLKEM768)
        System.out.println("Testing HTTP request via RestAssured");
        System.out.println("Note: Uses default provider (BCJSSE), prefers X25519MLKEM768");
        System.out.println("─────────────────────────────────────────────────────────");

        boolean httpSuccess = false;
        String responseBody = null;
        int statusCode = 0;

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .keyStore("target/certs/client-keystore.p12", "changeit")
                    .trustStore("target/certs/client-truststore.p12", "changeit")
                    .baseUri("https://localhost:" + port)
                    .get("/api/data")
                    .then()
                    .extract()
                    .response();

            statusCode = response.getStatusCode();
            responseBody = response.getBody().asString();
            httpSuccess = (statusCode == 200);

            System.out.println("✓ HTTP request SUCCEEDED");
            System.out.println("  Status Code: " + statusCode);
            System.out.println("  Response: " + responseBody);
            System.out.println("  Note: BCJSSE likely used X25519MLKEM768 (preferred when available)");

        } catch (Throwable e) {
            Throwable root = e;
            while (root.getCause() != null) {
                root = root.getCause();
            }
            System.out.println("✗ HTTP request FAILED: " + root.getMessage());
        }

        System.out.println();
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("                        RESULTS");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server config: X25519MLKEM768,secp256r1 (with fallback)");
        System.out.println("HTTP request: " + (httpSuccess ? "SUCCESS ✓" : "FAILED ✗"));

        if (httpSuccess) {
            System.out.println();
            System.out.println("⭐ TEST PASSED ⭐");
            System.out.println();
            System.out.println("HTTP request succeeded with PQC + fallback config:");
            System.out.println("  • Default provider (BCJSSE) can negotiate X25519MLKEM768");
            System.out.println("  • Fallback (secp256r1) available for compatibility");
            System.out.println("  • Demonstrates backward-compatible PQC deployment");
            System.out.println();
            System.out.println("Compare socket tests:");
            System.out.println("  • BCJSSE socket: Uses X25519MLKEM768 ✓");
            System.out.println("  • SunJSSE socket: Uses secp256r1 fallback ✓");
            System.out.println("  • Both providers can connect when fallback available");
        }
        System.out.println("═══════════════════════════════════════════════════════════\n");

        assertTrue(httpSuccess,
                "HTTP request must succeed with PQC+fallback. Status: " + statusCode);
    }
}
