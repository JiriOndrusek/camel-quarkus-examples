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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/**
 * Test 2: Standard Java TLS 1.3 (SunJSSE) client with X25519MLKEM768-only server.
 *
 * Server is configured with ONLY X25519MLKEM768 (no fallback).
 * SunJSSE does NOT support X25519MLKEM768 on JDK 21, so connection should FAIL.
 *
 * This proves that X25519MLKEM768 is actually required by the server.
 *
 * Run with: mvn test -Dtest=StandardTlsFailsTest
 */
@QuarkusTest
@TestProfile(StandardTlsFailsTest.PqcOnlyProfile.class)
class StandardTlsFailsTest {

    /**
     * Test profile that configures server with X25519MLKEM768 ONLY.
     * Sets system property BEFORE application startup.
     */
    public static class PqcOnlyProfile implements QuarkusTestProfile {

        // Static block ensures property is set early
        static {
            System.setProperty("pqc.named.groups", "X25519MLKEM768");
        }

        @Override
        public Map<String, String> getConfigOverrides() {
            // Reinforce the property setting
            System.setProperty("pqc.named.groups", "X25519MLKEM768");
            return Map.of();
        }

        @Override
        public String getConfigProfile() {
            // Ensure this test runs with its own isolated configuration
            return "pqc-only-standard-tls";
        }
    }

    @Test
    void testSunJsseFailsWithPqcOnly() throws Exception {
        boolean isNative = "true".equals(System.getProperty("quarkus.native.enabled"));
        assumeFalse(isNative, "Skipping in native mode - provider API may behave differently");

        Provider sunJsseProvider = Security.getProvider("SunJSSE");
        assertNotNull(sunJsseProvider, "SunJSSE must be available");

        int port = RestAssured.port > 0 ? RestAssured.port : 8443;

        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   Test 2: SunJSSE Client with X25519MLKEM768-Only Server");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server named groups: " + actualNamedGroups);
        System.out.println();

        // Verify server is configured with X25519MLKEM768 only
        assertTrue(actualNamedGroups != null && actualNamedGroups.equals("X25519MLKEM768"),
                "Server must be configured with ONLY X25519MLKEM768. Got: " + actualNamedGroups);

        System.out.println("✓ Server configuration verified: X25519MLKEM768 ONLY");
        System.out.println("  No fallback algorithms available");
        System.out.println();

        // Test: SunJSSE client (does NOT support PQC on JDK 21)
        System.out.println("Testing SunJSSE client (NO X25519MLKEM768 support on JDK 21)");
        System.out.println("─────────────────────────────────────────────────────────");
        boolean sunJsseSuccess = false;
        String sunJsseError = null;
        try {
            SSLContext sunJsseContext = createSSLContext(sunJsseProvider);
            try (SSLSocket socket = (SSLSocket) sunJsseContext.getSocketFactory().createSocket("localhost", port)) {
                socket.startHandshake();
                sunJsseSuccess = true;
                System.out.println("✓ SunJSSE handshake SUCCEEDED (unexpected!)");
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
        System.out.println("Server config: X25519MLKEM768 ONLY");
        System.out.println("SunJSSE client (no PQC on J21): " + (sunJsseSuccess ? "SUCCESS ✗" : "FAILED ✓"));

        if (sunJsseError != null) {
            System.out.println();
            System.out.println("SunJSSE error (expected): " + sunJsseError);
        }

        if (!sunJsseSuccess) {
            System.out.println();
            System.out.println("⭐ TEST PASSED ⭐");
            System.out.println("SunJSSE client correctly failed - proves X25519MLKEM768 is required");
            System.out.println();
            System.out.println("Why this is important:");
            System.out.println("  • Server has NO fallback algorithms");
            System.out.println("  • SunJSSE lacks X25519MLKEM768 on JDK 21");
            System.out.println("  • Connection failure proves PQC is enforced");
        } else {
            System.out.println();
            System.out.println("✗ TEST FAILED: SunJSSE should not succeed");
            System.out.println("This indicates server has fallback algorithms available");
        }
        System.out.println("═══════════════════════════════════════════════════════════\n");

        assertFalse(sunJsseSuccess,
                "SunJSSE client must FAIL when server is X25519MLKEM768-only. " +
                        "Success means server has fallback algorithms or test setup is incorrect. " +
                        "Actual named groups: " + actualNamedGroups);
    }

    @Test
    void testHttpRequestSucceedsWithDefaultProvider() throws Exception {
        boolean isNative = "true".equals(System.getProperty("quarkus.native.enabled"));
        assumeFalse(isNative, "Skipping in native mode - provider API may behave differently");

        int port = RestAssured.port > 0 ? RestAssured.port : 8443;

        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   Test 2b: RestAssured HTTP Request with Default Provider");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server named groups: " + actualNamedGroups);
        System.out.println();

        assertTrue(actualNamedGroups != null && actualNamedGroups.equals("X25519MLKEM768"),
                "Server must be configured with ONLY X25519MLKEM768. Got: " + actualNamedGroups);

        System.out.println("✓ Server configuration verified: X25519MLKEM768 ONLY");
        System.out.println();

        // Test: HTTP request via RestAssured (uses default provider = BCJSSE)
        System.out.println("Testing HTTP request via RestAssured");
        System.out.println("Note: Uses default provider (BCJSSE at position 1)");
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
            System.out.println("  Note: Used BCJSSE (default provider supports X25519MLKEM768)");

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
        System.out.println("Server config: X25519MLKEM768 ONLY");
        System.out.println("HTTP request: " + (httpSuccess ? "SUCCESS ✓" : "FAILED ✗"));

        if (httpSuccess) {
            System.out.println();
            System.out.println("⭐ TEST PASSED ⭐");
            System.out.println("HTTP request succeeded using default provider (BCJSSE)");
            System.out.println("Demonstrates that HTTP endpoints work with PQC");
        }
        System.out.println("═══════════════════════════════════════════════════════════\n");

        assertTrue(httpSuccess,
                "HTTP request must succeed with default provider (BCJSSE). " +
                        "Status: " + statusCode);
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
