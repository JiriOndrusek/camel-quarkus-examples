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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/**
 * Test 1: BouncyCastle JSSE client with X25519MLKEM768-only server.
 *
 * Server is configured with ONLY X25519MLKEM768 (no fallback).
 * BCJSSE client supports PQC and should succeed.
 *
 * Run with: mvn test -Dtest=PqcOnlyBcjsseTest
 */
@QuarkusTest
@TestProfile(PqcOnlyBcjsseTest.PqcOnlyProfile.class)
class PqcOnlyBcjsseTest {

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
            return "pqc-only";
        }
    }

    @BeforeAll
    static void setupPqcConfiguration() {
        // Additional reinforcement of the system property
        // Note: This runs AFTER Quarkus startup, but good for documentation
        System.setProperty("pqc.named.groups", "X25519MLKEM768");
        System.out.println("@BeforeAll: Set jdk.tls.namedGroups = " + System.getProperty("jdk.tls.namedGroups"));
    }

    @Test
    void testBcjsseSucceedsWithPqcOnly() throws Exception {
        boolean isNative = "true".equals(System.getProperty("quarkus.native.enabled"));
        assumeFalse(isNative, "Skipping in native mode - provider API may behave differently");

        Provider bcjsseProvider = Security.getProvider("BCJSSE");
        assertNotNull(bcjsseProvider, "BCJSSE must be registered");

        int port = RestAssured.port > 0 ? RestAssured.port : 8443;

        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   Test 1: BCJSSE Client with X25519MLKEM768-Only Server");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server named groups: " + actualNamedGroups);
        System.out.println();

        // Verify server is configured with X25519MLKEM768 only
        assertTrue(actualNamedGroups != null && actualNamedGroups.equals("X25519MLKEM768"),
                "Server must be configured with ONLY X25519MLKEM768. Got: " + actualNamedGroups);

        System.out.println("✓ Server configuration verified: X25519MLKEM768 ONLY");
        System.out.println("  No fallback algorithms available");
        System.out.println();

        // Test: BCJSSE client (supports PQC)
        System.out.println("Testing BCJSSE client (supports X25519MLKEM768)");
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
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("                        RESULTS");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server config: X25519MLKEM768 ONLY");
        System.out.println("BCJSSE client (PQC-capable): " + (bcjsseSuccess ? "SUCCESS ✓" : "FAILED ✗"));

        if (bcjsseSuccess) {
            System.out.println();
            System.out.println("⭐ TEST PASSED ⭐");
            System.out.println("BCJSSE client successfully connected using X25519MLKEM768");
        }
        System.out.println("═══════════════════════════════════════════════════════════\n");

        assertTrue(bcjsseSuccess,
                "BCJSSE client must succeed when server is X25519MLKEM768-only. " +
                        "Failure indicates PQC is not properly configured.");

        assertTrue(bcjsseSocketClass != null && bcjsseSocketClass.contains("bouncycastle"),
                "Socket must be BouncyCastle implementation: " + bcjsseSocketClass);
    }

    @Test
    void testHttpRequestWithPqcOnly() throws Exception {
        boolean isNative = "true".equals(System.getProperty("quarkus.native.enabled"));
        assumeFalse(isNative, "Skipping in native mode - provider API may behave differently");

        int port = RestAssured.port > 0 ? RestAssured.port : 8443;

        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   Test 1b: RestAssured HTTP Request (X25519MLKEM768-Only)");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server named groups: " + actualNamedGroups);
        System.out.println();

        assertTrue(actualNamedGroups != null && actualNamedGroups.equals("X25519MLKEM768"),
                "Server must be configured with ONLY X25519MLKEM768. Got: " + actualNamedGroups);

        System.out.println("✓ Server configuration verified: X25519MLKEM768 ONLY");
        System.out.println();

        // Test: HTTP request via RestAssured (uses BCJSSE as default provider)
        System.out.println("Testing HTTP request via RestAssured");
        System.out.println("Note: Uses BCJSSE (provider at position 1) for TLS");
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
            System.out.println("  Endpoint: /api/data");
            System.out.println("  Provider: BCJSSE (default, supports X25519MLKEM768)");

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
            System.out.println("HTTP request succeeded via X25519MLKEM768");
            System.out.println("(BCJSSE is the default provider and supports PQC)");
        }
        System.out.println("═══════════════════════════════════════════════════════════\n");

        assertTrue(httpSuccess,
                "HTTP request must succeed when server is X25519MLKEM768-only. " +
                        "Status: " + statusCode + ", Response: " + responseBody);
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
