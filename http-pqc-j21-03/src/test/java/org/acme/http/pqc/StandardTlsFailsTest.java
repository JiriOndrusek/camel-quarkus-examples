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
import java.net.URL;
import java.security.KeyStore;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManagerFactory;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Test 2: Standard Java TLS client fails with PQC-only server.
 *
 * This test verifies that a standard Java JSSE client (SunJSSE) FAILS
 * to connect to a server configured with X25519MLKEM768 ONLY, because
 * standard Java TLS 1.3 does not support Post-Quantum Cryptography.
 *
 * Run with: mvn test -Dtest=StandardTlsFailsTest
 */
@QuarkusTest
@TestProfile(StandardTlsFailsTest.PqcOnlyProfile.class)
class StandardTlsFailsTest {

    public static class PqcOnlyProfile implements QuarkusTestProfile {

        @Override
        public String getConfigProfile() {
            return "pqc-only";
        }
    }

    @Test
    void testStandardJavaTlsFailsWithPqcOnly() throws Exception {
        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   Test 2: Standard Java TLS FAILS (PQC-Only Server)");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server named groups: " + actualNamedGroups);
        System.out.println();

        assertTrue(actualNamedGroups != null && actualNamedGroups.equals("X25519MLKEM768"),
                "Server must be configured with ONLY X25519MLKEM768. Got: " + actualNamedGroups);

        System.out.println("✓ Server configuration verified: X25519MLKEM768 ONLY");
        System.out.println("  Testing with standard Java TLS (SunJSSE) - should FAIL");
        System.out.println();

        int port = RestAssured.port > 0 ? RestAssured.port : 8443;

        // Create SSLContext using standard Java JSSE (SunJSSE) explicitly
        SSLContext sslContext = createStandardJavaSslContext();

        // Try to connect using standard Java HTTPS - should FAIL
        boolean failedAsExpected = false;
        try {
            URL url = new URL("https://localhost:" + port + "/api/data");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());

            // Disable hostname verification for self-signed cert
            conn.setHostnameVerifier((hostname, session) -> true);

            conn.connect();
            int responseCode = conn.getResponseCode();
            conn.disconnect();

            // If we get here, the connection succeeded when it should have failed
            fail("Standard Java TLS should have failed to connect to PQC-only server, but got response code: " + responseCode);

        } catch (SSLHandshakeException e) {
            System.out.println("✓ Standard Java TLS connection FAILED as expected (handshake)");
            System.out.println("  Error: " + e.getMessage());
            failedAsExpected = true;
        } catch (ExceptionInInitializerError e) {
            // SunJSSE doesn't even recognize X25519MLKEM768 as a valid named group
            Throwable cause = e.getCause();
            if (cause != null && cause.getMessage().contains("contains no supported named groups")) {
                System.out.println("✓ Standard Java TLS FAILED as expected (initialization)");
                System.out.println("  Error: " + cause.getMessage());
                failedAsExpected = true;
            } else {
                throw e;
            }
        }

        if (failedAsExpected) {
            System.out.println("  This proves X25519MLKEM768 requires BouncyCastle JSSE");
            System.out.println("═══════════════════════════════════════════════════════════\n");
        }
    }

    private SSLContext createStandardJavaSslContext() throws Exception {
        // Load keystores
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream("target/certs/client-keystore.p12")) {
            keyStore.load(fis, "changeit".toCharArray());
        }

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream("target/certs/client-truststore.p12")) {
            trustStore.load(fis, "changeit".toCharArray());
        }

        // Initialize key and trust managers
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "changeit".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // Create SSLContext using SunJSSE provider explicitly
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "SunJSSE");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return sslContext;
    }
}
