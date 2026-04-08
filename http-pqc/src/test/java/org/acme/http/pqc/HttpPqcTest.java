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

import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
public class HttpPqcTest {

    @BeforeAll
    public static void setUp() {
        // Use relaxed HTTPS validation for self-signed certificates in tests
        RestAssured.useRelaxedHTTPSValidation();
    }

    @Test
    public void testBouncyCastleProviderRegistered() {
        // Verify BouncyCastle provider is registered
        Provider bcProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(bcProvider, "BouncyCastle provider should be registered");
        assertEquals("BC", bcProvider.getName(), "Provider name should be BC");
    }

    @Test
    public void testBouncyCastleAtPositionOne() {
        // Verify BouncyCastle is at position 1 for priority
        Provider[] providers = Security.getProviders();
        assertNotNull(providers, "Security providers should not be null");
        assertEquals("BC", providers[0].getName(),
                "BouncyCastle should be at position 1 for PQC algorithm priority");
    }

    @Test
    public void testDilithiumAlgorithmAvailable() throws Exception {
        // Verify Dilithium3 (ML-DSA-65 equivalent) signature algorithm is available
        Signature signature = Signature.getInstance("Dilithium3", "BC");
        assertNotNull(signature, "Dilithium3 signature instance should be created");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium3", "BC");
        assertNotNull(kpg, "Dilithium3 KeyPairGenerator should be available");
    }

    @Test
    public void testPqcHybridEndpoint() {
        // Note: With client-auth=required, ALL endpoints require client certificates
        // The /pqc/hybrid endpoint provides certificate info but still requires TLS auth
        // Testing without certificate to verify TLS-layer enforcement
        try {
            RestAssured.given()
                    .when()
                    .get("https://localhost:8443/pqc/hybrid")
                    .then()
                    .statusCode(200);

            // If we reach here, test should fail (expected SSL exception)
            assert false : "Expected SSL exception but connection succeeded";
        } catch (Exception e) {
            // Expected: SSL handshake failure (certificate_required)
            System.out.println("✓ Expected SSL exception for /pqc/hybrid without cert: " + e.getMessage());
            assertTrue(e.getMessage().contains("certificate_required") ||
                    e.getMessage().contains("Received fatal alert"),
                    "Expected certificate_required SSL error, got: " + e.getMessage());
        }
    }

    @Test
    public void testPqcSecureEndpointWithoutClientCert() {
        // Test /pqc/secure without client certificate
        // With client-auth=required, TLS handshake fails before reaching the route
        try {
            RestAssured.given()
                    .when()
                    .get("https://localhost:8443/pqc/secure")
                    .then()
                    .statusCode(200); // Should not reach here

            // If no exception, test should fail
            assert false : "Expected SSL exception but connection succeeded";
        } catch (Exception e) {
            // Expected: SSL/TLS handshake failure (certificate_required)
            System.out.println("✓ Expected SSL exception: " + e.getMessage());
            assertTrue(e.getMessage().contains("certificate_required") ||
                    e.getMessage().contains("Received fatal alert"),
                    "Expected certificate_required SSL error, got: " + e.getMessage());
        }
    }
}
