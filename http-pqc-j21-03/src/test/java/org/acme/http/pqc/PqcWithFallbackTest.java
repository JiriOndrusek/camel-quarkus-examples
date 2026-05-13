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

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test 3: HTTP endpoint with X25519MLKEM768 + secp256r1 fallback.
 *
 * Server is configured with X25519MLKEM768,secp256r1 (PQC preferred, but fallback available).
 * This demonstrates backward compatibility.
 *
 * Run with: mvn test -Dtest=PqcWithFallbackTest
 */
@QuarkusTest
@TestProfile(PqcWithFallbackTest.PqcWithFallbackProfile.class)
class PqcWithFallbackTest {

    public static class PqcWithFallbackProfile implements QuarkusTestProfile {

        @Override
        public String getConfigProfile() {
            return "pqc-with-fallback";
        }
    }

    @Test
    void testHttpRequestWithFallback() {
        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   Test 3: HTTP Request (PQC with Fallback)");
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

        int port = RestAssured.port > 0 ? RestAssured.port : 8443;

        given()
                .config(RestAssuredConfig.config().sslConfig(
                        SSLConfig.sslConfig()
                                .keyStore("target/certs/client-keystore.p12", "changeit")
                                .trustStore("target/certs/client-truststore.p12", "changeit")
                                .allowAllHostnames()))
                .baseUri("https://localhost:" + port)
                .when()
                .get("/api/data")
                .then()
                .statusCode(200);

        System.out.println("✓ HTTP request SUCCEEDED (with fallback available)");
        System.out.println("═══════════════════════════════════════════════════════════\n");
    }
}
