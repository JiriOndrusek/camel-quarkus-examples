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

import java.util.Map;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test 2: HTTP endpoint with X25519MLKEM768-only server (same as Test 1).
 *
 * This test verifies that the default JSSE provider (BCJSSE at position 1)
 * can successfully connect to a server configured with X25519MLKEM768 ONLY.
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

        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    // Disable client auth requirement for simpler testing
                    "quarkus.http.ssl.client-auth", "none");
        }
    }

    @Test
    void testHttpRequestWithPqcOnly() {
        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   Test 2: HTTP Request (X25519MLKEM768-Only)");
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server named groups: " + actualNamedGroups);
        System.out.println();

        assertTrue(actualNamedGroups != null && actualNamedGroups.equals("X25519MLKEM768"),
                "Server must be configured with ONLY X25519MLKEM768. Got: " + actualNamedGroups);

        System.out.println("✓ Server configuration verified: X25519MLKEM768 ONLY");
        System.out.println();

        int port = RestAssured.port > 0 ? RestAssured.port : 8443;

        given()
                .relaxedHTTPSValidation()
                .baseUri("https://localhost:" + port)
                .when()
                .get("/api/data")
                .then()
                .statusCode(200);

        System.out.println("✓ HTTP request SUCCEEDED");
        System.out.println("═══════════════════════════════════════════════════════════\n");
    }
}
