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

import java.io.File;
import java.security.Provider;
import java.security.Security;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class HttpPqcTest {

    @Test
    void testBouncyCastleProviderRegistered() {
        Provider bcProvider = Security.getProvider("BCJSSE");
        assertNotNull(bcProvider, "BouncyCastle JSSE provider should be registered");
        assertTrue(bcProvider.getName().equals("BCJSSE"),
                "Provider should be BouncyCastle JSSE (BCJSSE)");
    }

    @Test
    void testCertificatesGenerated() {
        File serverKeystore = new File("target/certs/server-keystore.p12");
        File clientKeystore = new File("target/certs/client-keystore.p12");
        File serverTruststore = new File("target/certs/server-truststore.p12");
        File clientTruststore = new File("target/certs/client-truststore.p12");

        assertTrue(serverKeystore.exists(), "Server keystore should be generated");
        assertTrue(clientKeystore.exists(), "Client keystore should be generated");
        assertTrue(serverTruststore.exists(), "Server truststore should be generated");
        assertTrue(clientTruststore.exists(), "Client truststore should be generated");

        // Verify keystore file sizes are reasonable (4096-bit RSA should be larger than 2048-bit)
        assertTrue(serverKeystore.length() > 2000, "Server keystore should contain certificate data");
        assertTrue(clientKeystore.length() > 2000, "Client keystore should contain certificate data");
    }

    @Test
    void testPqcSecureEndpoint() {
        // Note: This test requires client certificate authentication (mTLS)
        // The application.properties configures quarkus.http.ssl.client-auth=required
        // RestAssured is configured with valid client cert below
        RestAssured.keyStore("target/certs/client-keystore.p12", "changeit");
        RestAssured.trustStore("target/certs/client-truststore.p12", "changeit");

        given()
                .when()
                .get("/pqc/secure")
                .then()
                .statusCode(200)
                .body(containsString("PQC TLS connection established"))
                .body(containsString("quantum-safe"))
                .body(containsString("ML-KEM-768"))
                .body(containsString("Java 21"))
                .body(containsString("BouncyCastle JSSE"));
    }

    @Test
    void testPqcInfoEndpoint() {
        RestAssured.keyStore("target/certs/client-keystore.p12", "changeit");
        RestAssured.trustStore("target/certs/client-truststore.p12", "changeit");

        given()
                .when()
                .get("/pqc/info")
                .then()
                .statusCode(200)
                .body(containsString("Post-Quantum Cryptography Configuration"))
                .body(containsString("BouncyCastle JSSE"))
                .body(containsString("ML-KEM-768"))
                .body(containsString("X25519MLKEM768"));
    }
}
