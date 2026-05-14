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

import io.restassured.RestAssured;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;

/**
 * Abstract base class for RestAssured PQC tests.
 * RestAssured uses BCJSSE which supports PQC, so all tests succeed.
 */
abstract class AbstractRestAssuredPqcTest {

    /**
     * Returns the expected named groups configuration for this test.
     */
    protected abstract String getExpectedNamedGroups();

    /**
     * Returns the test description for console output.
     */
    protected abstract String getTestDescription();

    /**
     * Validates the named groups configuration.
     */
    protected abstract void validateNamedGroups(String actualNamedGroups);

    @Test
    void testRestAssuredWithPqc() {
        String actualNamedGroups = System.getProperty("jdk.tls.namedGroups");

        System.out.println("\n═══════════════════════════════════════════════════════════");
        System.out.println("   " + getTestDescription());
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Server: " + actualNamedGroups);
        System.out.println("Client: RestAssured (BCJSSE)");
        System.out.println();

        validateNamedGroups(actualNamedGroups);

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

        System.out.println("✓ SUCCESS - BCJSSE negotiated " + getExpectedNamedGroups());
        System.out.println("═══════════════════════════════════════════════════════════\n");
    }
}
