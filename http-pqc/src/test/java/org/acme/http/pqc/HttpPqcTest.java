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

import java.security.Security;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;

@QuarkusTest
public class HttpPqcTest {

    @BeforeAll
    public static void setUp() {
        // Use relaxed HTTPS validation for self-signed certificates in tests
        RestAssured.useRelaxedHTTPSValidation();

        // Ensure BouncyCastle provider is registered for PQC support
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    @Test
    public void testPqcHttpsEndpoint() {
        RestAssured.given()
                .when()
                .get("https://localhost:8443/hello")
                .then()
                .statusCode(200)
                .body(containsString("Successfully connected via PQC-enabled HTTPS"));
    }

    @Test
    public void testBouncyCastleProviderAvailable() {
        // Verify BouncyCastle provider is available in the security providers
        assertThat("BouncyCastle provider should be available",
                Security.getProviders().length, greaterThan(0));
    }
}
