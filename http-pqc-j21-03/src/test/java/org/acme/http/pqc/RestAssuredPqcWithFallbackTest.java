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
import io.quarkus.test.junit.TestProfile;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test RestAssured client with X25519MLKEM768 + secp256r1 fallback server.
 * RestAssured uses BCJSSE which supports PQC, so the request succeeds.
 *
 * Run with: mvn test -Dtest=RestAssuredPqcWithFallbackTest
 */
@QuarkusTest
@TestProfile(PqcWithFallbackProfile.class)
class RestAssuredPqcWithFallbackTest extends AbstractRestAssuredPqcTest {

    @Override
    protected String getExpectedNamedGroups() {
        return "X25519MLKEM768 or secp256r1";
    }

    @Override
    protected String getTestDescription() {
        return "RestAssured with PQC + Fallback Server";
    }

    @Override
    protected void validateNamedGroups(String actualNamedGroups) {
        assertTrue(
                actualNamedGroups != null && actualNamedGroups.contains("X25519MLKEM768")
                        && actualNamedGroups.contains("secp256r1"),
                "Server must be configured with X25519MLKEM768,secp256r1. Got: " + actualNamedGroups);
    }
}
