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
 * Test Apache HTTP Client with explicit provider selection on PQC-only server.
 *
 * Expected results:
 * - BCJSSE: SUCCESS (supports X25519MLKEM768)
 * - SunJSSE: FAILURE (does not support X25519MLKEM768)
 *
 * This proves that X25519MLKEM768 requires BouncyCastle JSSE.
 *
 * Run with: mvn test -Dtest=HttpClientPqcOnlyTest
 */
@QuarkusTest
@TestProfile(PqcOnlyProfile.class)
class HttpClientPqcOnlyTest extends AbstractHttpClientPqcTest {

    @Override
    protected String getBcjsseTestDescription() {
        return "HttpClient BCJSSE with PQC-Only Server";
    }

    @Override
    protected String getSunJsseTestDescription() {
        return "HttpClient SunJSSE FAILS with PQC-Only Server";
    }

    @Override
    protected void validateNamedGroups(String actualNamedGroups) {
        assertTrue(actualNamedGroups != null && actualNamedGroups.equals("X25519MLKEM768"),
                "Server must be configured with X25519MLKEM768. Got: " + actualNamedGroups);
    }
}
