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
import org.acme.http.pqc.profiles.PqcWithFallbackProfile;
import org.junit.jupiter.api.Test;

/**
 * Test PQC with classical fallback using JDK 25+ SunJSSE.
 *
 * Server configured with: X25519MLKEM768,x25519,secp256r1
 *
 * Expected results:
 * - PQC + fallback groups: SUCCESS (X25519MLKEM768 preferred, classical fallback available)
 * - Classical-only groups: SUCCESS (secp256r1 fallback negotiated)
 */
@QuarkusTest
@TestProfile(PqcWithFallbackProfile.class)
class PqcWithFallbackTest extends AbstractPqcTest {

    @Test
    void testRestAssured() throws Exception {
        testRestAssuredConnection();
    }

    @Test
    void testHttpClientWithPqcGroups() throws Exception {
        testHttpClientConnection(DEFAULT_NAMED_GROUPS, false);
    }

    @Test
    void testHttpClientWithClassicalOnly() throws Exception {
        testHttpClientConnection(new String[] { "x25519", "secp256r1" }, false);
    }
}
