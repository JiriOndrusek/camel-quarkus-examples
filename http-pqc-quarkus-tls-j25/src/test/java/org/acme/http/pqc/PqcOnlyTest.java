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
import org.acme.http.pqc.profiles.PqcOnlyProfile;
import org.junit.jupiter.api.Test;

/**
 * Test PQC-only configuration using JDK 25+ SunJSSE.
 *
 * Server configured with: quarkus.tls.key-exchange-protocols=X25519MLKEM768
 *
 * On JDK 25+, SunJSSE natively supports X25519MLKEM768. However, the Vert.x/JSSE
 * backend does not propagate key-exchange-protocols to the server's SSLEngine,
 * so the server uses JDK defaults (which do NOT include X25519MLKEM768).
 *
 * As a result:
 * - Clients MUST include classical fallback groups (x25519, secp256r1) for the
 * handshake to succeed, because the server can only negotiate those defaults.
 * - Server-side PQC-only enforcement requires the OpenSSL backend.
 * - Classical-only clients are NOT rejected (no server-side PQC enforcement).
 */
@QuarkusTest
@TestProfile(PqcOnlyProfile.class)
class PqcOnlyTest extends AbstractPqcTest {

    @Test
    void testRestAssured() throws Exception {
        testRestAssuredConnection();
    }

    @Test
    void testHttpClientWithPqcAndFallbackGroups() throws Exception {
        testHttpClientConnection(DEFAULT_NAMED_GROUPS, false);
    }

    @Test
    void testHttpClientWithClassicalGroups() throws Exception {
        testHttpClientConnection(new String[] { "secp256r1" }, false);
    }
}
