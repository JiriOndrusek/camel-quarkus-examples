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

import io.netty.handler.ssl.OpenSsl;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Test PQC key exchange with STRICT server-side enforcement (Quarkus PR #53076).
 *
 * Server configured with:
 * quarkus.tls.key-exchange-protocols = x25519mlkem768
 * quarkus.tls.enforce-pqc = STRICT
 *
 * STRICT mode activates the OpenSSL backend via Vert.x, which enforces
 * PQC hybrid key exchange on the server side.
 *
 * Requires system OpenSSL >= 3.5 with X25519MLKEM768 support.
 */
@QuarkusTest
class PqcStrictEnforcementTest extends AbstractPqcTest {

    @BeforeAll
    static void checkOpenSslAvailable() {
        Assumptions.assumeTrue(OpenSsl.isAvailable(), "OpenSSL not available via netty-tcnative");
        Assumptions.assumeTrue(OpenSsl.version() >= 0x30500000L,
                "OpenSSL >= 3.5 required, found: " + OpenSsl.versionString());
    }

    @Test
    void testHybridClientSucceeds() {
        testWebClientConnection(true, false);
    }

    @Test
    void testNonHybridClientRejected() {
        testWebClientConnection(false, true);
    }
}
