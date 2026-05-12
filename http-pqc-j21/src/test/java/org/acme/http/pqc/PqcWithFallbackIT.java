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

import io.quarkus.test.junit.QuarkusIntegrationTest;

/**
 * Native integration test for PqcWithFallbackTest.
 * Runs the same tests as PqcWithFallbackTest but against a native binary
 * built with PQC+fallback configuration (X25519MLKEM768,x25519,secp256r1).
 *
 * This is the ONLY native integration test in this example. Unlike JVM mode which
 * tests both PQC-only and PQC-with-fallback scenarios, native mode only tests
 * the fallback scenario because a native executable can be built with only one
 * jdk.tls.namedGroups configuration. We chose the fallback config as it's more
 * representative of real-world production use.
 *
 * BC providers are registered by CertificateTestResource (inherited from AbstractPqcTest).
 *
 * Run with: mvn verify -Dnative
 */
@QuarkusIntegrationTest
class PqcWithFallbackIT extends PqcWithFallbackTest {
}
